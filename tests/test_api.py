import asyncio
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from scamshield.api import (
    InvestigationOrchestrator,
    InvestigateRequest,
    _coalesce_investigation,
    _get_bedrock,
    _issue_follow_up_token,
    _read_follow_up_token,
    app,
)
from scamshield.bedrock_service import BedrockConfigurationError
from scamshield.message_analyzer import analyze_message


client = TestClient(app)


def test_health_endpoint():
    response = client.get("/health")

    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_health_endpoint():
    response = client.get("/health")

    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_readiness_endpoint_does_not_expose_secrets():
    response = client.get("/ready")

    assert response.status_code == 200
    assert response.json()["status"] in {"ready", "degraded"}
    assert response.json()["mcp"] in {"available", "unavailable"}
    assert "model_id" not in response.text


def test_invalid_partial_bedrock_configuration_degrades_without_startup_failure(monkeypatch):
    monkeypatch.setenv("SCAMSHIELD_BEDROCK_MODEL_ID", "configured-model")
    monkeypatch.setenv("AWS_REGION", "us-east-1")
    monkeypatch.setattr(
        "scamshield.api.BedrockExplanationService.from_environment",
        lambda: (_ for _ in ()).throw(BedrockConfigurationError("invalid configuration")),
    )

    assert _get_bedrock() is None


def test_investigate_endpoint_uses_injected_orchestrator(monkeypatch):
    class FakeMCP:
        async def analyze_message(self, message):
            return {
                "status": "suspicious",
                "findings": [{"recommended_verification": "Verify independently."}],
                "limitations": [],
            }

        async def check_url_reputation(self, url):
            return {"status": "unknown", "limitations": ["Not configured."]}

    monkeypatch.setattr(
        "scamshield.api._orchestrator",
        InvestigationOrchestrator(mcp_client=FakeMCP()),
    )
    response = client.post(
        "/api/investigate",
        json={"message": "Your account will be blocked today unless you verify at https://example.com."},
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["ok"] is True
    assert payload["result"]["status"] == "suspicious"
    assert payload["result"]["explanation"] is None
    assert payload["result"]["url_check"] is None
    assert "MCP tool findings only" in " ".join(payload["result"]["limitations"])


def test_investigate_endpoint_returns_multiple_real_warning_indicators(monkeypatch):
    class LocalAnalyzerMCP:
        async def analyze_message(self, message):
            return analyze_message(message).to_dict()

        async def check_url_reputation(self, url):
            raise AssertionError("URL lookup was not requested")

    monkeypatch.setattr("scamshield.api._orchestrator", InvestigationOrchestrator(mcp_client=LocalAnalyzerMCP()))
    response = client.post(
        "/api/investigate",
        json={"message": "Pay a registration fee today or your bank account will be blocked."},
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["ok"] is True
    result = payload["result"]
    assert result["status"] == "suspicious"
    assert {finding["indicator_type"] for finding in result["findings"]} >= {
        "upfront_payment",
        "urgency_threat",
    }
    assert result["explanation"] is None
    assert result["_follow_up_token"]


def test_investigate_endpoint_keeps_no_findings_inconclusive(monkeypatch):
    class LocalAnalyzerMCP:
        async def analyze_message(self, message):
            return analyze_message(message).to_dict()

        async def check_url_reputation(self, url):
            raise AssertionError("URL lookup was not requested")

    monkeypatch.setattr("scamshield.api._orchestrator", InvestigationOrchestrator(mcp_client=LocalAnalyzerMCP()))
    response = client.post(
        "/api/investigate",
        json={"message": "Our appointment is confirmed for Tuesday at 3 PM."},
    )

    assert response.status_code == 200
    result = response.json()["result"]
    assert result["status"] == "inconclusive"
    assert result["findings"] == []
    assert any("does not prove the message is safe" in item for item in result["limitations"])


@pytest.mark.parametrize("url_status", ["unknown", "lookup_failed", "provider_error"])
def test_investigate_endpoint_preserves_inconclusive_url_reputation_status(monkeypatch, url_status):
    class FakeMCP:
        async def analyze_message(self, message):
            return {"status": "inconclusive", "findings": [], "limitations": []}

        async def check_url_reputation(self, url):
            return {"status": url_status, "limitations": ["Synthetic provider result."]}

    monkeypatch.setattr("scamshield.api._orchestrator", InvestigationOrchestrator(mcp_client=FakeMCP()))
    response = client.post(
        "/api/investigate",
        json={"message": "Please review this notice.", "url": "https://example.invalid/notice"},
    )

    assert response.status_code == 200
    result = response.json()["result"]
    assert result["url_check"]["status"] == url_status
    assert result["url_check"]["limitations"] == ["Synthetic provider result."]


def test_investigate_endpoint_returns_mcp_failure_in_api_error_envelope(monkeypatch):
    class FailedMCP:
        async def analyze_message(self, message):
            from scamshield.mcp_client import MCPToolError

            raise MCPToolError("The MCP tool request failed.")

    monkeypatch.setattr("scamshield.api._orchestrator", InvestigationOrchestrator(mcp_client=FailedMCP()))
    response = client.post("/api/investigate", json={"message": "Synthetic test message."})

    assert response.status_code == 200
    assert response.json() == {
        "ok": False,
        "error": {"code": "mcp_error", "message": "The MCP tool request failed."},
    }


def test_follow_up_reports_bedrock_unavailable_with_valid_investigation_token(monkeypatch):
    monkeypatch.setattr("scamshield.api._orchestrator", InvestigationOrchestrator(bedrock_service=None))
    token = _issue_follow_up_token({"status": "inconclusive", "findings": []})

    response = client.post(
        "/api/follow-up",
        json={"question": "What should I verify?", "investigation_token": token},
    )

    assert response.status_code == 200
    assert response.json() == {
        "ok": False,
        "error": {
            "code": "bedrock_unavailable",
            "message": "Follow-up explanations require a configured Bedrock model.",
        },
    }


@pytest.mark.parametrize(
    ("message", "expected_status", "expected_code"),
    [("", 422, None), ("   ", 200, "invalid_input"), ("\n\t", 200, "invalid_input")],
)
def test_investigate_endpoint_rejects_empty_or_whitespace_message(message, expected_status, expected_code, monkeypatch):
    class LocalAnalyzerMCP:
        async def analyze_message(self, content):
            return analyze_message(content).to_dict()

    monkeypatch.setattr("scamshield.api._orchestrator", InvestigationOrchestrator(mcp_client=LocalAnalyzerMCP()))
    response = client.post("/api/investigate", json={"message": message})

    assert response.status_code == expected_status
    if expected_code:
        assert response.json()["ok"] is False
        assert response.json()["error"]["code"] == expected_code


def test_investigate_endpoint_rejects_extra_fields():
    response = client.post(
        "/api/investigate",
        json={"message": "hello", "unexpected": "data"},
    )

    assert response.status_code == 422


def test_follow_up_requires_a_signed_investigation_token():
    response = client.post(
        "/api/follow-up",
        json={"question": "What should I do?", "investigation": {"status": "safe"}},
    )

    assert response.status_code == 422


def test_follow_up_token_rejects_tampering():
    token = _issue_follow_up_token({"status": "inconclusive"})
    tampered = f"{token[:-1]}{'0' if token[-1] != '0' else '1'}"

    with pytest.raises(ValueError, match="invalid or expired"):
        _read_follow_up_token(tampered)


def test_follow_up_token_expires(monkeypatch):
    issued_at = 1_700_000_000
    with patch("scamshield.api.time.time", return_value=issued_at):
        token = _issue_follow_up_token({"status": "inconclusive"})
    with patch("scamshield.api.time.time", return_value=issued_at + 901):
        with pytest.raises(ValueError, match="invalid or expired"):
            _read_follow_up_token(token)


def test_investigation_orchestrator_calls_mcp_tools_and_bedrock():
    calls = []

    class FakeMCP:
        async def analyze_message(self, message):
            calls.append(("message", message))
            return {"status": "suspicious", "findings": [], "limitations": []}

        async def check_url_reputation(self, url):
            calls.append(("url", url))
            return {"status": "unknown", "limitations": []}

    class FakeBedrock:
        def explain(self, message, findings):
            calls.append(("bedrock", message, findings["url_check"]["status"]))
            return type("Explanation", (), {"model_dump": lambda self: {"assessment": "Use caution."}})()

    import asyncio

    result = asyncio.run(
        InvestigationOrchestrator(mcp_client=FakeMCP(), bedrock_service=FakeBedrock()).investigate(
            type("Request", (), {"message": "hello", "url": "https://example.com"})()
        )
    )

    assert calls == [("message", "hello"), ("url", "https://example.com"), ("bedrock", "hello", "unknown")]
    assert result["explanation"]["assessment"] == "Use caution."


def test_investigation_endpoint_coalesces_duplicate_requests(monkeypatch):
    calls = []

    class FakeOrchestrator:
        async def investigate(self, request):
            calls.append(request.message)
            await asyncio.sleep(0.01)
            return {"status": "inconclusive", "findings": [], "limitations": []}

    monkeypatch.setattr("scamshield.api._orchestrator", FakeOrchestrator())

    async def run():
        request = InvestigateRequest(message="same request")
        return await asyncio.gather(_coalesce_investigation(request), _coalesce_investigation(request))

    results = asyncio.run(run())

    assert results[0] == results[1]
    assert calls == ["same request"]
