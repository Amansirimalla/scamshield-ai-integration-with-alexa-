import pytest

pytest.importorskip("mcp")

from scamshield.guidance import SituationCategory, get_safety_guidance
from scamshield.mcp_server import analyze_message, check_url_reputation, get_safety_guidance as mcp_guidance
from scamshield.reputation import ReputationStatus, UrlReputationService


def test_mcp_analyze_message_returns_structured_result():
    result = analyze_message("Pay a processing fee today and verify at https://example.com.")

    assert result["ok"] is True
    assert result["result"]["status"] == "suspicious"
    assert result["result"]["findings"]


def test_mcp_analyze_message_rejects_invalid_input():
    result = analyze_message("")

    assert result == {
        "ok": False,
        "error": {"code": "invalid_input", "message": "message must not be empty"},
    }


def test_unconfigured_url_provider_is_unknown():
    result = UrlReputationService().check("https://example.com/path")

    assert result.status == ReputationStatus.UNKNOWN
    assert "not a safety determination" in " ".join(result.limitations)


@pytest.mark.parametrize(
    "url",
    ["", "ftp://example.com/file", "http://127.0.0.1/admin", "https://user:pass@example.com"],
)
def test_url_validation_rejects_unsafe_or_malformed_inputs(url):
    result = check_url_reputation(url)

    assert result["ok"] is False
    assert result["error"]["code"] == "invalid_input"


def test_guidance_tool_returns_category_steps():
    result = mcp_guidance(SituationCategory.MONEY_ALREADY_SENT.value)

    assert result["ok"] is True
    assert result["result"]["category"] == "money_already_sent"
    assert result["result"]["immediate_steps"]
    assert result["result"]["avoid"]


def test_guidance_rejects_unknown_category():
    result = mcp_guidance("make_me_safe")

    assert result["ok"] is False
    assert result["error"]["code"] == "invalid_input"


def test_guidance_core_rejects_non_string():
    with pytest.raises(TypeError):
        get_safety_guidance(None)  # type: ignore[arg-type]
