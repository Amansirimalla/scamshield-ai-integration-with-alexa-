"""Minimal FastAPI adapter for the ScamShield frontend."""

from __future__ import annotations

import os
import asyncio
import base64
import binascii
import hashlib
import hmac
import json
import secrets
import time
from collections import defaultdict, deque
from typing import Any, Optional

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, ConfigDict, Field

from .bedrock_service import BedrockConfigurationError, BedrockExplanationService, BedrockServiceError
from .mcp_client import MCPToolError, ScamShieldMCPClient

app = FastAPI(
    title="ScamShield AI API",
    description="Evidence-led preliminary safety analysis.",
    version="0.1.0",
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=[origin.strip() for origin in os.getenv("SCAMSHIELD_CORS_ORIGINS", "http://127.0.0.1:4173,http://localhost:4173").split(",") if origin.strip()],
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type"],
)


class InvestigateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    message: str = Field(min_length=1, max_length=10_000)
    url: Optional[str] = Field(default=None, max_length=2_048)


class FollowUpRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    question: str = Field(min_length=1, max_length=2_000)
    investigation_token: str = Field(min_length=1, max_length=100_000)


class InvestigationOrchestrator:
    """Coordinates validation, MCP tools, and optional Bedrock explanation."""

    def __init__(
        self,
        *,
        mcp_client: ScamShieldMCPClient | None = None,
        bedrock_service: BedrockExplanationService | None = None,
    ) -> None:
        self.mcp_client = mcp_client or ScamShieldMCPClient()
        self.bedrock_service = bedrock_service

    async def investigate(self, request: InvestigateRequest) -> dict[str, Any]:
        analysis = await self.mcp_client.analyze_message(request.message)
        if request.url:
            analysis["url_check"] = await self.mcp_client.check_url_reputation(request.url)
        else:
            analysis["url_check"] = None
        analysis["recommendations"] = [
            finding["recommended_verification"]
            for finding in analysis.get("findings", [])
            if finding.get("recommended_verification")
        ][:5]
        if self.bedrock_service:
            try:
                analysis["explanation"] = self.bedrock_service.explain(request.message, analysis).model_dump()
            except BedrockServiceError:
                analysis["explanation"] = None
                analysis.setdefault("limitations", []).append(
                    "Plain-language AI explanation was unavailable; the structured findings remain available."
                )
        else:
            analysis["explanation"] = None
            analysis.setdefault("limitations", []).append(
                "Amazon Bedrock is not configured; this result uses MCP tool findings only."
            )
        return analysis


def _get_bedrock() -> BedrockExplanationService | None:
    if not os.getenv("SCAMSHIELD_BEDROCK_MODEL_ID") or not (os.getenv("AWS_REGION") or os.getenv("AWS_DEFAULT_REGION")):
        return None
    try:
        return BedrockExplanationService.from_environment()
    except BedrockConfigurationError:
        return None


_orchestrator = InvestigationOrchestrator(bedrock_service=_get_bedrock())
_inflight_requests: dict[str, asyncio.Task[dict[str, Any]]] = {}
_inflight_lock = asyncio.Lock()
_rate_limit_window_seconds = 60.0
_rate_limit_max = int(os.getenv("SCAMSHIELD_RATE_LIMIT_PER_MINUTE", "30"))
_request_timestamps: dict[str, deque[float]] = defaultdict(deque)
_rate_limit_lock = asyncio.Lock()
_signing_key = (os.getenv("SCAMSHIELD_SESSION_SIGNING_KEY") or secrets.token_urlsafe(32)).encode("utf-8")
_follow_up_token_ttl_seconds = int(os.getenv("SCAMSHIELD_FOLLOW_UP_TOKEN_TTL_SECONDS", "900"))


def _client_key(request: Request) -> str:
    return request.client.host if request.client else "unknown"


async def _check_request_access(request: Request) -> str | None:
    configured_key = os.getenv("SCAMSHIELD_API_KEY")
    if configured_key and not hmac.compare_digest(
        request.headers.get("X-ScamShield-API-Key", ""),
        configured_key,
    ):
        return "authentication required"
    now = time.monotonic()
    timestamps = _request_timestamps[_client_key(request)]
    async with _rate_limit_lock:
        while timestamps and now - timestamps[0] >= _rate_limit_window_seconds:
            timestamps.popleft()
        if len(timestamps) >= max(1, _rate_limit_max):
            return "rate limit exceeded; retry later"
        timestamps.append(now)
    return None


def _issue_follow_up_token(investigation: dict[str, Any]) -> str:
    now = int(time.time())
    claims = {"iat": now, "exp": now + max(1, _follow_up_token_ttl_seconds), "investigation": investigation}
    payload = base64.urlsafe_b64encode(
        json.dumps(claims, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).decode("ascii").rstrip("=")
    signature = hmac.new(_signing_key, payload.encode("ascii"), hashlib.sha256).hexdigest()
    return f"{payload}.{signature}"


def _read_follow_up_token(token: str) -> dict[str, Any]:
    try:
        payload, signature = token.rsplit(".", 1)
        expected = hmac.new(_signing_key, payload.encode("ascii"), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(signature, expected):
            raise ValueError
        decoded = base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4))
        claims = json.loads(decoded)
    except (ValueError, TypeError, UnicodeError, json.JSONDecodeError, binascii.Error) as exc:
        raise ValueError("investigation token is invalid or expired") from exc
    if not isinstance(claims, dict) or not isinstance(claims.get("exp"), int) or claims["exp"] < int(time.time()):
        raise ValueError("investigation token is invalid or expired")
    result = claims.get("investigation")
    if not isinstance(result, dict):
        raise ValueError("investigation token is invalid or expired")
    return result


async def _coalesce_investigation(request: InvestigateRequest) -> dict[str, Any]:
    """Share identical in-flight work without persisting submitted content."""

    fingerprint = hashlib.sha256(
        json.dumps(request.model_dump(), sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    async with _inflight_lock:
        existing = _inflight_requests.get(fingerprint)
        if existing is None:
            existing = asyncio.create_task(_orchestrator.investigate(request))
            _inflight_requests[fingerprint] = existing
            owner = True
        else:
            owner = False
    try:
        return await asyncio.shield(existing)
    finally:
        if owner:
            async with _inflight_lock:
                if _inflight_requests.get(fingerprint) is existing:
                    _inflight_requests.pop(fingerprint, None)


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/ready")
def ready() -> dict[str, Any]:
    try:
        import mcp  # noqa: F401

        mcp_status = "available"
    except ImportError:
        mcp_status = "unavailable"
    overall = "ready" if mcp_status == "available" else "degraded"
    return {
        "status": overall,
        "mcp": mcp_status,
        "bedrock": "configured" if _orchestrator.bedrock_service else "not_configured",
    }


@app.post("/api/investigate")
async def investigate(request: InvestigateRequest, http_request: Request) -> dict[str, Any]:
    access_error = await _check_request_access(http_request)
    if access_error:
        return {"ok": False, "error": {"code": "request_rejected", "message": access_error}}
    try:
        result = await _coalesce_investigation(request)
        result = dict(result)
        result["_follow_up_token"] = _issue_follow_up_token(result)
        return {"ok": True, "result": result}
    except MCPToolError as exc:
        return {"ok": False, "error": {"code": "mcp_error", "message": str(exc)}}
    except (TypeError, ValueError) as exc:
        return {"ok": False, "error": {"code": "invalid_input", "message": str(exc)}}
    except Exception:
        return {"ok": False, "error": {"code": "internal_error", "message": "The investigation could not be completed."}}


@app.post("/api/follow-up")
async def follow_up(request: FollowUpRequest, http_request: Request) -> dict[str, Any]:
    access_error = await _check_request_access(http_request)
    if access_error:
        return {"ok": False, "error": {"code": "request_rejected", "message": access_error}}
    service = _orchestrator.bedrock_service
    if service is None:
        return {"ok": False, "error": {"code": "bedrock_unavailable", "message": "Follow-up explanations require a configured Bedrock model."}}
    try:
        context = {
            "prior_investigation": _read_follow_up_token(request.investigation_token),
            "follow_up_question": request.question,
        }
        explanation = service.explain(request.question, context)
    except ValueError as exc:
        return {"ok": False, "error": {"code": "invalid_input", "message": str(exc)}}
    except BedrockServiceError:
        return {"ok": False, "error": {"code": "bedrock_error", "message": "The follow-up explanation is currently unavailable."}}
    return {"ok": True, "result": {"answer": explanation.assessment, "next_steps": explanation.recommended_next_steps, "uncertainty": explanation.uncertainty_explanation}}
