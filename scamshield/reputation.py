"""URL validation and optional reputation-provider integration.

This module never requests a submitted URL. It sends the URL only to a
configured reputation API. With no provider configured, the result is
``unknown`` rather than a safety claim.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from enum import Enum
import ipaddress
import logging
import os
from typing import Any
from urllib.parse import urlparse, urlunparse

import httpx

logger = logging.getLogger(__name__)


class ReputationStatus(str, Enum):
    """Outcome of a URL reputation lookup."""

    MALICIOUS = "malicious"
    NO_THREAT_FOUND = "no_threat_found"
    UNKNOWN = "unknown"
    LOOKUP_FAILED = "lookup_failed"
    PROVIDER_ERROR = "provider_error"  # Backward-compatible alias for callers.


@dataclass(frozen=True)
class ReputationResult:
    """Structured, conservative result of URL validation and lookup."""

    status: ReputationStatus
    url: str
    domain: str | None
    provider: str | None
    details: str
    limitations: tuple[str, ...]
    evidence: tuple[dict[str, str], ...] = ()

    def to_dict(self) -> dict[str, Any]:
        result = asdict(self)
        result["status"] = self.status.value
        result["limitations"] = list(self.limitations)
        result["evidence"] = list(self.evidence)
        return result


def _validate_url(url: str) -> tuple[str, str]:
    if not isinstance(url, str):
        raise TypeError("url must be a string")
    candidate = url.strip()
    if not candidate:
        raise ValueError("url must not be empty")
    if len(candidate) > 2_048:
        raise ValueError("url exceeds the 2048-character limit")
    if any(ord(character) < 32 or ord(character) == 127 for character in candidate):
        raise ValueError("url contains control characters")

    parsed = urlparse(candidate)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError("url must use http or https and include a host")
    if parsed.username or parsed.password:
        raise ValueError("URLs containing embedded credentials are not accepted")

    try:
        parsed.port
    except ValueError as exc:
        raise ValueError("url contains an invalid port") from exc
    hostname = parsed.hostname
    if not hostname:
        raise ValueError("url must include a valid host")
    normalized_host = hostname.rstrip(".").lower()
    if normalized_host in {"localhost", "localhost.localdomain"} or normalized_host.endswith(".local"):
        raise ValueError("local hostnames are not accepted")
    try:
        address = ipaddress.ip_address(normalized_host)
    except ValueError:
        address = None
    if address and (address.is_private or address.is_loopback or address.is_link_local or address.is_reserved):
        raise ValueError("private, loopback, link-local, and reserved IP URLs are not accepted")

    # Do not send path, query, or fragment values to a third-party provider:
    # reset links and opaque path segments can contain bearer tokens.
    sanitized = parsed._replace(path="", params="", query="", fragment="")
    return urlunparse(sanitized), normalized_host


class GoogleSafeBrowsingProvider:
    """Small adapter for Google's Safe Browsing v4 Lookup API.

    The provider receives the submitted URL as data in an API request. This
    service does not fetch or download the submitted URL itself.
    """

    endpoint = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
    name = "google_safe_browsing"

    def __init__(self, api_key: str, timeout_seconds: float = 8.0) -> None:
        if not api_key.strip():
            raise ValueError("Safe Browsing API key must not be empty")
        self.api_key = api_key
        self.timeout_seconds = timeout_seconds

    def check(self, url: str) -> ReputationResult:
        sanitized_url, domain = _validate_url(url)
        payload = {
            "client": {"clientId": "scamshield-ai", "clientVersion": "0.1.0"},
            "threatInfo": {
                "threatTypes": [
                    "MALWARE",
                    "SOCIAL_ENGINEERING",
                    "UNWANTED_SOFTWARE",
                    "POTENTIALLY_HARMFUL_APPLICATION",
                ],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": sanitized_url}],
            },
        }
        try:
            response = httpx.post(
                f"{self.endpoint}?key={self.api_key}",
                json=payload,
                timeout=self.timeout_seconds,
                follow_redirects=False,
            )
            if response.status_code == 429:
                return ReputationResult(
                    status=ReputationStatus.LOOKUP_FAILED,
                    url=sanitized_url,
                    domain=domain,
                    provider=self.name,
                    details="The reputation provider rate limit was reached.",
                    limitations=("Retry later; no reputation conclusion was obtained.",),
                )
            if response.status_code in {401, 403}:
                return ReputationResult(
                    status=ReputationStatus.LOOKUP_FAILED,
                    url=sanitized_url,
                    domain=domain,
                    provider=self.name,
                    details="The reputation provider rejected authentication or authorization.",
                    limitations=("Check the provider configuration; no reputation conclusion was obtained.",),
                )
            response.raise_for_status()
            body = response.json()
        except Exception as exc:
            logger.error("Configured reputation provider failed: %s", type(exc).__name__)
            return ReputationResult(
                status=ReputationStatus.LOOKUP_FAILED,
                url=sanitized_url,
                domain=domain,
                provider=self.name,
                details="The configured reputation provider could not complete the lookup.",
                limitations=("No reputation conclusion was obtained.",),
            )

        if body.get("matches"):
            return ReputationResult(
                status=ReputationStatus.MALICIOUS,
                url=sanitized_url,
                domain=domain,
                provider=self.name,
                details="The configured provider reported one or more threat matches.",
                limitations=(
                    "This is a provider signal, not a complete security assessment.",
                    "Do not open the URL; use trusted account-recovery or reporting channels.",
                ),
                evidence=tuple(
                    {
                        key: str(match[key])
                        for key in ("threatType", "platformType", "threatEntryType", "cacheDuration")
                        if key in match
                    }
                    for match in body.get("matches", [])
                    if isinstance(match, dict)
                ),
            )
        return ReputationResult(
            status=ReputationStatus.NO_THREAT_FOUND,
            url=sanitized_url,
            domain=domain,
            provider=self.name,
            details="The configured provider reported no matching threats at lookup time.",
            limitations=(
                "No threat found does not prove that the URL is safe.",
                "Reputation databases can be incomplete, delayed, or wrong.",
            ),
            evidence=(),
        )


class UrlReputationService:
    """Validate URLs and use Google Safe Browsing only when configured."""

    def __init__(self, provider: GoogleSafeBrowsingProvider | None = None) -> None:
        self.provider = provider

    @classmethod
    def from_environment(cls) -> "UrlReputationService":
        api_key = os.getenv("SCAMSHIELD_SAFE_BROWSING_API_KEY")
        return cls(GoogleSafeBrowsingProvider(api_key) if api_key else None)

    def check(self, url: str) -> ReputationResult:
        normalized_url, domain = _validate_url(url)
        if self.provider is None:
            return ReputationResult(
                status=ReputationStatus.UNKNOWN,
                url=normalized_url,
                domain=domain,
                provider=None,
                details="No URL reputation provider is configured.",
                limitations=(
                    "The URL was not opened or downloaded.",
                    "No reputation result is available, so this is not a safety determination.",
                ),
                evidence=(),
            )
        return self.provider.check(normalized_url)
