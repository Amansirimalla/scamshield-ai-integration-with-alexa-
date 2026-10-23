"""Explainable preliminary warning-sign analysis for suspicious messages.

This module deliberately does not decide whether a message is safe or prove that
it is fraudulent. It finds observable indicators and returns an inconclusive
result when the available evidence is insufficient.

The analyzer has no web-framework, database, AWS, or AI-model dependencies. A
FastAPI route or an MCP tool can call :func:`analyze_message` and serialize the
returned dataclasses at its boundary.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from enum import Enum
import re
from typing import Any, Iterable

DEFAULT_MAX_MESSAGE_LENGTH = 10_000


class IndicatorType(str, Enum):
    """Categories of preliminary warning signs."""

    UPFRONT_PAYMENT = "upfront_payment"
    CREDENTIAL_REQUEST = "credential_request"
    URGENCY_THREAT = "urgency_threat"
    PRIZE_REWARD = "prize_reward"
    SUSPICIOUS_JOB_OFFER = "suspicious_job_offer"
    IMPERSONATION = "impersonation"
    URL_FOR_INVESTIGATION = "url_for_investigation"


class Severity(str, Enum):
    """Relative relevance of a finding, not a probability of fraud."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class OverallStatus(str, Enum):
    """Conservative interpretation of the collected indicators."""

    SUSPICIOUS = "suspicious"
    INCONCLUSIVE = "inconclusive"


@dataclass(frozen=True)
class Finding:
    """One explainable warning sign detected in a message."""

    indicator_type: IndicatorType
    supporting_text: str
    explanation: str
    severity: Severity
    recommended_verification: str

    def to_dict(self) -> dict[str, str]:
        """Return a JSON-serializable representation."""

        return {key: value.value if isinstance(value, Enum) else value for key, value in asdict(self).items()}


@dataclass(frozen=True)
class AnalysisResult:
    """Complete result returned by the analysis engine."""

    status: OverallStatus
    findings: tuple[Finding, ...]
    limitations: tuple[str, ...]
    message_length: int

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable representation suitable for an API."""

        return {
            "status": self.status.value,
            "findings": [finding.to_dict() for finding in self.findings],
            "limitations": list(self.limitations),
            "message_length": self.message_length,
        }


@dataclass(frozen=True)
class _Rule:
    indicator_type: IndicatorType
    patterns: tuple[re.Pattern[str], ...]
    explanation: str
    severity: Severity
    recommended_verification: str


def _compile_patterns(patterns: Iterable[str]) -> tuple[re.Pattern[str], ...]:
    return tuple(re.compile(pattern, re.IGNORECASE) for pattern in patterns)


_RULES: tuple[_Rule, ...] = (
    _Rule(
        IndicatorType.UPFRONT_PAYMENT,
        _compile_patterns(
            (
                r"\b(?:pay|send|transfer|wire|deposit|remit)\b.{0,80}\b(?:fee|money|payment|cash|gift\s+card|crypto(?:currency)?|bitcoin|btc|deposit)\b",
                r"\b(?:processing|release|registration|training|activation|customs|delivery)\s+fee\b",
                r"\b(?:buy|purchase)\b.{0,40}\b(?:gift\s+cards?|crypto(?:currency)?|bitcoin|btc)\b",
            )
        ),
        "The message asks for money or a payment before a promised service, benefit, or resolution.",
        Severity.HIGH,
        "Verify the request through an official website or a trusted phone number; do not pay using instructions in the message.",
    ),
    _Rule(
        IndicatorType.CREDENTIAL_REQUEST,
        _compile_patterns(
            (
                r"\b(?:share|send|provide|confirm|verify|enter|reply\s+with)\b.{0,50}\b(?:password|passcode|pin|cvv|cvc|otp|verification\s+code|security\s+code)\b",
                r"\b(?:password|passcode|pin|cvv|cvc|otp|verification\s+code|security\s+code)\b.{0,50}\b(?:share|send|provide|confirm|verify|enter|reply)\b",
            )
        ),
        "The message asks for a password, one-time code, banking credential, or another sensitive authentication detail.",
        Severity.HIGH,
        "Do not share credentials or codes. Contact the organization using an official app, website, or trusted phone number.",
    ),
    _Rule(
        IndicatorType.URGENCY_THREAT,
        _compile_patterns(
            (
                r"\b(?:act|respond|verify|pay|click|reply)\b.{0,45}\b(?:now|immediately|urgent|urgently|today|asap|within\s+\d+\s*(?:hours?|minutes?))\b",
                r"\b(?:account|access|service|package|application)\b.{0,45}\b(?:blocked|suspended|closed|terminated|cancelled|seized)\b",
                r"\b(?:final\s+notice|last\s+warning|legal\s+action|police|arrest)\b",
            )
        ),
        "The message uses a deadline, threat, or pressure tactic that can discourage careful verification.",
        Severity.MEDIUM,
        "Pause and verify independently; legitimate organizations usually provide a way to confirm an urgent claim through an official channel.",
    ),
    _Rule(
        IndicatorType.PRIZE_REWARD,
        _compile_patterns(
            (
                r"\b(?:congratulations|congrats|winner|won|selected|chosen)\b.{0,100}\b(?:prize|reward|lottery|giveaway|bonus|cash|claim)\b",
                r"\b(?:claim|collect|receive)\b.{0,50}\b(?:prize|reward|winnings|lottery|bonus)\b",
                r"\b(?:you\s+have|you['’]ve\s+won|you\s+won)\b.{0,50}\b(?:\$|£|€|₹|cash|money|prize|reward)\b",
            )
        ),
        "The message makes an unexpected prize or reward claim, which is commonly used to prompt payment or data sharing.",
        Severity.MEDIUM,
        "Check the promotion on the organization’s official website without using links or contact details from the message.",
    ),
    _Rule(
        IndicatorType.SUSPICIOUS_JOB_OFFER,
        _compile_patterns(
            (
                r"\b(?:work|job|employment|hiring|position|role)\b.{0,100}\b(?:registration|training|equipment|starter|onboarding|processing)\s+fee\b",
                r"\b(?:guaranteed|easy|instant)\s+(?:income|money|job|earnings)\b",
                r"\b(?:job|work|position|role)\b.{0,100}\b(?:buy|purchase|send|pay|deposit)\b",
                r"\b(?:recruiter|hiring\s+manager)\b.{0,80}\b(?:whatsapp|telegram|signal)\b",
            )
        ),
        "The job offer contains patterns associated with advance-fee recruitment, unrealistic promises, or off-platform pressure.",
        Severity.MEDIUM,
        "Verify the vacancy on the employer’s official careers page and never pay to obtain a job or equipment.",
    ),
    _Rule(
        IndicatorType.IMPERSONATION,
        _compile_patterns(
            (
                r"\b(?:bank|government|tax\s+office|police|customs|courier|delivery|amazon|microsoft|google|employer|hr)\b.{0,100}\b(?:verify|confirm|pay|click|reply|account|package|invoice)\b",
                r"\b(?:this\s+is|i['’]m\s+calling\s+from|we['’]re\s+from)\b.{0,50}\b(?:bank|government|police|hr|support|security|delivery)\b",
                r"\b(?:official|security|support)\s+(?:team|department|desk)\b",
            )
        ),
        "The sender invokes a trusted organization or authority while asking for an action that needs independent verification.",
        Severity.MEDIUM,
        "Use contact details from the organization’s official website or a physical card, not from the message.",
    ),
    _Rule(
        IndicatorType.URL_FOR_INVESTIGATION,
        _compile_patterns(
            (
                r"\bhttps?://[^\s<>()]+",
                r"\bwww\.[a-z0-9.-]+\.[a-z]{2,}(?:/[^\s<>()]*)?",
                r"\b[a-z0-9.-]+\.(?:com|net|org|co|io|in|uk|ai)\b/[^\s<>()]*",
            )
        ),
        "The message contains a URL. A link’s presence does not prove fraud, but its destination should be checked before opening it.",
        Severity.MEDIUM,
        "Do not open the link from the message; inspect it with a trusted reputation service or navigate to the organization manually.",
    ),
)


def _redact_supporting_text(text: str) -> str:
    """Remove likely secrets from evidence excerpts before returning them."""

    def redact_url(match: re.Match[str]) -> str:
        base, suffix = match.group(1), match.group(2)
        return f"{base}?[query removed]" if suffix else base

    redacted = re.sub(
        r"(?i)(https?://[^\s<>()?#]+)([?#][^\s<>()]*)?",
        redact_url,
        text,
    )
    redacted = re.sub(
        r"(?<!\d)(?:\d[ -]?){13,19}(?!\d)",
        "[REDACTED_CARD_NUMBER]",
        redacted,
    )
    redacted = re.sub(
        r"(?i)(\b(?:otp|one[-\s]?time\s+password|verification\s+code|security\s+code|pin|password|passcode|cvv|cvc|recovery\s+code|api\s+key|secret|account\s+number)\b\s*(?:is|:|=)?\s*)([A-Za-z0-9][A-Za-z0-9._-]{2,})",
        r"\1[REDACTED]",
        redacted,
    )
    return re.sub(r"\b\d{4,8}\b", "[REDACTED]", redacted)


def _supporting_text(message: str, matches: Iterable[re.Match[str]]) -> str:
    first = next(iter(matches), None)
    if first is None:
        return ""
    start = max(0, first.start() - 35)
    end = min(len(message), first.end() + 55)
    excerpt = message[start:end].strip()
    if start > 0:
        excerpt = f"…{excerpt}"
    if end < len(message):
        excerpt = f"{excerpt}…"
    return _redact_supporting_text(excerpt)


class MessageAnalyzer:
    """Analyze a message for explainable preliminary warning signs."""

    def __init__(self, max_message_length: int = DEFAULT_MAX_MESSAGE_LENGTH) -> None:
        if not isinstance(max_message_length, int) or isinstance(max_message_length, bool):
            raise TypeError("max_message_length must be an integer")
        if max_message_length < 1:
            raise ValueError("max_message_length must be greater than zero")
        self.max_message_length = max_message_length

    def analyze(self, message: str) -> AnalysisResult:
        """Return findings for ``message`` after validating its size and type."""

        if not isinstance(message, str):
            raise TypeError("message must be a string")
        if not message.strip():
            raise ValueError("message must not be empty")
        if len(message) > self.max_message_length:
            raise ValueError(f"message exceeds the {self.max_message_length}-character limit")

        findings: list[Finding] = []
        for rule in _RULES:
            matches = [pattern.search(message) for pattern in rule.patterns]
            matched = [match for match in matches if match is not None]
            if matched:
                findings.append(
                    Finding(
                        indicator_type=rule.indicator_type,
                        supporting_text=_supporting_text(message, matched),
                        explanation=rule.explanation,
                        severity=rule.severity,
                        recommended_verification=rule.recommended_verification,
                    )
                )

        status = OverallStatus.SUSPICIOUS if len(findings) >= 2 else OverallStatus.INCONCLUSIVE
        limitations = (
            "These are preliminary indicators, not proof that the message is fraudulent.",
            "No finding means only that these checks found no clear signal; it does not prove the message is safe.",
            "Sender identity and external reputation were not independently verified by this local analysis.",
        )
        return AnalysisResult(
            status=status,
            findings=tuple(findings),
            limitations=limitations,
            message_length=len(message),
        )


def analyze_message(message: str, *, max_message_length: int = DEFAULT_MAX_MESSAGE_LENGTH) -> AnalysisResult:
    """Convenience function for callers that do not need a reusable analyzer."""

    return MessageAnalyzer(max_message_length=max_message_length).analyze(message)
