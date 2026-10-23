"""Practical, non-diagnostic safety guidance for common situations."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from enum import Enum
from typing import Any


class SituationCategory(str, Enum):
    """Supported safety-guidance categories."""

    SUSPICIOUS_JOB_OFFER = "suspicious_job_offer"
    PHISHING_MESSAGE = "phishing_message"
    SUSPECTED_ACCOUNT_COMPROMISE = "suspected_account_compromise"
    MONEY_ALREADY_SENT = "money_already_sent"


@dataclass(frozen=True)
class SafetyGuidance:
    category: SituationCategory
    immediate_steps: tuple[str, ...]
    avoid: tuple[str, ...]
    if_already_acted: tuple[str, ...]
    limitations: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        result = asdict(self)
        result["category"] = self.category.value
        for key in ("immediate_steps", "avoid", "if_already_acted", "limitations"):
            result[key] = list(result[key])
        return result


_GUIDANCE: dict[SituationCategory, SafetyGuidance] = {
    SituationCategory.SUSPICIOUS_JOB_OFFER: SafetyGuidance(
        SituationCategory.SUSPICIOUS_JOB_OFFER,
        (
            "Verify the role on the employer's official careers website.",
            "Contact the employer using contact details found independently.",
            "Keep the conversation and offer documents for reporting.",
        ),
        (
            "Do not pay a recruitment, training, equipment, or registration fee.",
            "Do not send identity documents or banking details until the employer is verified.",
        ),
        (
            "Contact your bank or payment provider if money or financial details were shared.",
            "Report the offer to the platform where it appeared and relevant local authorities.",
        ),
        ("This guidance cannot verify a specific employer or job listing.",),
    ),
    SituationCategory.PHISHING_MESSAGE: SafetyGuidance(
        SituationCategory.PHISHING_MESSAGE,
        (
            "Do not click links, open attachments, reply, or call numbers in the message.",
            "Navigate to the organization's official app or website yourself.",
            "Report the message through your email, messaging, or mobile provider.",
        ),
        (
            "Never share a password, OTP, PIN, CVV, or recovery code in response to an unsolicited message.",
        ),
        (
            "If you clicked a link, close it and run an update and security scan.",
            "If credentials were entered, change them through the official site and enable multi-factor authentication.",
        ),
        ("The message alone cannot establish the sender's identity.",),
    ),
    SituationCategory.SUSPECTED_ACCOUNT_COMPROMISE: SafetyGuidance(
        SituationCategory.SUSPECTED_ACCOUNT_COMPROMISE,
        (
            "Use the official service app or website to change the password.",
            "Sign out other sessions and review recent activity.",
            "Contact the provider using a trusted support channel.",
        ),
        (
            "Do not use account-recovery links supplied by the suspicious message.",
            "Do not share verification codes with anyone claiming to help.",
        ),
        (
            "Contact your bank immediately if financial accounts or payment instruments may be affected.",
            "Preserve evidence and report unauthorized activity through the service's official process.",
        ),
        ("The correct recovery steps depend on the affected service.",),
    ),
    SituationCategory.MONEY_ALREADY_SENT: SafetyGuidance(
        SituationCategory.MONEY_ALREADY_SENT,
        (
            "Contact the bank, card issuer, wallet, or transfer service immediately and ask about recall or fraud procedures.",
            "Save receipts, transaction IDs, addresses, and the conversation.",
            "Report the incident to the relevant platform and local authorities.",
        ),
        (
            "Do not pay an additional fee to unlock, recover, or refund the money.",
            "Do not continue negotiating with the recipient if they pressure you.",
        ),
        (
            "Change any credentials shared with the recipient using the official service.",
            "Monitor accounts and cards for further unauthorized activity.",
        ),
        ("Recovery is not guaranteed; act quickly through the payment provider.",),
    ),
}


def get_safety_guidance(category: str) -> SafetyGuidance:
    """Return guidance for a supported category, rejecting unknown values."""

    if not isinstance(category, str):
        raise TypeError("category must be a string")
    try:
        normalized = SituationCategory(category.strip().lower())
    except ValueError as exc:
        choices = ", ".join(item.value for item in SituationCategory)
        raise ValueError(f"unsupported category; choose one of: {choices}") from exc
    return _GUIDANCE[normalized]
