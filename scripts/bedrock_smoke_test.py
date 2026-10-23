"""Optional live Bedrock smoke test using a synthetic message.

This script makes one real Bedrock request and may incur charges. It prints
only the validated response shape, not the submitted prompt or raw response.
"""

from __future__ import annotations

from scamshield.bedrock_service import (
    BedrockConfigurationError,
    BedrockExplanationService,
    BedrockServiceError,
)


def main() -> int:
    try:
        service = BedrockExplanationService.from_environment()
        explanation = service.explain(
            "Synthetic test message: your account will be blocked today. Do not reply with credentials.",
            {
                "status": "suspicious",
                "findings": [
                    {
                        "indicator_type": "urgency_threat",
                        "supporting_text": "account will be blocked today",
                    }
                ],
                "url_check": None,
            },
        )
    except BedrockConfigurationError as exc:
        print(f"Bedrock is not configured: {exc}")
        return 2
    except BedrockServiceError as exc:
        print(f"Bedrock smoke test failed: {exc}")
        return 1

    print("Bedrock smoke test completed.")
    print(f"Validated assessment length: {len(explanation.assessment)}")
    print(f"Warning signs returned: {len(explanation.supporting_warning_signs)}")
    print(f"Next steps returned: {len(explanation.recommended_next_steps)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
