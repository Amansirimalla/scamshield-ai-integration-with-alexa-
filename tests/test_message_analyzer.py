import pytest

from scamshield.message_analyzer import (
    IndicatorType,
    MessageAnalyzer,
    OverallStatus,
    Severity,
    analyze_message,
)


@pytest.mark.parametrize(
    ("message", "indicator", "severity"),
    [
        (
            "Pay a $50 processing fee today to release your package.",
            IndicatorType.UPFRONT_PAYMENT,
            Severity.HIGH,
        ),
        (
            "Security notice: reply with your OTP and PIN to verify your account.",
            IndicatorType.CREDENTIAL_REQUEST,
            Severity.HIGH,
        ),
        (
            "Act immediately or your account will be suspended today.",
            IndicatorType.URGENCY_THREAT,
            Severity.MEDIUM,
        ),
        (
            "Congratulations, you are the winner of a cash prize. Claim your reward.",
            IndicatorType.PRIZE_REWARD,
            Severity.MEDIUM,
        ),
        (
            "Guaranteed easy income job. Pay a training fee to begin.",
            IndicatorType.SUSPICIOUS_JOB_OFFER,
            Severity.MEDIUM,
        ),
        (
            "This is the bank security team. Verify your account now.",
            IndicatorType.IMPERSONATION,
            Severity.MEDIUM,
        ),
        (
            "Review your notice at https://example.com/verify before responding.",
            IndicatorType.URL_FOR_INVESTIGATION,
            Severity.MEDIUM,
        ),
    ],
)
def test_each_indicator_returns_structured_evidence(message, indicator, severity):
    result = analyze_message(message)

    finding = next(item for item in result.findings if item.indicator_type == indicator)
    assert finding.severity == severity
    assert finding.supporting_text
    assert finding.explanation
    assert finding.recommended_verification


def test_multiple_indicators_are_suspicious_but_not_proof():
    result = analyze_message(
        "Your bank account will be blocked today. Click https://example.com and send your OTP, "
        "then pay a $20 verification fee."
    )

    assert result.status == OverallStatus.SUSPICIOUS
    assert len(result.findings) >= 4
    assert any("not proof" in limitation for limitation in result.limitations)


def test_legitimate_message_without_signals_remains_inconclusive():
    result = analyze_message(
        "Hi Sam, our appointment is confirmed for Tuesday at 3 PM. "
        "Please bring the form we discussed."
    )

    assert result.status == OverallStatus.INCONCLUSIVE
    assert result.findings == ()
    assert any("does not prove the message is safe" in item for item in result.limitations)


def test_ambiguous_message_with_one_signal_remains_inconclusive():
    result = analyze_message("Your delivery update is available at https://carrier.example/track.")

    assert result.status == OverallStatus.INCONCLUSIVE
    assert [item.indicator_type for item in result.findings] == [IndicatorType.URL_FOR_INVESTIGATION]


def test_sensitive_values_are_redacted_from_evidence():
    result = analyze_message("Send your OTP: 123456 and password: hunter2 to verify.")

    evidence = result.findings[0].supporting_text
    assert "123456" not in evidence
    assert "hunter2" not in evidence
    assert "[REDACTED]" in evidence


def test_card_numbers_and_url_query_values_are_redacted_from_evidence():
    result = analyze_message(
        "Pay with card 4111 1111 1111 1111 at https://example.com/reset?token=abc123&email=user@example.com"
    )

    evidence = " ".join(item.supporting_text for item in result.findings)
    assert "4111 1111 1111 1111" not in evidence
    assert "token=abc123" not in evidence
    assert "email=user@example.com" not in evidence
    assert "[REDACTED_CARD_NUMBER]" in evidence
    assert "[query removed]" in evidence


def test_url_without_query_is_not_given_query_redaction_suffix():
    result = analyze_message("Review https://example.com/verify before responding.")

    evidence = " ".join(item.supporting_text for item in result.findings)
    assert "https://example.com/verify?[query removed]" not in evidence
    assert "https://example.com/verify" in evidence


def test_credential_words_without_a_request_are_not_high_severity_findings():
    result = analyze_message("Security notice: our password policy has changed. No action is required.")

    assert all(item.indicator_type != IndicatorType.CREDENTIAL_REQUEST for item in result.findings)


def test_secret_and_recovery_code_labels_are_redacted():
    result = analyze_message("Reply with your OTP: 123456 and secret: abcXYZ123.")

    evidence = " ".join(item.supporting_text for item in result.findings)
    assert "abcXYZ123" not in evidence
    assert "123456" not in evidence


@pytest.mark.parametrize(
    "message",
    ["", "   ", "\n\t"],
)
def test_empty_messages_are_rejected(message):
    with pytest.raises(ValueError, match="must not be empty"):
        analyze_message(message)


def test_non_string_messages_are_rejected():
    with pytest.raises(TypeError, match="must be a string"):
        analyze_message(None)  # type: ignore[arg-type]


def test_oversized_messages_are_rejected():
    with pytest.raises(ValueError, match="100-character limit"):
        MessageAnalyzer(max_message_length=100).analyze("x" * 101)


def test_invalid_analyzer_configuration_is_rejected():
    with pytest.raises(ValueError, match="greater than zero"):
        MessageAnalyzer(max_message_length=0)
    with pytest.raises(TypeError, match="must be an integer"):
        MessageAnalyzer(max_message_length=True)


def test_to_dict_is_json_serializable_shape():
    result = analyze_message("Pay a processing fee at https://example.com.")

    payload = result.to_dict()
    assert payload["status"] == "suspicious"
    assert isinstance(payload["findings"], list)
    assert payload["findings"][0]["indicator_type"] == "upfront_payment"
