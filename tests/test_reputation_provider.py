from unittest.mock import Mock, patch

from scamshield.reputation import GoogleSafeBrowsingProvider, ReputationStatus


def test_provider_marks_matches_malicious_without_fetching_url():
    response = Mock()
    response.raise_for_status.return_value = None
    response.json.return_value = {"matches": [{"threatType": "SOCIAL_ENGINEERING"}]}

    with patch("scamshield.reputation.httpx.post", return_value=response) as post, patch(
        "scamshield.reputation.httpx.get"
    ) as get:
        result = GoogleSafeBrowsingProvider("test-key").check("https://example.com/path?token=secret")

    post.assert_called_once()
    get.assert_not_called()
    assert result.status == ReputationStatus.MALICIOUS
    assert result.evidence[0]["threatType"] == "SOCIAL_ENGINEERING"
    assert "token=secret" not in post.call_args.kwargs["json"]["threatInfo"]["threatEntries"][0]["url"]
    assert post.call_args.kwargs["follow_redirects"] is False


def test_provider_reports_no_threat_without_claiming_safe():
    response = Mock()
    response.raise_for_status.return_value = None
    response.json.return_value = {}

    with patch("scamshield.reputation.httpx.post", return_value=response):
        result = GoogleSafeBrowsingProvider("test-key").check("https://example.com")

    assert result.status == ReputationStatus.NO_THREAT_FOUND
    assert any("does not prove" in item for item in result.limitations)


def test_provider_errors_are_structured():
    with patch("scamshield.reputation.httpx.post", side_effect=RuntimeError("secret token")):
        result = GoogleSafeBrowsingProvider("test-key").check("https://example.com")

    assert result.status == ReputationStatus.LOOKUP_FAILED
    assert "secret token" not in result.details


def test_rate_limit_is_lookup_failed():
    response = Mock(status_code=429)
    with patch("scamshield.reputation.httpx.post", return_value=response):
        result = GoogleSafeBrowsingProvider("test-key").check("https://example.com")

    assert result.status == ReputationStatus.LOOKUP_FAILED


def test_authentication_failure_is_lookup_failed():
    response = Mock(status_code=401)
    with patch("scamshield.reputation.httpx.post", return_value=response):
        result = GoogleSafeBrowsingProvider("test-key").check("https://example.com")

    assert result.status == ReputationStatus.LOOKUP_FAILED


def test_malformed_provider_json_is_lookup_failed():
    response = Mock(status_code=200)
    response.raise_for_status.return_value = None
    response.json.side_effect = ValueError("malformed")

    with patch("scamshield.reputation.httpx.post", return_value=response):
        result = GoogleSafeBrowsingProvider("test-key").check("https://example.com")

    assert result.status == ReputationStatus.LOOKUP_FAILED


def test_sensitive_query_and_fragment_are_removed():
    from scamshield.reputation import UrlReputationService

    result = UrlReputationService().check(
        "https://example.com/path?utm_source=test&session=private#fragment"
    )

    assert result.url == "https://example.com"


def test_sensitive_path_is_not_sent_to_provider():
    response = Mock(status_code=200)
    response.raise_for_status.return_value = None
    response.json.return_value = {}

    with patch("scamshield.reputation.httpx.post", return_value=response) as post:
        GoogleSafeBrowsingProvider("test-key").check(
            "https://example.com/reset/secret-token"
        )

    submitted = post.call_args.kwargs["json"]["threatInfo"]["threatEntries"][0]["url"]
    assert submitted == "https://example.com"
    assert "secret-token" not in submitted
