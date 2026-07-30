"""Tests for console URL normalisation, token-derived URLs and URL validation."""

import base64
import json
import os
import sys
from unittest.mock import Mock, patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from aquasec.common import normalize_console_url, validate_console_url, get_console_url
from aquasec.auth import decode_token_claims, get_console_urls_from_token


def _token(claims):
    """Build an unsigned JWT-shaped token carrying the given claims."""
    payload = base64.urlsafe_b64encode(json.dumps(claims).encode()).rstrip(b'=').decode()
    return f"header.{payload}.signature"


class TestNormalizeConsoleUrl:
    """Accept the forms people actually paste."""

    def test_bare_host_gets_https(self):
        assert normalize_console_url("tenant.cloud.aquasec.com") == "https://tenant.cloud.aquasec.com"

    def test_explicit_443_is_dropped(self):
        assert normalize_console_url("tenant.cloud.aquasec.com:443") == "https://tenant.cloud.aquasec.com"

    def test_https_with_443_is_dropped(self):
        assert normalize_console_url("https://tenant.cloud.aquasec.com:443") == "https://tenant.cloud.aquasec.com"

    def test_trailing_slash_removed(self):
        assert normalize_console_url("https://tenant.cloud.aquasec.com/") == "https://tenant.cloud.aquasec.com"

    def test_path_and_fragment_discarded(self):
        assert normalize_console_url("https://tenant.cloud.aquasec.com/#/dashboard") == \
            "https://tenant.cloud.aquasec.com"

    def test_case_and_whitespace_normalised(self):
        assert normalize_console_url("  HTTPS://Tenant.Cloud.Aquasec.Com  ") == \
            "https://tenant.cloud.aquasec.com"

    def test_surrounding_quotes_stripped(self):
        assert normalize_console_url('"https://tenant.cloud.aquasec.com"') == \
            "https://tenant.cloud.aquasec.com"

    def test_custom_onprem_port_preserved(self):
        # On-prem consoles commonly run on a non-default port; keep it.
        assert normalize_console_url("aqua.company.internal:8443") == "https://aqua.company.internal:8443"

    def test_http_scheme_preserved_and_port_80_dropped(self):
        assert normalize_console_url("http://aqua.internal:80") == "http://aqua.internal"
        assert normalize_console_url("http://aqua.internal:8080") == "http://aqua.internal:8080"

    def test_empty_and_none_passthrough(self):
        assert normalize_console_url("") == ""
        assert normalize_console_url(None) is None

    def test_already_normalised_is_stable(self):
        url = "https://tenant.cloud.aquasec.com"
        assert normalize_console_url(normalize_console_url(url)) == url


class TestGetConsoleUrl:
    def test_reads_and_normalises_env(self):
        with patch.dict(os.environ, {'CSP_ENDPOINT': 'tenant.cloud.aquasec.com:443'}):
            assert get_console_url() == "https://tenant.cloud.aquasec.com"

    def test_none_when_unset(self):
        with patch.dict(os.environ, {'CSP_ENDPOINT': ''}):
            assert get_console_url() is None


class TestTokenDerivedUrls:
    """SaaS tokens carry csp_metadata.urls; on-prem tokens do not."""

    def test_extracts_console_and_gateway(self):
        tok = _token({"csp_metadata": {"urls": {
            "ese_url": "tenant.cloud.aquasec.com",
            "ese_gw_url": "tenant-gw.cloud.aquasec.com"}}})
        urls = get_console_urls_from_token(tok)
        assert urls['console'] == "https://tenant.cloud.aquasec.com"
        assert urls['gateway'] == "https://tenant-gw.cloud.aquasec.com"

    def test_missing_metadata_yields_none(self):
        urls = get_console_urls_from_token(_token({"user_id": 1}))
        assert urls == {'console': None, 'gateway': None}

    def test_garbage_token_does_not_raise(self):
        assert decode_token_claims("not-a-jwt") == {}
        assert get_console_urls_from_token("not-a-jwt") == {'console': None, 'gateway': None}

    def test_claims_decoded_without_padding(self):
        # Payloads are base64url without '=' padding; decoding must still work.
        claims = decode_token_claims(_token({"account_id": 400002, "plan": "enterprise"}))
        assert claims["account_id"] == 400002


def _resp(status=200, content_type="application/json"):
    m = Mock()
    m.status_code = status
    m.headers = {'content-type': content_type}
    return m


class TestValidateConsoleUrl:
    """The gateway host authenticates fine but answers gRPC, not REST."""

    @patch('aquasec.common.requests.get')
    def test_console_ok(self, mock_get):
        mock_get.return_value = _resp(200, "application/json")
        ok, msg = validate_console_url("https://tenant.cloud.aquasec.com", "tok")
        assert ok is True

    @patch('aquasec.common.requests.get')
    def test_gateway_rejected_with_correction(self, mock_get):
        mock_get.return_value = _resp(415, "application/grpc")
        ok, msg = validate_console_url("https://tenant-gw.cloud.aquasec.com", "tok")
        assert ok is False
        assert "gateway" in msg
        # Offers the corrected host
        assert "https://tenant.cloud.aquasec.com" in msg

    @patch('aquasec.common.requests.get')
    def test_grpc_content_type_alone_is_rejected(self, mock_get):
        mock_get.return_value = _resp(200, "application/grpc")
        ok, _ = validate_console_url("https://something.example.com", "tok")
        assert ok is False

    @patch('aquasec.common.requests.get')
    def test_permission_error_still_counts_as_reachable(self, mock_get):
        mock_get.return_value = _resp(403, "application/json")
        ok, msg = validate_console_url("https://tenant.cloud.aquasec.com", "tok")
        assert ok is True
        assert "403" in msg

    @patch('aquasec.common.requests.get')
    def test_unreachable_host_reported(self, mock_get):
        import requests as _requests
        mock_get.side_effect = _requests.exceptions.ConnectionError("nope")
        ok, msg = validate_console_url("https://typo.cloud.aquasec.com", "tok")
        assert ok is False
        assert "Could not reach" in msg

    @patch('aquasec.common.requests.get')
    def test_unexpected_html_response_rejected(self, mock_get):
        mock_get.return_value = _resp(200, "text/html")
        ok, _ = validate_console_url("https://wrong.example.com", "tok")
        assert ok is False
