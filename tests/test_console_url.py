"""Tests for console URL normalisation, token-derived URLs and URL validation."""

import base64
import json
import os
import sys
from unittest.mock import Mock, patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from aquasec.common import (normalize_console_url, validate_console_url,
                            get_console_url, resolve_console_url)
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


class TestResolveConsoleUrl:
    """
    CSP_ENDPOINT when set, the token's own metadata otherwise.

    Callers were chaining get_console_url() and get_console_urls_from_token()
    by hand, and getting that chain wrong fails at the first data call rather
    than at sign-in — so the failure surfaces a long way from its cause.
    """

    def test_env_wins_when_set(self):
        tok = _token({"csp_metadata": {"urls": {"ese_url": "from-token.cloud.aquasec.com"}}})
        with patch.dict(os.environ, {"CSP_ENDPOINT": "https://from-env.cloud.aquasec.com"}):
            assert resolve_console_url(tok) == "https://from-env.cloud.aquasec.com"

    def test_env_is_normalised_like_any_other_input(self):
        with patch.dict(os.environ, {"CSP_ENDPOINT": "TENANT.cloud.aquasec.com:443/"}):
            assert resolve_console_url() == "https://tenant.cloud.aquasec.com"

    def test_token_used_when_env_unset(self):
        tok = _token({"csp_metadata": {"urls": {"ese_url": "from-token.cloud.aquasec.com"}}})
        with patch.dict(os.environ, {}, clear=True):
            assert resolve_console_url(tok) == "https://from-token.cloud.aquasec.com"

    def test_none_when_neither_source_has_one(self):
        with patch.dict(os.environ, {}, clear=True):
            assert resolve_console_url() is None

    def test_token_without_metadata_yields_none(self):
        """An on-prem token carries no csp_metadata; that is not an error."""
        with patch.dict(os.environ, {}, clear=True):
            assert resolve_console_url(_token({"account_id": 1})) is None

    def test_malformed_token_does_not_raise(self):
        """Callers pass whatever sign-in returned; a bad token must not explode."""
        with patch.dict(os.environ, {}, clear=True):
            assert resolve_console_url("not-a-jwt") is None
            assert resolve_console_url("") is None

    def test_empty_env_falls_through_to_the_token(self):
        """CSP_ENDPOINT='' is unset, not an instruction to use the empty string."""
        tok = _token({"csp_metadata": {"urls": {"ese_url": "from-token.cloud.aquasec.com"}}})
        with patch.dict(os.environ, {"CSP_ENDPOINT": ""}):
            assert resolve_console_url(tok) == "https://from-token.cloud.aquasec.com"


class TestAuthenticateGating:
    """
    API-key auth must not require CSP_ENDPOINT.

    Sign-in goes to the regional API endpoint, api_auth() never receives the
    console URL, and the token carries it. Gating on it made a complete set of
    API-key credentials report "missing credentials", which points at the wrong
    problem entirely.
    """

    KEYS = {"AQUA_KEY": "k", "AQUA_SECRET": "s", "AQUA_ROLE": "r",
            "AQUA_METHODS": "ANY", "AQUA_ENDPOINT": "https://eu-1.api.cloudsploit.com"}

    def test_api_keys_without_csp_endpoint_authenticate(self):
        from aquasec import auth as auth_mod
        with patch.dict(os.environ, self.KEYS, clear=True), \
             patch.object(auth_mod, "api_auth", return_value="tok") as m:
            assert auth_mod.authenticate() == "tok"
        assert m.called, "API-key branch was not taken without CSP_ENDPOINT"

    def test_on_prem_still_requires_csp_endpoint(self):
        """The on-prem branch is unchanged: console URL, and no API endpoint."""
        from aquasec import auth as auth_mod
        env = {"AQUA_USER": "u", "AQUA_PASSWORD": "p",
               "CSP_ENDPOINT": "https://onprem.example.com"}
        with patch.dict(os.environ, env, clear=True), \
             patch.object(auth_mod, "user_pass_onprem_auth", return_value="tok") as m:
            assert auth_mod.authenticate() == "tok"
        assert m.called, "on-prem branch no longer reachable"

    def test_incomplete_api_keys_still_rejected(self):
        """
        Relaxing one requirement must not relax the rest.

        Incomplete credentials exit rather than returning — authenticate() is
        the entry point of CLI tools and treats this as fatal, which is why the
        old CSP_ENDPOINT gate was so costly: a complete set of API keys took
        this branch and the process died telling you they were missing.
        """
        import pytest
        from aquasec import auth as auth_mod
        partial = dict(self.KEYS)
        partial.pop("AQUA_ROLE")
        with patch.dict(os.environ, partial, clear=True):
            with pytest.raises(SystemExit):
                auth_mod.authenticate()
