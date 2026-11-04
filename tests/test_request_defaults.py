"""Library-wide request defaults: TLS verification and timeout."""

import os
import sys
from unittest.mock import Mock, patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from aquasec.common import (
    _request_with_retry,
    get_request_defaults,
    reset_request_defaults,
    resolve_timeout,
    set_request_defaults,
    DEFAULT_API_TIMEOUT,
)


def _ok():
    m = Mock()
    m.status_code = 200
    return m


@patch("aquasec.common.requests.request")
def test_verification_stays_off_by_default_for_backward_compatibility(request):
    request.return_value = _ok()
    _request_with_retry("GET", "https://x/api", "t")
    assert request.call_args.kwargs["verify"] is False
    assert "timeout" not in request.call_args.kwargs


@patch("aquasec.common.requests.request")
def test_a_ca_bundle_can_be_set_library_wide(request):
    request.return_value = _ok()
    set_request_defaults(verify="/etc/ssl/internal-ca.pem", timeout=12)
    _request_with_retry("GET", "https://x/api", "t")
    assert request.call_args.kwargs["verify"] == "/etc/ssl/internal-ca.pem"
    assert request.call_args.kwargs["timeout"] == 12


@patch("aquasec.common.requests.request")
def test_an_explicit_argument_beats_the_default(request):
    request.return_value = _ok()
    set_request_defaults(verify=True, timeout=12)
    _request_with_retry("GET", "https://x/api", "t", verify=False, timeout=1800)
    assert request.call_args.kwargs["verify"] is False
    assert request.call_args.kwargs["timeout"] == 1800


def test_timeout_resolution_order():
    assert resolve_timeout() == DEFAULT_API_TIMEOUT
    set_request_defaults(timeout=5)
    assert resolve_timeout() == 5
    assert resolve_timeout(9) == 9
    set_request_defaults(timeout=None)
    assert resolve_timeout() == DEFAULT_API_TIMEOUT


def test_reset_restores_the_original_defaults():
    set_request_defaults(verify=True, timeout=3)
    reset_request_defaults()
    assert get_request_defaults() == {"verify": False}


# --- Sign-in calls --------------------------------------------------------------

def _login_ok(payload):
    m = Mock()
    m.status_code = 200
    m.json.return_value = payload
    return m


def _sign_in_all_three(post):
    from aquasec import auth
    post.return_value = _login_ok({"data": "tok"})
    auth.api_auth("k", "s", "https://api.example", "role", '["ANY:*"]')
    key_verify = post.call_args.kwargs["verify"]

    post.return_value = _login_ok({"data": {"token": "tok"}})
    auth.user_pass_saas_auth("u", "p", "https://api.example")
    saas_user_verify = post.call_args.kwargs["verify"]

    post.return_value = _login_ok({"token": "tok"})
    auth.user_pass_onprem_auth("u", "p", "https://aqua.internal")
    onprem_verify = post.call_args.kwargs["verify"]
    return key_verify, saas_user_verify, onprem_verify


@patch("aquasec.auth.requests.post")
def test_sign_in_keeps_its_historical_tls_behaviour_by_default(post):
    """No caller-visible change unless a setting is chosen."""
    assert _sign_in_all_three(post) == (True, False, False)


@patch("aquasec.auth.requests.post")
def test_an_explicit_ca_bundle_reaches_every_sign_in_call(post):
    """Sign-in carries the password: it must honour the caller's TLS choice,
    on-prem above all, where an internal CA is the norm."""
    set_request_defaults(verify="/etc/ssl/internal-ca.pem")
    assert _sign_in_all_three(post) == ("/etc/ssl/internal-ca.pem",) * 3


@patch("aquasec.auth.requests.post")
def test_reset_restores_historical_sign_in_behaviour(post):
    set_request_defaults(verify=True)
    reset_request_defaults()
    assert _sign_in_all_three(post) == (True, False, False)


class TestRateLimit:
    def _responses(self, *codes, headers=None):
        from unittest.mock import Mock
        return [Mock(status_code=c, headers=headers or {}) for c in codes]

    def test_a_429_is_waited_out(self):
        from unittest.mock import patch
        from aquasec.common import _request_with_retry
        with patch("aquasec.common.requests.request", side_effect=self._responses(429, 429, 200)) as request, \
                patch("aquasec.common.time.sleep") as sleep:
            assert _request_with_retry("GET", "https://x", "t").status_code == 200
        assert request.call_count == 3
        assert [c.args[0] for c in sleep.call_args_list] == [2.0, 4.0]

    def test_retry_after_is_honoured_up_to_the_cap(self):
        from unittest.mock import patch
        from aquasec.common import _request_with_retry
        for value, waited in (("7", 7.0), ("9999", 30.0)):
            with patch("aquasec.common.requests.request",
                       side_effect=self._responses(429, 200, headers={"Retry-After": value})), \
                    patch("aquasec.common.time.sleep") as sleep:
                _request_with_retry("GET", "https://x", "t")
            assert sleep.call_args.args[0] == waited

    def test_it_gives_up_and_returns_the_429(self):
        from unittest.mock import patch
        from aquasec.common import _request_with_retry
        with patch("aquasec.common.requests.request", side_effect=self._responses(*[429] * 5)) as request, \
                patch("aquasec.common.time.sleep"):
            assert _request_with_retry("GET", "https://x", "t").status_code == 429
        assert request.call_count == 5


class TestRedirects:
    def test_a_sign_in_follows_as_set(self):
        from unittest.mock import Mock, patch
        from aquasec.auth import user_pass_onprem_auth
        from aquasec.common import reset_request_defaults, set_request_defaults
        res = Mock(status_code=200, json=lambda: {"token": "t"}, headers={})
        try:
            with patch("aquasec.auth.requests.post", return_value=res) as post:
                user_pass_onprem_auth("u", "p", "https://x")
            assert post.call_args.kwargs["allow_redirects"] is True

            set_request_defaults(allow_redirects=False)
            with patch("aquasec.auth.requests.post", return_value=res) as post:
                user_pass_onprem_auth("u", "p", "https://x")
            assert post.call_args.kwargs["allow_redirects"] is False
        finally:
            reset_request_defaults()

    def test_other_calls_follow_as_set(self):
        from unittest.mock import Mock, patch
        from aquasec.common import _request_with_retry, reset_request_defaults, set_request_defaults
        try:
            set_request_defaults(allow_redirects=False)
            with patch("aquasec.common.requests.request", return_value=Mock(status_code=200)) as request:
                _request_with_retry("GET", "https://x", "t")
            assert request.call_args.kwargs["allow_redirects"] is False
        finally:
            reset_request_defaults()


def test_a_bad_retry_after_falls_back():
    from unittest.mock import Mock
    from aquasec.common import _retry_after
    for value in ("-1", "nan", "inf", "Wed, 21 Oct 2026 07:28:00 GMT"):
        assert _retry_after(Mock(headers={"Retry-After": value}), 0) == 2.0
