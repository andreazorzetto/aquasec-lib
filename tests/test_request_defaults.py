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
