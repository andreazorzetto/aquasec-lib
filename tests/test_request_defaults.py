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
