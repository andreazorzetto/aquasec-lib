"""
Assurance policy API functions for the aquasec library.

Assurance policies are addressed by type *and* name:
``/api/v2/assurance_policy/{type}/{name}``. The types are ``image``, ``host``,
``function`` and ``kubernetes``; a policy of one type is invisible under another.

Same conventions as ``runtime_policies``: ``api_*`` functions return the raw
response, the rest interpret it, return None for "does not exist", and raise
``ApiError`` otherwise. Every call has a timeout.
"""

from .common import (
    _request_with_retry,
    path_segment,
    resolve_timeout,
    response_json,
    server_message,
)
from .exceptions import ApiError

ASSURANCE_POLICY_PATH = "/api/v2/assurance_policy"

ASSURANCE_TYPES = ("image", "host", "function", "kubernetes")

_JSON = {"Content-Type": "application/json"}


def _check_type(assurance_type):
    if assurance_type not in ASSURANCE_TYPES:
        raise ValueError(
            f"unknown assurance policy type {assurance_type!r}; "
            f"expected one of: {', '.join(ASSURANCE_TYPES)}"
        )


def _collection_url(server, assurance_type):
    _check_type(assurance_type)
    return f"{server}{ASSURANCE_POLICY_PATH}/{assurance_type}"


def _item_url(server, assurance_type, name):
    return f"{_collection_url(server, assurance_type)}/{path_segment(name)}"


def _raise(res, action):
    raise ApiError(
        f"{action}: HTTP {res.status_code} - {server_message(res)}",
        status_code=res.status_code,
        response_text=res.text,
    )


# --------------------------------------------------------------------------- #
# Raw calls
# --------------------------------------------------------------------------- #

def api_get_assurance_policies(server, token, assurance_type, page=1, page_size=100,
                               timeout=None, verbose=False):
    """List assurance policies of one type, one page (raw call)."""
    api_url = _collection_url(server, assurance_type)
    if verbose:
        print(f"GET {api_url} page={page}")
    return _request_with_retry('GET', api_url, token,
                               params={'page': page, 'pagesize': page_size},
                               timeout=resolve_timeout(timeout), verbose=verbose)


def api_get_assurance_policy(server, token, assurance_type, name, timeout=None, verbose=False):
    """Get one assurance policy by type and name (raw call). Missing is HTTP 404."""
    api_url = _item_url(server, assurance_type, name)
    if verbose:
        print(f"GET {api_url}")
    return _request_with_retry('GET', api_url, token,
                               timeout=resolve_timeout(timeout), verbose=verbose)


def api_create_assurance_policy(server, token, assurance_type, policy, timeout=None,
                                verbose=False):
    """Create an assurance policy of the given type (raw call)."""
    api_url = _collection_url(server, assurance_type)
    if verbose:
        print(f"POST {api_url} name={policy.get('name')!r}")
    return _request_with_retry('POST', api_url, token, headers=dict(_JSON), json=policy,
                               timeout=resolve_timeout(timeout), verbose=verbose)


def api_update_assurance_policy(server, token, assurance_type, name, policy, timeout=None,
                                verbose=False):
    """Replace an assurance policy (raw call). Send the complete object."""
    api_url = _item_url(server, assurance_type, name)
    if verbose:
        print(f"PUT {api_url}")
    return _request_with_retry('PUT', api_url, token, headers=dict(_JSON), json=policy,
                               timeout=resolve_timeout(timeout), verbose=verbose)


def api_delete_assurance_policy(server, token, assurance_type, name, timeout=None,
                                verbose=False):
    """Delete an assurance policy by type and name (raw call)."""
    api_url = _item_url(server, assurance_type, name)
    if verbose:
        print(f"DELETE {api_url}")
    return _request_with_retry('DELETE', api_url, token,
                               timeout=resolve_timeout(timeout), verbose=verbose)


# --------------------------------------------------------------------------- #
# Interpreted calls
# --------------------------------------------------------------------------- #

def get_assurance_policy(server, token, assurance_type, name, timeout=None, verbose=False):
    """The complete assurance policy, or None if none of that type has that name."""
    res = api_get_assurance_policy(server, token, assurance_type, name,
                                   timeout=timeout, verbose=verbose)
    if res.status_code == 404:
        return None
    if res.status_code != 200:
        _raise(res, f"Failed to get {assurance_type} assurance policy {name!r}")
    return res.json()


def get_all_assurance_policies(server, token, assurance_type, page_size=100, timeout=None,
                               verbose=False):
    """Every assurance policy of one type, across all pages."""
    policies = []
    page = 1
    while True:
        res = api_get_assurance_policies(server, token, assurance_type, page=page,
                                         page_size=page_size, timeout=timeout,
                                         verbose=verbose)
        if res.status_code != 200:
            _raise(res, f"Failed to list {assurance_type} assurance policies")
        body = res.json() or {}
        result = body.get("result") or []
        if not result:
            break
        policies.extend(result)
        count = body.get("count")
        if isinstance(count, int) and len(policies) >= count:
            break
        page += 1
    return policies


def create_assurance_policy(server, token, assurance_type, policy, timeout=None,
                            verbose=False):
    """Create an assurance policy. Returns the response body, or None if empty."""
    if not policy.get("name"):
        raise ValueError("an assurance policy needs a name")
    res = api_create_assurance_policy(server, token, assurance_type, policy,
                                      timeout=timeout, verbose=verbose)
    if not 200 <= res.status_code < 300:
        _raise(res, f"Failed to create {assurance_type} assurance policy {policy['name']!r}")
    return response_json(res)


def update_assurance_policy(server, token, assurance_type, name, policy, timeout=None,
                            verbose=False):
    """Replace an assurance policy. Returns the response body, or None if empty."""
    res = api_update_assurance_policy(server, token, assurance_type, name, policy,
                                      timeout=timeout, verbose=verbose)
    if not 200 <= res.status_code < 300:
        _raise(res, f"Failed to update {assurance_type} assurance policy {name!r}")
    return response_json(res)


def delete_assurance_policy(server, token, assurance_type, name, missing_ok=False,
                            timeout=None, verbose=False):
    """Delete an assurance policy. True if deleted, False if missing and ``missing_ok``."""
    res = api_delete_assurance_policy(server, token, assurance_type, name,
                                      timeout=timeout, verbose=verbose)
    if res.status_code == 404 and missing_ok:
        return False
    if not 200 <= res.status_code < 300:
        _raise(res, f"Failed to delete {assurance_type} assurance policy {name!r}")
    return True
