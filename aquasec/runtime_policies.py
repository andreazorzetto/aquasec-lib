"""
Runtime policy API functions for the aquasec library.

Container, host and function runtime policies are one object type in Aqua,
distinguished by ``runtime_type``, and are addressed by **name** in the URL --
there is no numeric-ID form of these endpoints, and no rename operation.

Conventions, as elsewhere in the library:

* ``api_*`` functions make one call and return the ``requests.Response``
  unmodified, so a caller that needs the complete server object gets exactly
  what Aqua sent.
* The other functions interpret the response: they return parsed data, return
  ``None`` for "does not exist" where that is a normal answer, and raise
  ``ApiError`` for anything else. Nothing here calls ``sys.exit``.

Every call has a timeout (see ``common.resolve_timeout``); a stalled connection
must fail, not hang.

Field-name note: the control the console calls "Block Non-Compliant Images" is
``block_disallowed_images`` in the API. Aqua's published docs still name
``block_non_compliant_images``, which the API ignores on write. Aqua ignores
unknown fields generally, so a typo'd field returns success and changes nothing.
"""

from .common import (
    _request_with_retry,
    path_segment,
    resolve_timeout,
    response_json,
    server_message,
)
from .exceptions import ApiError

RUNTIME_POLICIES_PATH = "/api/v2/runtime_policies"

_JSON = {"Content-Type": "application/json"}


def _item_url(server, name):
    return f"{server}{RUNTIME_POLICIES_PATH}/{path_segment(name)}"


def _raise(res, action):
    raise ApiError(
        f"{action}: HTTP {res.status_code} - {server_message(res)}",
        status_code=res.status_code,
        response_text=res.text,
    )


# --------------------------------------------------------------------------- #
# Raw calls
# --------------------------------------------------------------------------- #

def api_get_runtime_policies(server, token, page=1, page_size=100, timeout=None, verbose=False):
    """List runtime policies, one page (raw call).

    The list response is a summary: several control fields are absent from it.
    Fetch a policy individually for the complete object.
    """
    api_url = server + RUNTIME_POLICIES_PATH
    if verbose:
        print(f"GET {api_url} page={page}")
    return _request_with_retry('GET', api_url, token,
                               params={'page': page, 'pagesize': page_size},
                               timeout=resolve_timeout(timeout), verbose=verbose)


def api_get_runtime_policy(server, token, name, timeout=None, verbose=False):
    """Get one runtime policy by name (raw call). A missing policy is HTTP 404."""
    api_url = _item_url(server, name)
    if verbose:
        print(f"GET {api_url}")
    return _request_with_retry('GET', api_url, token,
                               timeout=resolve_timeout(timeout), verbose=verbose)


def api_create_runtime_policy(server, token, policy, timeout=None, verbose=False):
    """Create a runtime policy (raw call). ``policy`` must include ``name``.

    A sparse body is accepted; Aqua fills in its defaults and returns the
    complete object. Note the default ``application_scopes`` is ``["Global"]``,
    so a policy created without scopes applies to every workload.
    """
    api_url = server + RUNTIME_POLICIES_PATH
    if verbose:
        print(f"POST {api_url} name={policy.get('name')!r}")
    return _request_with_retry('POST', api_url, token, headers=dict(_JSON), json=policy,
                               timeout=resolve_timeout(timeout), verbose=verbose)


def api_update_runtime_policy(server, token, name, policy, timeout=None, verbose=False):
    """Replace a runtime policy (raw call).

    This is a full REPLACE, not a merge: fields left out of the body are reset.
    Verified live -- a PUT naming only a few fields switched off two controls it
    did not mention. Read the policy, change the fields you mean to change, and
    send the whole object back. The object exactly as GET returned it (server
    fields such as ``author`` included) is accepted.
    """
    api_url = _item_url(server, name)
    if verbose:
        print(f"PUT {api_url}")
    return _request_with_retry('PUT', api_url, token, headers=dict(_JSON), json=policy,
                               timeout=resolve_timeout(timeout), verbose=verbose)


def api_delete_runtime_policy(server, token, name, timeout=None, verbose=False):
    """Delete a runtime policy by name (raw call)."""
    api_url = _item_url(server, name)
    if verbose:
        print(f"DELETE {api_url}")
    return _request_with_retry('DELETE', api_url, token,
                               timeout=resolve_timeout(timeout), verbose=verbose)


# --------------------------------------------------------------------------- #
# Interpreted calls
# --------------------------------------------------------------------------- #

def get_runtime_policy(server, token, name, timeout=None, verbose=False):
    """The complete runtime policy, or None if no policy has that name.

    Raises:
        ApiError: for any response other than 200 or 404.
    """
    res = api_get_runtime_policy(server, token, name, timeout=timeout, verbose=verbose)
    if res.status_code == 404:
        return None
    if res.status_code != 200:
        _raise(res, f"Failed to get runtime policy {name!r}")
    return res.json()


def get_all_runtime_policies(server, token, page_size=100, timeout=None, verbose=False):
    """Every runtime policy (summary form), across all pages.

    Raises:
        ApiError: if any page fails.
    """
    policies = []
    page = 1
    while True:
        res = api_get_runtime_policies(server, token, page=page, page_size=page_size,
                                       timeout=timeout, verbose=verbose)
        if res.status_code != 200:
            _raise(res, "Failed to list runtime policies")
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


def create_runtime_policy(server, token, policy, timeout=None, verbose=False):
    """Create a runtime policy.

    Returns:
        The response body when Aqua sends one, otherwise None.

    Raises:
        ValueError: if ``policy`` has no name.
        ApiError: on any non-2xx response (409 if the name is taken).
    """
    if not policy.get("name"):
        raise ValueError("a runtime policy needs a name")
    res = api_create_runtime_policy(server, token, policy, timeout=timeout, verbose=verbose)
    if not 200 <= res.status_code < 300:
        _raise(res, f"Failed to create runtime policy {policy['name']!r}")
    return response_json(res)


def update_runtime_policy(server, token, name, policy, timeout=None, verbose=False):
    """Replace a runtime policy with ``policy`` (the complete object).

    Returns:
        The response body when Aqua sends one, otherwise None.

    Raises:
        ApiError: on any non-2xx response (404 if it does not exist).
    """
    res = api_update_runtime_policy(server, token, name, policy, timeout=timeout,
                                    verbose=verbose)
    if not 200 <= res.status_code < 300:
        _raise(res, f"Failed to update runtime policy {name!r}")
    return response_json(res)


def delete_runtime_policy(server, token, name, missing_ok=False, timeout=None, verbose=False):
    """Delete a runtime policy.

    Returns:
        True if it was deleted, False if it did not exist and ``missing_ok``.

    Raises:
        ApiError: on any other non-2xx response, or 404 without ``missing_ok``.
    """
    res = api_delete_runtime_policy(server, token, name, timeout=timeout, verbose=verbose)
    if res.status_code == 404 and missing_ok:
        return False
    if not 200 <= res.status_code < 300:
        _raise(res, f"Failed to delete runtime policy {name!r}")
    return True
