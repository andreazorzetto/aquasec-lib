"""
Common utility functions for Aqua library
"""

import base64
import csv
import json
import threading
import time
import requests
from os.path import exists
from urllib.parse import quote, urlparse

# How an expired token gets replaced, in order of preference:
#
#   1. a provider registered with set_token_provider() -- for applications that
#      hold their own credentials (secrets manager, vault) and sign in with
#      api_auth() rather than through AQUA_* environment variables;
#   2. authenticate(), when a complete set of AQUA_* variables is present;
#   3. nothing -- the 401 is returned to the caller.
#
# _refreshed maps the token a caller keeps passing in to (fresh token, when it
# was obtained), so a refresh is only ever applied to the token it replaced. A
# single global "cached token" would silently override whatever token a caller
# passed, which is exactly wrong for a process that juggles more than one.
_token_provider = None
_refreshed = {}
_refresh_lock = threading.Lock()

# A token obtained by refresh this recently and *still* rejected is not an
# expiry -- it is a wrong host, a revoked role, a token scope problem -- and
# signing in again on every request would only hammer the auth endpoint.
REFRESH_BACKOFF_SECONDS = 60

# Per-token maps must not grow for the lifetime of a long-running process.
_TOKEN_MAP_MAX = 64

# Defaults applied to every request made through _request_with_retry unless the
# call passes its own value.
#
# TLS verification stays off by default for backward compatibility: every
# utility built on this library has relied on that. An application that can name
# a CA bundle should call set_request_defaults(verify="/path/to/ca.pem") -- an
# on-prem console behind an internal CA is exactly where a verified chain is
# worth having, and an air-gapped network does not make an unverified one safe.
_REQUEST_DEFAULTS_INITIAL = {"verify": False}
_request_defaults = dict(_REQUEST_DEFAULTS_INITIAL)

# Timeout used by API functions that take a ``timeout`` argument and were not
# given one, when no library-wide default has been set. Without a timeout a
# stalled connection blocks forever, which in a CI job or a Kubernetes hook means
# a pipeline that never finishes rather than one that fails.
DEFAULT_API_TIMEOUT = 30

_UNSET = object()


def set_request_defaults(verify=_UNSET, timeout=_UNSET):
    """Set library-wide defaults for TLS verification and request timeout.

    Args:
        verify: ``True`` to verify against the system trust store, a path to a
            CA bundle, or ``False`` to disable verification (the default).
        timeout: Seconds, or a ``(connect, read)`` tuple. ``None`` removes a
            previously set default.

    A value passed explicitly to an individual call always wins.
    """
    if verify is not _UNSET:
        _request_defaults["verify"] = verify
    if timeout is not _UNSET:
        if timeout is None:
            _request_defaults.pop("timeout", None)
        else:
            _request_defaults["timeout"] = timeout


def get_request_defaults():
    """The current library-wide request defaults (a copy)."""
    return dict(_request_defaults)


def reset_request_defaults():
    """Restore the original request defaults. Mainly for tests."""
    _request_defaults.clear()
    _request_defaults.update(_REQUEST_DEFAULTS_INITIAL)


# Whether credential-bearing fields (enforcer registration tokens and the
# install commands that embed them) may appear in output the library produces
# itself: error messages and verbose printing. Off by default, because that
# output tends to land in CI and hook logs that are kept, shared and shipped.
# The data itself is never withheld -- functions return complete objects either
# way -- this only governs what the library writes out on its own.
_show_secrets = False


def set_show_secrets(show):
    """Allow (True) or redact (False, the default) secrets in library output.

    Affects error messages, ``ApiError.response_text`` and verbose output. Turn
    it on for interactive debugging; leave it off anywhere output is logged.
    """
    global _show_secrets
    _show_secrets = bool(show)


def get_show_secrets():
    """Whether secrets may currently appear in library output."""
    return _show_secrets


def resolve_timeout(timeout=None):
    """The timeout an API call should use: explicit, then library default, then 30s."""
    if timeout is not None:
        return timeout
    return _request_defaults.get("timeout", DEFAULT_API_TIMEOUT)


def path_segment(value):
    """Encode one URL path segment. Aqua names may contain spaces and slashes."""
    return quote(str(value), safe="")


def response_json(res):
    """The parsed JSON body, or None when there is none (e.g. 204) or it is not JSON."""
    if res.status_code == 204 or not (res.text or "").strip():
        return None
    try:
        return res.json()
    except ValueError:
        return None


def server_message(res):
    """Aqua's error message from a response body, falling back to the raw text."""
    body = response_json(res)
    if isinstance(body, dict) and body.get("message"):
        return str(body["message"])
    return (res.text or "").strip()[:500]


def _jwt_exp(token):
    """Expiry (epoch seconds) from a JWT's claims, or None if unreadable."""
    try:
        payload = token.split('.')[1]
        payload += '=' * (-len(payload) % 4)
        return json.loads(base64.urlsafe_b64decode(payload)).get('exp')
    except Exception:
        return None


def _prune_token_map(mapping, now=None):
    """
    Drop entries keyed by expired tokens, then the oldest beyond ``_TOKEN_MAP_MAX``.

    Both per-token maps in the library (refreshed tokens here, issuing
    endpoints in ``auth``) are keyed by bearer tokens, which expire; anything
    keyed by a dead token can never be looked up again.
    """
    now = time.time() if now is None else now
    for tok in [t for t in mapping if (_jwt_exp(t) or float('inf')) < now]:
        del mapping[tok]
    while len(mapping) > _TOKEN_MAP_MAX:
        del mapping[next(iter(mapping))]


def set_token_provider(provider):
    """
    Register a zero-argument callable that returns a fresh bearer token.

    Called by ``_request_with_retry`` when a request comes back 401. Use this
    when the credentials are not in the environment::

        from aquasec import api_auth, set_token_provider

        def fresh_token():
            key, secret = vault.read("aqua")
            return api_auth(key, secret, endpoint, role, '["ANY:*"]')

        set_token_provider(fresh_token)
        token = fresh_token()

    Pass ``None`` to unregister.
    """
    global _token_provider
    if provider is not None and not callable(provider):
        raise TypeError("token provider must be callable or None")
    _token_provider = provider
    _refreshed.clear()


def get_token_provider():
    """Return the registered token provider, or None."""
    return _token_provider


def _refresh_token(verbose=False):
    """
    Obtain a replacement token, or return None if there is no way to.

    Never raises for the *absence* of a way to refresh -- that is an ordinary
    outcome and the caller gets its 401 back. A provider or ``authenticate()``
    that fails while trying does raise, since that is a real error.
    """
    if _token_provider is not None:
        if verbose:
            print("Token rejected (401). Refreshing via the registered token provider...")
        return _token_provider()

    from .auth import authenticate, env_credentials_present
    if env_credentials_present():
        if verbose:
            print("Token rejected (401). Re-authenticating from environment credentials...")
        return authenticate(verbose=verbose)

    if verbose:
        print("Token rejected (401) and no way to refresh it: no token provider is "
              "registered and no AQUA_* credentials are in the environment. "
              "Returning the 401 to the caller.")
    return None


def normalize_console_url(url):
    """
    Normalise an Aqua console URL to ``scheme://host[:port]``.

    Accepts the forms people actually paste, e.g.::

        tenant.cloud.aquasec.com            -> https://tenant.cloud.aquasec.com
        tenant.cloud.aquasec.com:443        -> https://tenant.cloud.aquasec.com
        https://tenant.cloud.aquasec.com/   -> https://tenant.cloud.aquasec.com
        HTTPS://Tenant.Cloud.Aquasec.Com    -> https://tenant.cloud.aquasec.com
        http://aqua.internal:8443/#/home    -> http://aqua.internal:8443

    The scheme defaults to https when omitted. Default ports (443 for https,
    80 for http) are dropped; any other port is preserved, since on-prem
    consoles are commonly served on a custom port. Paths, query strings and
    fragments are discarded -- API calls append their own path.

    Args:
        url: The console URL as entered (may be None/empty)

    Returns:
        The normalised URL, or the input unchanged if it is empty/None.
    """
    if not url or not str(url).strip():
        return url

    raw = str(url).strip().strip('"').strip("'")

    # Without a scheme, urlparse would read "host:443" as scheme "host".
    if '://' not in raw:
        raw = 'https://' + raw.lstrip('/')

    parsed = urlparse(raw)
    scheme = (parsed.scheme or 'https').lower()
    host = (parsed.hostname or '').lower()
    if not host:
        return url

    try:
        port = parsed.port
    except ValueError:
        port = None

    if (scheme == 'https' and port == 443) or (scheme == 'http' and port == 80):
        port = None

    return f"{scheme}://{host}" + (f":{port}" if port else "")


def get_console_url():
    """
    Read the console URL from the environment, normalised.

    Use this instead of ``os.environ['CSP_ENDPOINT']`` so a URL supplied via the
    environment or a .env file gets the same normalisation as one entered during
    setup (bare host, explicit :443, trailing slash, and so on).

    Returns:
        The normalised console URL, or None when CSP_ENDPOINT is unset/empty.
    """
    import os
    return normalize_console_url(os.environ.get('CSP_ENDPOINT', '')) or None


def resolve_console_url(token=None, verbose=False):
    """
    Work out the console URL, preferring what the caller configured.

    ``CSP_ENDPOINT`` wins when set, so an operator can always override. When it
    is not set and a token is supplied, the URL is read from the token's own
    ``csp_metadata`` — which is where it comes from on SaaS anyway, so callers
    using user/password auth need not know their tenant ID at all.

    Every caller was otherwise chaining ``get_console_url()`` and
    ``get_console_urls_from_token()`` by hand, and getting that chain wrong
    fails at the first data call rather than at sign-in.

    Args:
        token: A bearer token, used only if CSP_ENDPOINT is unset
        verbose: Print which source the URL came from

    Returns:
        The normalised console URL, or None if neither source has one.
    """
    url = get_console_url()
    if url:
        if verbose:
            print(f"Console URL from CSP_ENDPOINT: {url}")
        return url

    if token:
        from .auth import get_console_urls_from_token
        try:
            url = (get_console_urls_from_token(token) or {}).get('console')
        except Exception:            # a malformed or on-prem token has no metadata
            url = None
        if url:
            if verbose:
                print(f"Console URL detected from token: {url}")
            return url

    return None


def validate_console_url(server, token, verbose=False):
    """
    Check that a console URL actually serves the Aqua console API.

    Authentication happens against the regional API endpoint, so a wrong
    console URL still lets sign-in succeed and only breaks later on every data
    call. The most common mistake is using the tenant *gateway* URL (the
    ``-gw`` host), which answers gRPC rather than the REST API.

    Args:
        server: Normalised console URL
        token: A valid bearer token
        verbose: Print the probe URL

    Returns:
        (ok, message) -- ok is True when the URL serves the REST API.
    """
    api_url = f"{server}/api/v2/repositories"
    if verbose:
        print(f"Validating console URL: GET {api_url}")

    try:
        res = requests.get(api_url, headers={'Authorization': f'Bearer {token}'},
                           params={'page': 1, 'pagesize': 1}, verify=False, timeout=20)
    except requests.exceptions.RequestException as e:
        return False, f"Could not reach {server} ({type(e).__name__}). Check the console URL."

    content_type = res.headers.get('content-type', '')

    # The tenant gateway speaks gRPC and rejects REST with 415.
    if 'grpc' in content_type.lower() or res.status_code == 415:
        hint = ""
        if '-gw.' in server:
            hint = f" Try removing '-gw' -> {server.replace('-gw.', '.', 1)}"
        return False, (f"{server} looks like the tenant gateway (gRPC), not the console "
                       f"API.{hint}")

    if res.status_code == 200 and 'json' in content_type.lower():
        return True, "Console URL verified."

    if res.status_code in (401, 403):
        # Reachable and speaking the right protocol; the token just lacks rights.
        return True, f"Console URL reachable (HTTP {res.status_code} - limited permissions)."

    return False, (f"{server} did not return the expected API response "
                   f"(HTTP {res.status_code}, content-type '{content_type or 'unknown'}').")


def _request_with_retry(method, url, token, headers=None, verbose=False, **kwargs):
    """
    Make HTTP request with automatic re-authentication on 401.

    All API functions should use this instead of calling requests directly.
    On a 401 the token is refreshed through the registered token provider, or
    through ``authenticate()`` when ``AQUA_*`` credentials are present, and the
    request is retried once. If neither is available the 401 response is
    returned as-is for the caller to handle; the library never exits.

    Args:
        method: HTTP method ('GET', 'POST', 'DELETE', etc.)
        url: Full API URL
        token: Authentication token
        headers: Optional additional headers (Authorization is added automatically)
        verbose: Print debug info on re-auth
        **kwargs: Passed to requests (params, json, data, etc.)

    Returns:
        Response object from the API call
    """
    # A refresh obtained earlier for this exact token supersedes it.
    entry = _refreshed.get(token)
    effective_token = entry[0] if entry else token

    # Build headers
    if headers is None:
        headers = {}
    headers['Authorization'] = f'Bearer {effective_token}'

    # Library-wide defaults (TLS verification, timeout); explicit kwargs win.
    for key, value in _request_defaults.items():
        kwargs.setdefault(key, value)

    # Make the request
    res = requests.request(method, url, headers=headers, **kwargs)

    # Handle 401 - token expired (or otherwise rejected)
    if res.status_code == 401:
        if entry and time.time() - entry[1] < REFRESH_BACKOFF_SECONDS:
            if verbose:
                print("Token was refreshed %ds ago and is still rejected (401); not "
                      "signing in again. Check the host, the role and the token scope."
                      % (time.time() - entry[1]))
            return res

        with _refresh_lock:
            # Another thread may have refreshed this token while we waited.
            current = _refreshed.get(token)
            if current is not None and current is not entry:
                new_token = current[0]
            else:
                new_token = _refresh_token(verbose=verbose)
                if not new_token:
                    return res
                _refreshed[token] = (new_token, time.time())
                _prune_token_map(_refreshed)

        # Update header and retry
        headers['Authorization'] = f'Bearer {new_token}'
        res = requests.request(method, url, headers=headers, **kwargs)

        if verbose and res.status_code == 200:
            print("Re-authentication successful.")

    return res


def clear_token_cache():
    """Forget every refreshed token. Useful for testing or forcing re-auth."""
    _refreshed.clear()


def write_content_to_file(file, content):
    """Write content to file"""
    with open(file, 'w') as f:
        f.write(content)


def write_json_to_file(file, content):
    """Write JSON content to file, appending if exists"""
    if exists(file):
        with open(file, "a") as file:
            json.dump(content, file)
            file.write('\n')
    else:
        with open(file, "w") as file:
            json.dump(content, file)
            file.write('\n')


def _enforcer_count(value):
    """Normalise an enforcer count that may be a plain int or a {'connected': n} dict."""
    if isinstance(value, dict):
        return value.get('connected', 0)
    return value or 0


def generate_csv_for_license_breakdown(license_breakdown, filename):
    """Generate CSV file for license breakdown data"""
    columns = ['scope', 'images', 'host_image_repos', 'code',
               'agents', 'kube', 'host', 'micro', 'nano', 'pod']

    with open(filename, mode='w', newline='') as file:
        writer = csv.DictWriter(file, fieldnames=columns)
        writer.writeheader()

        for key, value in license_breakdown.items():
            row = {
                'scope': value['scope name'],
                'images': value['repos'],
                'host_image_repos': value.get('host_image_repos', 0),
                'code': value.get('code_repos', 0),
                'agents': _enforcer_count(value.get('agent', 0)),
                'kube': _enforcer_count(value.get('kube_enforcer', 0)),
                'host': _enforcer_count(value.get('host_enforcer', 0)),
                'micro': _enforcer_count(value.get('micro_enforcer', 0)),
                'nano': _enforcer_count(value.get('nano_enforcer', 0)),
                'pod': _enforcer_count(value.get('pod_enforcer', 0))
            }
            writer.writerow(row)