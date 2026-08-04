"""
Common utility functions for Aqua library
"""

import csv
import json
import requests
from os.path import exists
from urllib.parse import urlparse

# Module-level token cache for re-authentication
_cached_token = None


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
    This ensures automatic token refresh on 401 responses.

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
    global _cached_token

    # Use cached token if available (from a previous re-auth)
    effective_token = _cached_token if _cached_token else token

    # Build headers
    if headers is None:
        headers = {}
    headers['Authorization'] = f'Bearer {effective_token}'

    # Ensure verify=False is set (can be overridden in kwargs)
    kwargs.setdefault('verify', False)

    # Make the request
    res = requests.request(method, url, headers=headers, **kwargs)

    # Handle 401 - token expired
    if res.status_code == 401:
        if verbose:
            print("Token expired. Re-authenticating...")

        from .auth import authenticate
        new_token = authenticate(verbose=verbose)
        _cached_token = new_token

        # Update header and retry
        headers['Authorization'] = f'Bearer {new_token}'
        res = requests.request(method, url, headers=headers, **kwargs)

        if verbose and res.status_code == 200:
            print("Re-authentication successful.")

    return res


def clear_token_cache():
    """Clear the cached token. Useful for testing or forcing re-auth."""
    global _cached_token
    _cached_token = None


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