"""
Application Scopes related API functions for Aqua library
"""

from .common import _request_with_retry


def api_get_scopes(server, token, page=1, pagesize=100, verbose=False):
    """
    Get application scopes from the server (raw call).

    Returns the response object unmodified so callers can decide how to handle
    non-200 responses (consistent with the other ``api_*`` functions).
    """
    api_url = server + "/api/v2/access_management/scopes?page=" + str(page) + "&pagesize=" + str(
        pagesize) + "&order_by=name"

    if verbose:
        print(api_url)
    res = _request_with_retry('GET', api_url, token, verbose=verbose)
    return res


def get_app_scopes(server, token, verbose=False):
    """
    Get all application scopes, paginating until exhausted.

    Raises:
        Exception: If the scopes API returns a non-200 status (e.g. HTTP 403 when
            the API key/role lacks Access Management read permission). Callers that
            want to tolerate this should wrap the call in try/except.
    """
    app_scopes = []
    page = 1

    if verbose:
        print("Getting all application scopes")

    while True:
        res = api_get_scopes(server, token, page, 25, verbose)

        if res.status_code != 200:
            # Surface a real error instead of printing to stdout and exiting;
            # the caller (or the CLI's top-level handler) decides what to do.
            raise Exception(
                f"Failed to list application scopes: HTTP {res.status_code} - {res.text}"
            )

        result = res.json().get("result")
        if not result:
            break

        app_scopes += result
        if verbose:
            print(f"Retrieved {len(result)} scopes from page {page}")
        page += 1

    if verbose:
        print(f"Total application scopes retrieved: {len(app_scopes)}")

    return app_scopes
