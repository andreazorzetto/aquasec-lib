"""
Application Scopes related API functions for Aqua library
"""

import sys

from .common import _request_with_retry


def api_get_scopes(server, token, page=1, pagesize=100, verbose=False):
    """Get application scopes from the server"""
    api_url = server + "/api/v2/access_management/scopes?page=" + str(page) + "&pagesize=" + str(
        pagesize) + "&order_by=name"

    if verbose:
        print(api_url)
    res = _request_with_retry('GET', api_url, token, verbose=verbose)

    if res.status_code != 200:
        print(res.json())
        sys.exit(1)

    return res


def get_app_scopes(server, token, verbose=False):
    """Get all application scopes"""
    app_scopes = []
    page = 1

    if verbose:
        print("Getting all application scopes")

    while True:
        res = api_get_scopes(server, token, page, 25, verbose)

        if res.status_code == 200 and res.json()["result"]:
            app_scopes += res.json()["result"]
            page += 1
            if verbose:
                print(f"Retrieved {len(res.json()['result'])} scopes from page {page-1}")
        else:
            break

    if verbose:
        print(f"Total application scopes retrieved: {len(app_scopes)}")

    return app_scopes