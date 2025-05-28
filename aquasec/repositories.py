"""
Repository-related API functions for Andrea library
"""

import requests


def api_get_repositories(server, token, page, page_size, registry=None, scope=None, verbose=False):
    """Get repositories from the server"""
    if registry:
        api_url = "{server}/api/v2/repositories?registry={registry}&page={page}&pagesize={page_size}&include_totals=true&order_by=name".format(
            server=server,
            registry=registry,
            page=page,
            page_size=page_size)
    elif scope:
        api_url = "{server}/api/v2/repositories?scope={scope}&page={page}&pagesize={page_size}&include_totals=true&order_by=name".format(
            server=server,
            scope=scope,
            page=page,
            page_size=page_size)
    else:
        api_url = "{server}/api/v2/repositories?page={page}&pagesize={page_size}&include_totals=true&order_by=name".format(
            server=server,
            page=page,
            page_size=page_size)

    headers = {'Authorization': f'Bearer {token}'}
    if verbose:
        print(api_url)
    res = requests.get(url=api_url, headers=headers, verify=False)

    return res