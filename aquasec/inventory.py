"""
Hub inventory API functions for Aqua Security library

This module provides functions for querying and managing the Hub inventory
at /api/v2/hub/inventory/assets/images/list endpoint.
"""

import requests


def api_get_inventory_images(server, token, page=1, page_size=200, scope=None,
                              first_found_date=None, has_workloads=None,
                              registry_name=None, verbose=False):
    """
    Get images from Hub inventory with optional filters.

    Args:
        server: The server URL
        token: Authentication token
        page: Page number (1-based)
        page_size: Number of results per page (default 200)
        scope: Optional scope filter
        first_found_date: Date filter string (e.g., "over|90|days")
        has_workloads: Filter by workload status (True/False/None)
        registry_name: Optional registry name filter (server-side)
        verbose: Print debug information

    Returns:
        Response object from the API call
    """
    params = {
        'page': page,
        'pagesize': page_size
    }

    if scope is not None:
        params['scope'] = scope
    if first_found_date:
        params['first_found_date'] = first_found_date
    if has_workloads is not None:
        params['has_workloads'] = str(has_workloads).lower()
    if registry_name:
        params['registry_name'] = registry_name

    api_url = f"{server}/api/v2/hub/inventory/assets/images/list"
    headers = {'Authorization': f'Bearer {token}'}

    if verbose:
        print(f"GET {api_url}")
        print(f"Params: {params}")

    res = requests.get(url=api_url, headers=headers, params=params, verify=False)
    return res


def api_get_inventory_images_count(server, token, scope=None, first_found_date=None,
                                    has_workloads=None, verbose=False):
    """
    Get count of images from Hub inventory with optional filters.

    Args:
        server: The server URL
        token: Authentication token
        scope: Optional scope filter
        first_found_date: Date filter string (e.g., "last|90|days")
        has_workloads: Filter by workload status (True/False/None)
        verbose: Print debug information

    Returns:
        Response object from the API call
    """
    params = {}

    if scope is not None:
        params['scope'] = scope
    if first_found_date:
        params['first_found_date'] = first_found_date
    if has_workloads is not None:
        params['has_workloads'] = str(has_workloads).lower()

    api_url = f"{server}/api/v2/hub/inventory/assets/images/list/count"
    headers = {'Authorization': f'Bearer {token}'}

    if verbose:
        print(f"GET {api_url}")
        print(f"Params: {params}")

    res = requests.get(url=api_url, headers=headers, params=params, verify=False)
    return res


def api_delete_images(server, token, uids, verbose=False):
    """
    Delete images by their UIDs.

    Args:
        server: The server URL
        token: Authentication token
        uids: List of image UIDs to delete
        verbose: Print debug information

    Returns:
        Response object from the API call
    """
    api_url = f"{server}/api/v2/images/actions/delete"
    headers = {
        'Authorization': f'Bearer {token}',
        'Content-Type': 'application/json'
    }
    payload = {'uids': uids}

    if verbose:
        print(f"POST {api_url}")
        print(f"Deleting {len(uids)} images")

    res = requests.post(url=api_url, headers=headers, json=payload, verify=False)
    return res


def get_stale_images_count(server, token, days=90, scope=None, registry_name=None, verbose=False):
    """
    Get count of stale images (registered more than X days ago without workloads).

    Args:
        server: The server URL
        token: Authentication token
        days: Number of days threshold (default 90)
        scope: Optional scope filter
        registry_name: Optional registry name filter
        verbose: Print debug information

    Returns:
        Number of matching images
    """
    first_found_date = f"over|{days}|days"

    try:
        response = api_get_inventory_images_count(
            server, token,
            scope=scope,
            first_found_date=first_found_date,
            has_workloads=False,
            verbose=verbose
        )

        if response.status_code == 200:
            data = response.json()
            count = data.get('count', 0)
            if verbose:
                print(f"Stale images count: {count}")
            return count
        else:
            if verbose:
                print(f"Failed to get count: {response.status_code}")
            return 0
    except Exception as e:
        if verbose:
            print(f"Error getting stale images count: {e}")
        return 0


def get_all_stale_images(server, token, days=90, scope=None, registry_name=None, verbose=False):
    """
    Get all stale images (registered more than X days ago without workloads).

    Loops through all pages until empty page returned.

    Args:
        server: The server URL
        token: Authentication token
        days: Number of days threshold (default 90)
        scope: Optional scope filter
        registry_name: Optional registry name filter
        verbose: Print debug information

    Returns:
        List of all matching images
    """
    all_images = []
    page = 1
    page_size = 200
    first_found_date = f"over|{days}|days"

    while True:
        res = api_get_inventory_images(
            server, token,
            page=page,
            page_size=page_size,
            scope=scope,
            first_found_date=first_found_date,
            has_workloads=False,
            registry_name=registry_name,
            verbose=verbose
        )

        if res.status_code != 200:
            raise Exception(f"API call failed with status {res.status_code}: {res.text}")

        data = res.json()
        images = data.get("result", [])

        if not images:
            break

        all_images.extend(images)
        page += 1

        if verbose:
            print(f"Fetched {len(all_images)} images so far...")

    return all_images


def filter_images_by_registry(images, registry):
    """
    Filter images by registry name.

    Args:
        images: List of image objects
        registry: Registry name to filter by

    Returns:
        Filtered list of images
    """
    return [img for img in images if img.get('registry') == registry]


def filter_images_by_repository(images, repository):
    """
    Filter images by repository name.

    Args:
        images: List of image objects
        repository: Repository name to filter by (supports partial match)

    Returns:
        Filtered list of images
    """
    return [img for img in images if repository in img.get('repository', '')]
