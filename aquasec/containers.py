"""
Running-containers API functions for Aqua Security library

Containers are the live workload inventory reported by enforcers, exposed at
``/api/v2/containers`` (Workload Protection). Like repositories, the endpoint
accepts an application-scope filter, so the same "what is only in Global" delta
analysis applies: a container is *unscoped* when it is visible in the Global
scope but does not fall into any custom application scope.

The relevant identity for a running container is the individual instance
(``id`` / ``container_uid`` are unique per container), but for coverage reporting
it is often more useful to group by cluster/namespace or by image, so this module
returns the raw container objects and leaves grouping to the caller.
"""

from .common import _request_with_retry


def api_get_containers(server, token, page=1, page_size=100, scope=None,
                       cluster=None, namespace=None, status=None,
                       order_by="name", verbose=False):
    """
    Get running containers from ``/api/v2/containers`` with optional filters.

    Args:
        server: The server URL (the tenant console / CSP endpoint)
        token: Authentication token
        page: Page number (1-based)
        page_size: Number of results per page (default 100)
        scope: Optional application scope name to filter by
        cluster: Optional cluster name filter
        namespace: Optional namespace filter
        status: Optional container status filter (e.g. "running")
        order_by: Field to order by (default "name")
        verbose: Print debug information

    Returns:
        Response object from the API call
    """
    params = {
        'page': page,
        'pagesize': page_size,
        'order_by': order_by,
    }
    # Pass filters via params so spaces/special chars are URL-encoded correctly.
    if scope is not None:
        params['scope'] = scope
    if cluster is not None:
        params['cluster'] = cluster
    if namespace is not None:
        params['namespace'] = namespace
    if status is not None:
        params['status'] = status

    api_url = f"{server}/api/v2/containers"

    if verbose:
        print(f"GET {api_url}")
        print(f"Params: {params}")

    res = _request_with_retry('GET', api_url, token, params=params, verbose=verbose)
    return res


def get_container_count(server, token, scope=None, verbose=False):
    """
    Get the total number of running containers for an optional scope.

    Cheap: reads the ``count`` field with pagesize=1.

    Args:
        server: The server URL
        token: Authentication token
        scope: Optional application scope name to filter by
        verbose: Print debug information

    Returns:
        Number of containers (int)
    """
    try:
        res = api_get_containers(server, token, page=1, page_size=1, scope=scope, verbose=verbose)
        if res.status_code == 200:
            count = res.json().get("count", 0)
            if verbose:
                print(f"Container count (scope={scope}): {count}")
            return count
        if verbose:
            print(f"Failed to get container count (scope={scope}): {res.status_code}")
        return 0
    except Exception as e:
        if verbose:
            print(f"Error getting container count (scope={scope}): {e}")
        return 0


def get_all_containers(server, token, scope=None, cluster=None, namespace=None,
                       status=None, page_size=100, verbose=False):
    """
    Get all running containers for the given filters, paginating until complete.

    Args:
        server: The server URL
        token: Authentication token
        scope: Optional application scope name to filter by
        cluster: Optional cluster name filter
        namespace: Optional namespace filter
        status: Optional container status filter
        page_size: Number of results per page (default 100)
        verbose: Print debug information

    Returns:
        List of all container objects

    Raises:
        Exception: If any page returns a non-200 status code
    """
    all_containers = []
    page = 1

    while True:
        res = api_get_containers(server, token, page=page, page_size=page_size,
                                 scope=scope, cluster=cluster, namespace=namespace,
                                 status=status, verbose=verbose)
        if res.status_code != 200:
            raise Exception(f"API call failed with status {res.status_code}: {res.text}")

        data = res.json()
        containers = data.get("result", [])
        if not containers:
            break

        all_containers.extend(containers)

        total = data.get("count", 0)
        if len(all_containers) >= total or len(containers) < page_size:
            break

        page += 1
        if verbose:
            print(f"Fetched {len(all_containers)} of {total} containers (scope={scope})...")

    return all_containers


def get_container_count_by_scope(server, token, scopes_list, verbose=False):
    """
    Get the running-container count for each scope.

    Args:
        server: The server URL
        token: Authentication token
        scopes_list: List of application scope names to process
        verbose: Print debug information

    Returns:
        Dict mapping scope name -> container count (int)
    """
    counts_by_scope = {}
    for scope in scopes_list:
        counts_by_scope[scope] = get_container_count(server, token, scope=scope, verbose=verbose)
    return counts_by_scope


def container_key(container):
    """
    Return a stable unique identifier for a container instance.

    Prefers ``container_uid`` (stable across reports), falling back to ``id``.
    Used to compute set differences between the Global view and scoped views.

    Args:
        container: A container object (dict)

    Returns:
        The container's unique key (str), or None if neither field is present
    """
    return container.get("container_uid") or container.get("id")
