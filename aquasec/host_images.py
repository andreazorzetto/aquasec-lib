"""
Host Images API functions for Aqua Security library

Host images are container images discovered on hosts/VMs by enforcers, exposed at
``/api/v1/hosts/images``. Unlike registered repositories, they are not cleanly
attributed to an application scope by the "General" Images tab. However, the host
images endpoint *does* support application-scope filtering (the enforcer group that
found the image is considered behind the scenes), which lets us attribute host
images to a scope for licensing breakdowns.

For licensing the relevant unit is the *repository* (the image base name without
tag or digest), not each individual image instance, so this module provides helpers
to enumerate host images per scope and collapse them to unique repository names.
"""

from .common import _request_with_retry


def api_get_host_images(server, token, page=1, page_size=200, scope=None,
                        order_by="id", verbose=False):
    """
    Get host images from /api/v1/hosts/images with an optional scope filter.

    Args:
        server: The server URL (the tenant console / ese_url)
        token: Authentication token
        page: Page number (1-based)
        page_size: Number of results per page (default 200)
        scope: Optional application scope name to filter by
        order_by: Field to order by (default "id")
        verbose: Print debug information

    Returns:
        Response object from the API call
    """
    params = {
        'page': page,
        'pagesize': page_size,
        'orderby': order_by,
    }
    # Pass scope via params so spaces/special chars are URL-encoded correctly.
    if scope is not None:
        params['scope'] = scope

    api_url = f"{server}/api/v1/hosts/images"

    if verbose:
        print(f"GET {api_url}")
        print(f"Params: {params}")

    res = _request_with_retry('GET', api_url, token, params=params, verbose=verbose)
    return res


def get_host_image_count(server, token, scope=None, verbose=False):
    """
    Get the total number of host *images* (individual image instances, not repos)
    for an optional scope. Cheap: reads the ``count`` field with pagesize=1.

    Args:
        server: The server URL
        token: Authentication token
        scope: Optional application scope name to filter by
        verbose: Print debug information

    Returns:
        Number of host images (int)
    """
    try:
        res = api_get_host_images(server, token, page=1, page_size=1, scope=scope, verbose=verbose)
        if res.status_code == 200:
            count = res.json().get("count", 0)
            if verbose:
                print(f"Host image count (scope={scope}): {count}")
            return count
        if verbose:
            print(f"Failed to get host image count (scope={scope}): {res.status_code}")
        return 0
    except Exception as e:
        if verbose:
            print(f"Error getting host image count (scope={scope}): {e}")
        return 0


def extract_repo_base(name):
    """
    Strip the tag or digest from a host image name to get the repository base name.

    Host image names come in the form ``repo:tag`` or ``repo@sha256:<digest>``,
    optionally with a registry prefix that may itself contain a port (``host:5000``).
    The registry/port portion is preserved; only the trailing tag or digest is removed.

    Examples:
        'caddy:latest'                              -> 'caddy'
        'caddy@sha256:abc123...'                    -> 'caddy'
        'registry.aquasec.com/enforcer:2022.4'      -> 'registry.aquasec.com/enforcer'
        '192.168.49.2:32736/my-app/alpine:latest'   -> '192.168.49.2:32736/my-app/alpine'

    Args:
        name: The host image name string

    Returns:
        The repository base name (registry + repository, no tag/digest), or the
        original value if it is empty/None.
    """
    if not name:
        return name

    # Strip a digest reference first: repo@sha256:<digest>
    if '@' in name:
        name = name.split('@', 1)[0]

    # Strip the tag (repo:tag) only when the segment after the last ':' has no '/'.
    # This preserves a registry port such as "host:5000/path/image".
    head, sep, tail = name.rpartition(':')
    if sep and '/' not in tail:
        name = head

    return name


def get_all_host_images(server, token, scope=None, page_size=200, verbose=False):
    """
    Get all host images for an optional scope, paginating until complete.

    Args:
        server: The server URL
        token: Authentication token
        scope: Optional application scope name to filter by
        page_size: Number of results per page (default 200)
        verbose: Print debug information

    Returns:
        List of all host image objects
    """
    all_images = []
    page = 1

    while True:
        res = api_get_host_images(server, token, page=page, page_size=page_size,
                                  scope=scope, verbose=verbose)
        if res.status_code != 200:
            raise Exception(f"API call failed with status {res.status_code}: {res.text}")

        data = res.json()
        images = data.get("result", [])
        if not images:
            break

        all_images.extend(images)

        total = data.get("count", 0)
        if len(all_images) >= total or len(images) < page_size:
            break

        page += 1
        if verbose:
            print(f"Fetched {len(all_images)} of {total} host images (scope={scope})...")

    return all_images


def get_host_image_repos(server, token, scope=None, verbose=False):
    """
    Get the set of unique repository base names from host images for a scope.

    Args:
        server: The server URL
        token: Authentication token
        scope: Optional application scope name to filter by
        verbose: Print debug information

    Returns:
        Sorted list of unique repository base names
    """
    images = get_all_host_images(server, token, scope=scope, verbose=verbose)
    repos = {extract_repo_base(img.get("name")) for img in images if img.get("name")}
    if verbose:
        print(f"Scope '{scope}': {len(images)} host images -> {len(repos)} unique repos")
    return sorted(repos)


def get_host_image_repo_count_by_scope(server, token, scopes_list, verbose=False):
    """
    Get the unique host-image *repository* count for each scope.

    For each scope, all host images are enumerated and collapsed to their unique
    repository base names (tag/digest stripped), then counted. This is the unit
    relevant for licensing utilization per application scope.

    Args:
        server: The server URL
        token: Authentication token
        scopes_list: List of application scope names to process
        verbose: Print debug information

    Returns:
        Dict mapping scope name -> unique repository count (int)
    """
    repo_count_by_scope = {}
    for scope in scopes_list:
        try:
            repos = get_host_image_repos(server, token, scope=scope, verbose=verbose)
            repo_count_by_scope[scope] = len(repos)
        except Exception as e:
            if verbose:
                print(f"DEBUG: Failed to get host image repos for scope '{scope}': {e}")
            repo_count_by_scope[scope] = 0

    return repo_count_by_scope
