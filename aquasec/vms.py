"""
VM inventory related API functions for Andrea library
"""

import requests
import urllib3

# Disable SSL warnings for unverified HTTPS requests
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def api_get_vms(server, token, page, page_size, scope=None, verbose=False):
    """Get VMs from the server using the hub inventory API"""
    if scope:
        api_url = "{server}/api/v2/hub/inventory/assets/vms/list?scope={scope}&page={page}&pagesize={page_size}&use_estimated_count=false&skip_count=true".format(
            server=server,
            scope=scope,
            page=page,
            page_size=page_size)
    else:
        api_url = "{server}/api/v2/hub/inventory/assets/vms/list?page={page}&pagesize={page_size}&use_estimated_count=false&skip_count=true".format(
            server=server,
            page=page,
            page_size=page_size)

    headers = {'Authorization': f'Bearer {token}'}
    if verbose:
        print(api_url)
    res = requests.get(url=api_url, headers=headers, verify=False)

    return res


def api_get_vms_count(server, token, scope=None, use_estimated=False, skip_count=True, verbose=False):
    """Get VM count from the server"""
    if scope:
        api_url = "{server}/api/v2/hub/inventory/assets/vms/list/count?scope={scope}&page=1&pagesize=1&use_estimated_count={use_estimated}&skip_count={skip_count}".format(
            server=server,
            scope=scope,
            use_estimated=str(use_estimated).lower(),
            skip_count=str(skip_count).lower())
    else:
        api_url = "{server}/api/v2/hub/inventory/assets/vms/list/count?page=1&pagesize=1&use_estimated_count={use_estimated}&skip_count={skip_count}".format(
            server=server,
            use_estimated=str(use_estimated).lower(),
            skip_count=str(skip_count).lower())

    headers = {'Authorization': f'Bearer {token}'}
    if verbose:
        print(api_url)
    res = requests.get(url=api_url, headers=headers, verify=False)

    return res


def get_all_vms(server, token, scope=None, verbose=False):
    """
    Get all VMs with pagination support
    
    Args:
        server: The server URL
        token: Authentication token
        scope: Optional scope filter
        verbose: Print debug information
        
    Returns:
        List of all VMs
    """
    all_vms = []
    page = 1
    page_size = 100  # Larger page size for efficiency (like repositories)
    
    while True:
        res = api_get_vms(server, token, page, page_size, scope, verbose)
        
        if res.status_code != 200:
            raise Exception(f"API call failed with status {res.status_code}: {res.text}")
        
        data = res.json()
        vms = data.get("result", [])
        
        if not vms:
            break
            
        all_vms.extend(vms)
        
        # Check if there are more pages 
        # VM API doesn't provide reliable total count, so use simple pagination logic
        # Continue pagination if we got a full page (indicates more data likely available)
        if len(vms) < page_size:
            break
            
        page += 1
        
        if verbose:
            print(f"Fetched {len(all_vms)} VMs so far...")
    
    return all_vms


def get_vm_count(server, token, scope=None, verbose=False):
    """
    Get count of VMs
    
    Args:
        server: The server URL
        token: Authentication token
        scope: Optional scope filter
        verbose: Print debug information
        
    Returns:
        Number of VMs
    """
    try:
        # Use the dedicated count API endpoint
        response = api_get_vms_count(server, token, scope=scope, verbose=verbose)
        
        if response.status_code == 200:
            response_json = response.json()
            count = response_json.get("count", 0)
            if verbose:
                print(f"Total VM count: {count}")
            return count
        else:
            if verbose:
                print(f"Failed to get VM count: {response.status_code}")
            return 0
    except Exception as e:
        if verbose:
            print(f"Error getting VM count: {e}")
        return 0


def filter_vms_by_coverage(vms, included_types=None, excluded_types=None):
    """
    Filter VMs by coverage types
    
    Args:
        vms: List of VMs
        included_types: List of coverage types that must be present
        excluded_types: List of coverage types that must NOT be present
        
    Returns:
        Filtered list of VMs
    """
    if included_types is None:
        included_types = []
    if excluded_types is None:
        excluded_types = []
    
    filtered_vms = []
    
    for vm in vms:
        covered_by = vm.get("covered_by", [])
        
        # Check if any excluded types are present
        if excluded_types and any(exc_type in covered_by for exc_type in excluded_types):
            continue
            
        # Check if all included types are present
        if included_types and not all(inc_type in covered_by for inc_type in included_types):
            continue
            
        filtered_vms.append(vm)
    
    return filtered_vms


def filter_vms_by_cloud_provider(vms, providers=None):
    """
    Filter VMs by cloud provider
    
    Args:
        vms: List of VMs
        providers: List of cloud providers to include (e.g., ['AWS', 'Azure', 'GCP'])
        
    Returns:
        Filtered list of VMs
    """
    if providers is None:
        return vms
    
    # Convert to lowercase for case-insensitive comparison
    providers_lower = [p.lower() for p in providers]
    
    filtered_vms = []
    for vm in vms:
        cloud_provider = vm.get("cloud_provider", "").lower()
        if cloud_provider in providers_lower:
            filtered_vms.append(vm)
    
    return filtered_vms


def filter_vms_by_region(vms, regions=None):
    """
    Filter VMs by region
    
    Args:
        vms: List of VMs
        regions: List of regions to include
        
    Returns:
        Filtered list of VMs
    """
    if regions is None:
        return vms
    
    filtered_vms = []
    for vm in vms:
        vm_region = vm.get("region", "")
        if vm_region in regions:
            filtered_vms.append(vm)
    
    return filtered_vms


def filter_vms_by_risk_level(vms, risk_levels=None):
    """
    Filter VMs by risk level
    
    Args:
        vms: List of VMs
        risk_levels: List of risk levels to include (e.g., ['critical', 'high', 'medium', 'low'])
        
    Returns:
        Filtered list of VMs
    """
    if risk_levels is None:
        return vms
    
    # Convert to lowercase for case-insensitive comparison
    risk_levels_lower = [r.lower() for r in risk_levels]
    
    filtered_vms = []
    for vm in vms:
        highest_risk = vm.get("highest_risk", "").lower()
        if highest_risk in risk_levels_lower:
            filtered_vms.append(vm)
    
    return filtered_vms