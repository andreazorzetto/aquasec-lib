"""
Andrea Library - API client library for Aqua Security platform

This library provides a clean API interface for interacting with Aqua Security's
platform, extracted from the andreactl tool.
"""

__version__ = "0.7.0"

from .auth import (
    authenticate,
    api_auth,
    user_pass_saas_auth,
    user_pass_onprem_auth,
    extract_token_from_auth
)

from .licenses import (
    api_get_licenses,
    api_get_dta_license,
    api_post_dta_license_utilization,
    get_all_licenses,
    get_licences,
    get_enforcer_count_by_scope
)

from .scopes import (
    api_get_scopes,
    get_app_scopes
)

from .enforcers import (
    api_get_enforcer_groups,
    get_enforcers_from_group,
    get_enforcer_groups,
    get_enforcer_count
)

from .repositories import (
    api_get_repositories,
    api_delete_repo,
    get_all_repositories,
    get_repo_count,
    get_repo_count_by_scope
)

from .code_repositories import (
    api_get_code_repositories,
    get_all_code_repositories,
    get_code_repo_count,
    get_code_repo_count_by_scope
)

from .functions import (
    api_get_functions,
    get_function_count
)

from .vms import (
    api_get_vms,
    api_get_vms_count,
    get_all_vms,
    get_vm_count,
    filter_vms_by_coverage,
    filter_vms_by_cloud_provider,
    filter_vms_by_region,
    filter_vms_by_risk_level
)

from .inventory import (
    api_get_inventory_images,
    api_get_inventory_images_count,
    api_delete_images,
    get_all_stale_images,
    get_stale_images_count,
    filter_images_by_registry,
    filter_images_by_repository
)

from .common import (
    write_content_to_file,
    write_json_to_file,
    generate_csv_for_license_breakdown
)

from .config import (
    ConfigManager,
    load_profile_credentials,
    test_connection,
    interactive_setup,
    list_profiles,
    get_profile_info,
    get_all_profiles_info,
    format_profile_info,
    delete_profile_with_result,
    set_default_profile_with_result,
    profile_not_found_response,
    profile_operation_response
)

__all__ = [
    # Auth
    'authenticate',
    'api_auth',
    'user_pass_saas_auth',
    'user_pass_onprem_auth',
    'extract_token_from_auth',
    
    # Licenses
    'api_get_licenses',
    'api_get_dta_license',
    'api_post_dta_license_utilization',
    'get_all_licenses',
    'get_licences',
    'get_enforcer_count_by_scope',
    
    # Scopes
    'api_get_scopes',
    'get_app_scopes',
    
    # Enforcers
    'api_get_enforcer_groups',
    'get_enforcers_from_group',
    'get_enforcer_groups',
    'get_enforcer_count',
    
    # Repositories
    'api_get_repositories',
    'api_delete_repo',
    'get_all_repositories',
    'get_repo_count',
    'get_repo_count_by_scope',
    
    # Code Repositories
    'api_get_code_repositories',
    'get_all_code_repositories',
    'get_code_repo_count',
    'get_code_repo_count_by_scope',
    
    # Functions
    'api_get_functions',
    'get_function_count',
    
    # VMs
    'api_get_vms',
    'api_get_vms_count',
    'get_all_vms',
    'get_vm_count',
    'filter_vms_by_coverage',
    'filter_vms_by_cloud_provider',
    'filter_vms_by_region',
    'filter_vms_by_risk_level',

    # Inventory (Hub images)
    'api_get_inventory_images',
    'api_get_inventory_images_count',
    'api_delete_images',
    'get_all_stale_images',
    'get_stale_images_count',
    'filter_images_by_registry',
    'filter_images_by_repository',

    # Common utilities
    'write_content_to_file',
    'write_json_to_file',
    'generate_csv_for_license_breakdown',
    
    # Configuration management
    'ConfigManager',
    'load_profile_credentials',
    'test_connection',
    'interactive_setup',
    'list_profiles',
    'get_profile_info',
    'get_all_profiles_info',
    'format_profile_info',
    'delete_profile_with_result',
    'set_default_profile_with_result',
    'profile_not_found_response',
    'profile_operation_response'
]