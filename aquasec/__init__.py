"""
Andrea Library - API client library for Aqua Security platform

This library provides a clean API interface for interacting with Aqua Security's
platform, extracted from the andreactl tool.
"""

__version__ = "0.3.2"

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
    get_licences,
    get_repo_count_by_scope,
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
    api_get_repositories
)

from .code_repositories import (
    api_get_code_repositories,
    get_all_code_repositories,
    get_code_repo_count,
    get_code_repo_count_by_scope
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
    list_profiles
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
    'get_licences',
    'get_repo_count_by_scope',
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
    
    # Code Repositories
    'api_get_code_repositories',
    'get_all_code_repositories',
    'get_code_repo_count',
    'get_code_repo_count_by_scope',
    
    # Common utilities
    'write_content_to_file',
    'write_json_to_file',
    'generate_csv_for_license_breakdown',
    
    # Configuration management
    'ConfigManager',
    'load_profile_credentials',
    'test_connection',
    'interactive_setup',
    'list_profiles'
]