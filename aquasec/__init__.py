"""
Andrea Library - API client library for Aqua Security platform

This library provides a clean API interface for interacting with Aqua Security's
platform, extracted from the andreactl tool.
"""

__version__ = "0.11.0"

from .auth import (
    authenticate,
    api_auth,
    user_pass_saas_auth,
    user_pass_onprem_auth,
    extract_token_from_auth,
    decode_token_claims,
    get_console_urls_from_token
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
    get_all_inventory_images,
    get_all_stale_images,
    get_stale_images_count,
    filter_images_by_registry,
    filter_images_by_repository
)

from .vulnerabilities import (
    api_get_vulnerabilities,
    get_vulnerability_count,
    image_ref,
    get_image_vulnerabilities,
    iter_all_vulnerabilities,
    get_all_vulnerabilities,
    finding_key,
    unique_cves,
    summarise_by_image,
    vulnerability_to_row,
    write_vulnerabilities_csv,
    write_image_summary_csv,
    write_unique_cves_csv,
    api_get_available_columns,
    get_available_columns,
    api_trigger_export,
    api_list_exporters,
    get_exporter_names,
    api_get_export_job,
    api_stream_export,
    export_vulnerabilities,
    read_export_archive,
    extract_export_csv,
    EXPORT_ENTITY_TYPES,
    CSV_COLUMNS,
    IMAGE_SUMMARY_COLUMNS,
    UNIQUE_CVE_COLUMNS
)

from .exports import (
    resolve_region,
    get_export_base_url,
    api_list_exports,
    api_get_export,
    api_create_export,
    api_delete_exports,
    api_set_export_active,
    api_get_export_metadata,
    api_get_export_entities,
    api_list_integrations,
    get_exports,
    get_export_capacity,
    get_export_entities,
    get_integrations,
    create_export,
    PREFIX_TO_REGION
)

from .host_images import (
    api_get_host_images,
    get_host_image_count,
    extract_repo_base,
    get_all_host_images,
    get_host_image_repos,
    get_host_image_repo_count_by_scope
)

from .containers import (
    api_get_containers,
    get_container_count,
    get_all_containers,
    get_container_count_by_scope,
    container_key
)

from .common import (
    write_content_to_file,
    write_json_to_file,
    generate_csv_for_license_breakdown,
    normalize_console_url,
    validate_console_url,
    get_console_url,
    resolve_console_url
)

from .config import (
    ConfigManager,
    load_profile_credentials,
    test_connection,
    authenticate_with,
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
    'decode_token_claims',
    'get_console_urls_from_token',
    
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
    'get_all_inventory_images',
    'get_all_stale_images',
    'get_stale_images_count',
    'filter_images_by_registry',
    'filter_images_by_repository',

    # Vulnerabilities (per-image extraction)
    'api_get_vulnerabilities',
    'get_vulnerability_count',
    'image_ref',
    'get_image_vulnerabilities',
    'iter_all_vulnerabilities',
    'get_all_vulnerabilities',
    'finding_key',
    'unique_cves',
    'summarise_by_image',
    'vulnerability_to_row',
    'write_vulnerabilities_csv',
    'write_image_summary_csv',
    'write_unique_cves_csv',
    'api_get_available_columns',
    'get_available_columns',
    'api_trigger_export',
    'api_list_exporters',
    'get_exporter_names',
    'api_get_export_job',
    'api_stream_export',
    'export_vulnerabilities',
    'read_export_archive',
    'extract_export_csv',
    'EXPORT_ENTITY_TYPES',
    'CSV_COLUMNS',
    'IMAGE_SUMMARY_COLUMNS',
    'UNIQUE_CVE_COLUMNS',

    # Scheduled exports (CNAPP export service, push to a destination)
    'resolve_region',
    'get_export_base_url',
    'api_list_exports',
    'api_get_export',
    'api_create_export',
    'api_delete_exports',
    'api_set_export_active',
    'api_get_export_metadata',
    'api_get_export_entities',
    'api_list_integrations',
    'get_exports',
    'get_export_capacity',
    'get_export_entities',
    'get_integrations',
    'create_export',
    'PREFIX_TO_REGION',

    # Host images (images discovered on hosts/VMs by enforcers)
    'api_get_host_images',
    'get_host_image_count',
    'extract_repo_base',
    'get_all_host_images',
    'get_host_image_repos',
    'get_host_image_repo_count_by_scope',

    # Containers (running workload inventory)
    'api_get_containers',
    'get_container_count',
    'get_all_containers',
    'get_container_count_by_scope',
    'container_key',

    # Common utilities
    'write_content_to_file',
    'write_json_to_file',
    'generate_csv_for_license_breakdown',
    'normalize_console_url',
    'validate_console_url',
    'get_console_url',
    'resolve_console_url',
    
    # Configuration management
    'ConfigManager',
    'load_profile_credentials',
    'test_connection',
    'authenticate_with',
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