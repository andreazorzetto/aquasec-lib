#!/usr/bin/env python3
"""
Aqua VM Extraction Utility
A focused tool for extracting VM inventory and identifying candidates for VM enforcer onboarding

Usage:
    python aqua_vm_extract.py setup                       # Interactive setup
    
    # VM List Commands
    python aqua_vm_extract.py vm list                     # List all VMs (JSON)
    python aqua_vm_extract.py vm list -v                  # List all VMs (table format)
    python aqua_vm_extract.py vm list --csv               # Export VMs to CSV format
    python aqua_vm_extract.py vm list --no-enforcer       # VMs without enforcer coverage
    python aqua_vm_extract.py vm list --scope production  # VMs in specific scope
    python aqua_vm_extract.py vm list --breakdown         # VM breakdown by application scope
    python aqua_vm_extract.py vm list --breakdown --csv   # VM breakdown exported to CSV
    
    # VM Count Commands  
    python aqua_vm_extract.py vm count                    # VM statistics (JSON)
    python aqua_vm_extract.py vm count -v                 # VM statistics (table format)
    python aqua_vm_extract.py vm count --scope production # VM statistics for specific scope
    python aqua_vm_extract.py vm count --breakdown        # VM count breakdown by application scope
    
    # Note: --breakdown and --scope are mutually exclusive
"""

import argparse
import json
import sys
import os
import csv
import io
from prettytable import PrettyTable
import urllib3

# Disable SSL warnings for unverified HTTPS requests
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Import from aquasec library
from aquasec import (
    authenticate,
    get_all_vms,
    get_vm_count,
    get_app_scopes,
    filter_vms_by_coverage,
    filter_vms_by_cloud_provider,
    filter_vms_by_region,
    filter_vms_by_risk_level,
    load_profile_credentials,
    interactive_setup,
    list_profiles,
    ConfigManager,
    get_profile_info,
    get_all_profiles_info,
    format_profile_info,
    delete_profile_with_result,
    set_default_profile_with_result,
    profile_not_found_response,
    profile_operation_response
)

# Version
__version__ = "0.1.0"


def vm_list(server, token, verbose=False, debug=False, no_enforcer=False, 
           cloud=None, region=None, risk_level=None, scope=None, csv_output=False, breakdown=False):
    """List VMs with various filtering options"""
    
    try:
        # If breakdown requested, use the breakdown function instead
        if breakdown:
            vm_breakdown(server, token, verbose=verbose, debug=debug, csv_output=csv_output)
            return
            
        # Use streaming approach for CSV and verbose table outputs to minimize memory usage
        if csv_output:
            if verbose:
                print("Streaming VM data as CSV...", file=sys.stderr)
            
            stream_vms_csv(server, token, verbose=verbose, debug=debug,
                          no_enforcer=no_enforcer, cloud=cloud, region=region, 
                          risk_level=risk_level, scope=scope)
            return
        
        elif verbose:
            # Use streaming table output for verbose mode
            stream_vms_table(server, token, verbose=verbose, debug=debug,
                           no_enforcer=no_enforcer, cloud=cloud, region=region, 
                           risk_level=risk_level, scope=scope)
            return
        
        # For JSON output only, use the original approach (need full dataset for counts)
        if debug:
            print("Fetching VM inventory for JSON output...")
        
        # Get all VMs
        all_vms = get_all_vms(server, token, scope=scope, verbose=debug)
        
        # Apply filters
        filtered_vms = all_vms
        
        # Filter by enforcer coverage if requested
        if no_enforcer:
            # VMs without VM enforcer are those that DON'T have vm_enforcer, host_enforcer, aqua_enforcer, or agent
            excluded_types = ['vm_enforcer', 'host_enforcer', 'aqua_enforcer', 'agent']
            filtered_vms = filter_vms_by_coverage(filtered_vms, excluded_types=excluded_types)
        
        # Filter by cloud provider
        if cloud:
            filtered_vms = filter_vms_by_cloud_provider(filtered_vms, [cloud])
        
        # Filter by region
        if region:
            filtered_vms = filter_vms_by_region(filtered_vms, [region])
        
        # Filter by risk level
        if risk_level:
            filtered_vms = filter_vms_by_risk_level(filtered_vms, [risk_level])
        
        # JSON output by default
        result = {
            "count": len(filtered_vms),
            "vms": filtered_vms
        }
        print(json.dumps(result, indent=2))
    
    except Exception as e:
        if verbose:
            print(f"Error listing VMs: {e}")
        else:
            print(json.dumps({"error": f"Failed to list VMs: {str(e)}"}))
        sys.exit(1)


def vm_count(server, token, verbose=False, debug=False, scope=None, breakdown=False):
    """Show VM count statistics"""
    
    try:
        # If breakdown requested, use the count breakdown function instead
        if breakdown:
            vm_count_breakdown(server, token, verbose=verbose, debug=debug, csv_output=False)
            return
            
        if verbose:
            print("Fetching VM statistics...")
        
        # Get total count efficiently first
        total_count = get_vm_count(server, token, scope=scope, verbose=debug)
        
        if verbose:
            print(f"Total VMs: {total_count}")
            print("Fetching detailed VM data for breakdown analysis...")
        
        # Get all VMs for detailed statistics
        all_vms = get_all_vms(server, token, scope=scope, verbose=debug)
        
        # Count by enforcer coverage
        excluded_types = ['vm_enforcer', 'host_enforcer', 'aqua_enforcer', 'agent']
        vms_without_enforcer = filter_vms_by_coverage(all_vms, excluded_types=excluded_types)
        no_enforcer_count = len(vms_without_enforcer)
        
        # Count by cloud provider
        cloud_stats = {}
        for vm in all_vms:
            cloud = vm.get("cloud_provider", "Unknown")
            cloud_stats[cloud] = cloud_stats.get(cloud, 0) + 1
        
        # Count by risk level
        risk_stats = {}
        for vm in all_vms:
            risk = vm.get("highest_risk", "unknown")
            risk_stats[risk] = risk_stats.get(risk, 0) + 1
        
        # Count by coverage type
        coverage_stats = {}
        for vm in all_vms:
            covered_by = vm.get("covered_by", [])
            for coverage in covered_by:
                coverage_stats[coverage] = coverage_stats.get(coverage, 0) + 1
        
        stats = {
            "total_vms": total_count,
            "vms_without_vm_enforcer": no_enforcer_count,
            "vms_with_vm_enforcer": total_count - no_enforcer_count,
            "coverage_breakdown": coverage_stats,
            "cloud_provider_breakdown": cloud_stats,
            "risk_level_breakdown": risk_stats
        }
        
        if verbose:
            # Human-readable table output
            display_vm_stats_table(stats)
        else:
            # JSON output
            print(json.dumps(stats, indent=2))
    
    except Exception as e:
        if verbose:
            print(f"Error getting VM statistics: {e}")
        else:
            print(json.dumps({"error": f"Failed to get VM statistics: {str(e)}"}))
        sys.exit(1)



def display_vms_table(vms):
    """Display VMs in a human-readable table format"""
    if not vms:
        print("No VMs found")
        return
    
    table = PrettyTable()
    table.field_names = ["Name", "Cloud", "Region", "OS", "Risk", "Coverage", "Compliant"]
    table.align["Name"] = "l"
    table.align["Cloud"] = "l"
    table.align["Region"] = "l"
    table.align["OS"] = "l"
    table.align["Risk"] = "c"
    table.align["Coverage"] = "l"
    table.align["Compliant"] = "c"
    
    for vm in vms:  # Show all VMs, no truncation
        coverage = ', '.join(vm.get('covered_by', []))
        if len(coverage) > 30:
            coverage = coverage[:27] + "..."
        
        table.add_row([
            vm.get('name', 'N/A')[:30],
            vm.get('cloud_provider', 'N/A'),
            vm.get('region', 'N/A'),
            vm.get('os', 'N/A')[:20],
            vm.get('highest_risk', 'N/A'),
            coverage,
            "Yes" if vm.get('compliant') else "No"
        ])
    
    print(table)


def display_vm_stats_table(stats):
    """Display VM statistics in table format"""
    print("\n=== VM Statistics ===")
    
    # Overall stats
    table = PrettyTable(["Metric", "Count"])
    table.align["Metric"] = "l"
    table.align["Count"] = "r"
    
    table.add_row(["Total VMs", f"{stats['total_vms']:,}"])
    table.add_row(["VMs without VM Enforcer", f"{stats['vms_without_vm_enforcer']:,}"])
    table.add_row(["VMs with VM Enforcer", f"{stats['vms_with_vm_enforcer']:,}"])
    
    print(table)
    
    # Cloud provider breakdown
    if stats['cloud_provider_breakdown']:
        print("\n=== Cloud Provider Breakdown ===")
        cloud_table = PrettyTable(["Cloud Provider", "Count"])
        cloud_table.align["Cloud Provider"] = "l"
        cloud_table.align["Count"] = "r"
        
        for cloud, count in sorted(stats['cloud_provider_breakdown'].items()):
            cloud_table.add_row([cloud, f"{count:,}"])
        
        print(cloud_table)
    
    # Risk level breakdown
    if stats['risk_level_breakdown']:
        print("\n=== Risk Level Breakdown ===")
        risk_table = PrettyTable(["Risk Level", "Count"])
        risk_table.align["Risk Level"] = "l"
        risk_table.align["Count"] = "r"
        
        # Sort by risk severity
        risk_order = ['critical', 'high', 'medium', 'low', 'unknown']
        sorted_risks = sorted(stats['risk_level_breakdown'].items(), 
                            key=lambda x: risk_order.index(x[0]) if x[0] in risk_order else 999)
        
        for risk, count in sorted_risks:
            risk_table.add_row([risk.title(), f"{count:,}"])
        
        print(risk_table)


def get_vms_paginated(server, token, scope=None, verbose=False, debug=False):
    """
    Generator function that yields VM data page by page to avoid loading
    all VMs into memory at once. Useful for streaming CSV output.
    
    Args:
        server: The server URL
        token: Authentication token
        scope: Optional scope filter
        verbose: Show progress information
        debug: Show debug information
        
    Yields:
        List of VMs from each API page
    """
    page = 1
    page_size = 100  # Same as get_all_vms
    total_fetched = 0
    
    while True:
        # Import the API function from aquasec library
        from aquasec.vms import api_get_vms
        
        res = api_get_vms(server, token, page, page_size, scope=scope, verbose=debug)
        
        if res.status_code != 200:
            raise Exception(f"API call failed with status {res.status_code}: {res.text}")
        
        data = res.json()
        vms = data.get("result", [])
        
        if not vms:
            break
            
        total_fetched += len(vms)
        if verbose:
            print(f"Fetched page {page}: {len(vms)} VMs (total so far: {total_fetched})")
            
        yield vms
        
        # Check if there are more pages
        if len(vms) < page_size:
            break
            
        page += 1


def format_vms_csv(vms):
    """Format VMs as CSV string"""
    if not vms:
        return ""
    
    output = io.StringIO()
    writer = csv.writer(output)
    
    # Write header
    writer.writerow(['Name', 'Cloud Provider', 'Region', 'OS', 'Highest Risk', 'Coverage', 'Compliant', 'ID'])
    
    # Write VM data
    for vm in vms:
        coverage = ', '.join(vm.get('covered_by', []))
        writer.writerow([
            vm.get('name', ''),
            vm.get('cloud_provider', ''),
            vm.get('region', ''),
            vm.get('os', ''),
            vm.get('highest_risk', ''),
            coverage,
            'Yes' if vm.get('compliant') else 'No',
            vm.get('id', '')
        ])
    
    return output.getvalue()


def stream_vms_csv(server, token, verbose=False, debug=False, no_enforcer=False, 
                  cloud=None, region=None, risk_level=None, scope=None):
    """
    Stream VMs as CSV output, processing data page by page to minimize memory usage.
    
    Args:
        server: The server URL
        token: Authentication token
        verbose: Show progress information
        debug: Show debug information
        no_enforcer: Filter VMs without enforcer coverage
        cloud: Filter by cloud provider
        region: Filter by region
        risk_level: Filter by risk level
        scope: Filter by application scope
    """
    # Import filter functions from aquasec library
    from aquasec import (
        filter_vms_by_coverage,
        filter_vms_by_cloud_provider,
        filter_vms_by_region,
        filter_vms_by_risk_level
    )
    
    # Write CSV header first
    writer = csv.writer(sys.stdout)
    writer.writerow(['Name', 'Cloud Provider', 'Region', 'OS', 'Highest Risk', 'Coverage', 'Compliant', 'ID'])
    
    total_output = 0
    
    # Process VMs page by page
    for vm_batch in get_vms_paginated(server, token, scope=scope, verbose=verbose, debug=debug):
        # Apply filters to this batch
        filtered_batch = vm_batch
        
        # Filter by enforcer coverage if requested
        if no_enforcer:
            excluded_types = ['vm_enforcer', 'host_enforcer', 'aqua_enforcer', 'agent']
            filtered_batch = filter_vms_by_coverage(filtered_batch, excluded_types=excluded_types)
        
        # Filter by cloud provider
        if cloud:
            filtered_batch = filter_vms_by_cloud_provider(filtered_batch, [cloud])
        
        # Filter by region
        if region:
            filtered_batch = filter_vms_by_region(filtered_batch, [region])
        
        # Filter by risk level
        if risk_level:
            filtered_batch = filter_vms_by_risk_level(filtered_batch, [risk_level])
        
        # Output filtered VMs from this batch as CSV rows
        for vm in filtered_batch:
            coverage = ', '.join(vm.get('covered_by', []))
            writer.writerow([
                vm.get('name', ''),
                vm.get('cloud_provider', ''),
                vm.get('region', ''),
                vm.get('os', ''),
                vm.get('highest_risk', ''),
                coverage,
                'Yes' if vm.get('compliant') else 'No',
                vm.get('id', '')
            ])
            total_output += 1
    
    if verbose:
        print(f"\n# Total VMs output: {total_output}", file=sys.stderr)


def stream_vms_table(server, token, verbose=False, debug=False, no_enforcer=False, 
                    cloud=None, region=None, risk_level=None, scope=None):
    """
    Stream VMs as human-readable text output, processing data page by page.
    
    Args:
        server: The server URL
        token: Authentication token
        verbose: Show progress information
        debug: Show debug information
        no_enforcer: Filter VMs without enforcer coverage
        cloud: Filter by cloud provider
        region: Filter by region
        risk_level: Filter by risk level
        scope: Filter by application scope
    """
    # Import filter functions from aquasec library
    from aquasec import (
        filter_vms_by_coverage,
        filter_vms_by_cloud_provider,
        filter_vms_by_region,
        filter_vms_by_risk_level
    )
    
    if verbose:
        print("Streaming VM data as table...", file=sys.stderr)
    
    # Print header
    print("=" * 150)
    print(f"{'Name':<50} {'Cloud':<8} {'Region':<18} {'OS':<25} {'Risk':<8} {'Coverage':<25} {'Compliant'}")
    print("=" * 150)
    
    total_output = 0
    
    # Process VMs page by page
    for vm_batch in get_vms_paginated(server, token, scope=scope, verbose=verbose, debug=debug):
        # Apply filters to this batch
        filtered_batch = vm_batch
        
        # Filter by enforcer coverage if requested
        if no_enforcer:
            excluded_types = ['vm_enforcer', 'host_enforcer', 'aqua_enforcer', 'agent']
            filtered_batch = filter_vms_by_coverage(filtered_batch, excluded_types=excluded_types)
        
        # Filter by cloud provider
        if cloud:
            filtered_batch = filter_vms_by_cloud_provider(filtered_batch, [cloud])
        
        # Filter by region
        if region:
            filtered_batch = filter_vms_by_region(filtered_batch, [region])
        
        # Filter by risk level
        if risk_level:
            filtered_batch = filter_vms_by_risk_level(filtered_batch, [risk_level])
        
        # Output filtered VMs from this batch
        for vm in filtered_batch:
            coverage = ', '.join(vm.get('covered_by', []))
            if len(coverage) > 25:
                coverage = coverage[:22] + "..."
            
            name = vm.get('name', 'N/A')
            os_name = vm.get('os', 'N/A')
            
            print(f"{name:<50} {vm.get('cloud_provider', 'N/A'):<8} {vm.get('region', 'N/A'):<18} "
                  f"{os_name:<25} {vm.get('highest_risk', 'N/A'):<8} {coverage:<25} "
                  f"{'Yes' if vm.get('compliant') else 'No'}")
            total_output += 1
    
    print("=" * 150)
    print(f"Total VMs: {total_output}")
    
    if verbose and total_output > 0:
        print(f"# Streamed {total_output} VMs", file=sys.stderr)


def build_vm_scope_map(server, token, verbose=False, debug=False):
    """Build complete map of VMs and their scopes for breakdown analysis"""
    scope_map = {}
    
    if verbose:
        print("Building VM scope map...")
        print("Step 1: Fetching all application scopes...")
    
    # Step 1: Get all application scopes (excluding Global)
    try:
        all_scopes = get_app_scopes(server, token, debug)
        app_scopes = [s for s in all_scopes if s.get("name") != "Global"]
        
        if verbose:
            print(f"Found {len(app_scopes)} application scopes")
            print("Step 2: Fetching VMs for each scope...")
    
    except Exception as e:
        if verbose:
            print(f"Error fetching scopes: {e}")
        raise
    
    # Step 2: For each app scope, get VMs
    for i, scope in enumerate(app_scopes):
        scope_name = scope.get("name")
        
        if verbose:
            print(f"  Fetching VMs for scope {i+1}/{len(app_scopes)}: {scope_name}")
        
        try:
            # Get count from count API
            api_count = get_vm_count(server, token, scope=scope_name, verbose=debug)
            
            # Get actual VMs
            scope_vms = get_all_vms(server, token, scope=scope_name, verbose=debug)
            actual_count = len(scope_vms)
            
            # Cross-validation: check if counts match
            if api_count != actual_count:
                if debug or verbose:
                    print(f"    WARNING: Count mismatch for scope {scope_name}: API reported {api_count}, actual count {actual_count}")
            elif debug:
                print(f"    Count validation passed for {scope_name}: {actual_count} VMs")
            
            scope_map[scope_name] = {
                "count": actual_count,  # Use actual count for accuracy
                "api_count": api_count,  # Store API count for comparison
                "vms": scope_vms,
                "count_validated": api_count == actual_count
            }
            
            if debug:
                print(f"    Found {actual_count} VMs in {scope_name}")
                
        except Exception as e:
            if verbose:
                print(f"  Error fetching VMs for scope {scope_name}: {e}")
            # Continue with other scopes
            scope_map[scope_name] = {
                "count": 0,
                "api_count": 0,
                "vms": [],
                "count_validated": True
            }
    
    if verbose:
        total_vms = sum(data["count"] for data in scope_map.values())
        validation_mismatches = sum(1 for data in scope_map.values() if not data["count_validated"])
        print(f"\nScope mapping complete:")
        print(f"  Total application scopes: {len(scope_map)}")
        print(f"  Total VMs in scopes: {total_vms}")
        if validation_mismatches > 0:
            print(f"  Count validation warnings: {validation_mismatches} scopes had API/actual count mismatches")
        else:
            print(f"  Count validation: All scope counts validated successfully")
    
    return scope_map


def vm_count_breakdown(server, token, verbose=False, debug=False, csv_output=False):
    """Count breakdown of VMs by scope"""
    
    # Build VM scope map (counts only)
    scope_map = build_vm_scope_map(server, token, verbose, debug)
    
    # Calculate statistics
    total_scopes = len(scope_map)
    total_vms = sum(data["count"] for data in scope_map.values())
    
    # Build breakdown data
    validation_mismatches = sum(1 for data in scope_map.values() if not data["count_validated"])
    breakdown = {
        "summary": {
            "total_scopes": total_scopes,
            "total_vms": total_vms,
            "scopes_with_vms": len([s for s in scope_map.values() if s["count"] > 0]),
            "empty_scopes": len([s for s in scope_map.values() if s["count"] == 0]),
            "count_validation_mismatches": validation_mismatches
        },
        "scope_counts": {scope: data["count"] for scope, data in scope_map.items()},
        "validation_details": {scope: {"api_count": data["api_count"], "actual_count": data["count"], "validated": data["count_validated"]} for scope, data in scope_map.items() if not data["count_validated"]}
    }
    
    # Output handling
    if csv_output:
        # CSV output for counts - clean format
        writer = csv.writer(sys.stdout)
        
        # Write header row
        writer.writerow(["Scope", "VM Count", "Percentage"])
        
        # Write scope counts data
        for scope, count in sorted(breakdown["scope_counts"].items()):
            percentage = (count / total_vms * 100) if total_vms > 0 else 0
            writer.writerow([scope, count, f"{percentage:.1f}%"])
            
    elif verbose:
        # Table output
        display_vm_breakdown_table(breakdown, counts_only=True)
    else:
        # JSON output (counts only)
        print(json.dumps(breakdown, indent=2))


def vm_breakdown(server, token, verbose=False, debug=False, csv_output=False):
    """Comprehensive breakdown of VMs by scope"""
    
    # Build VM scope map
    scope_map = build_vm_scope_map(server, token, verbose, debug)
    
    # Calculate statistics
    total_scopes = len(scope_map)
    total_vms = sum(data["count"] for data in scope_map.values())
    
    # Build breakdown data
    validation_mismatches = sum(1 for data in scope_map.values() if not data["count_validated"])
    breakdown = {
        "summary": {
            "total_scopes": total_scopes,
            "total_vms": total_vms,
            "scopes_with_vms": len([s for s in scope_map.values() if s["count"] > 0]),
            "empty_scopes": len([s for s in scope_map.values() if s["count"] == 0]),
            "count_validation_mismatches": validation_mismatches
        },
        "scope_counts": {scope: data["count"] for scope, data in scope_map.items()},
        "scope_details": {},
        "validation_details": {scope: {"api_count": data["api_count"], "actual_count": data["count"], "validated": data["count_validated"]} for scope, data in scope_map.items() if not data["count_validated"]}
    }
    
    # Add detailed scope information  
    for scope_name, scope_data in scope_map.items():
        if scope_data["count"] > 0:
            breakdown["scope_details"][scope_name] = {
                "count": scope_data["count"],
                "percentage": (scope_data["count"] / total_vms * 100) if total_vms > 0 else 0,
                "vms": scope_data["vms"]
            }
    
    # Output handling
    if csv_output:
        # CSV output - single flat format with Scope column
        writer = csv.writer(sys.stdout)
        
        # Write single header row with Scope column added at the end
        writer.writerow(['Name', 'Cloud Provider', 'Region', 'OS', 'Highest Risk', 'Coverage', 'Compliant', 'ID', 'Scope'])
        
        # Write all VMs across all scopes in a flat format
        for scope_name in sorted(scope_map.keys()):
            if scope_map[scope_name]["count"] > 0:
                for vm in scope_map[scope_name]["vms"]:
                    coverage = ', '.join(vm.get('covered_by', []))
                    writer.writerow([
                        vm.get('name', ''),
                        vm.get('cloud_provider', ''),
                        vm.get('region', ''),
                        vm.get('os', ''),
                        vm.get('highest_risk', ''),
                        coverage,
                        'Yes' if vm.get('compliant') else 'No',
                        vm.get('id', ''),
                        scope_name
                    ])
                
    elif verbose:
        # Human-readable table output
        display_vm_breakdown_table(breakdown, scope_map)
    else:
        # JSON output by default
        print(json.dumps(breakdown, indent=2))


def display_vm_breakdown_table(breakdown, scope_map=None, counts_only=False):
    """Display VM breakdown in table format"""
    title = "VM Count Breakdown" if counts_only else "VM Scope Breakdown"
    print(f"\n=== {title} ===")
    
    # Summary statistics
    summary_table = PrettyTable()
    summary_table.field_names = ["Metric", "Count"]
    summary_table.align["Metric"] = "l"
    summary_table.align["Count"] = "r"
    
    summary_table.add_row(["Total Application Scopes", breakdown["summary"]["total_scopes"]])
    summary_table.add_row(["Total VMs in Scopes", breakdown["summary"]["total_vms"]])
    summary_table.add_row(["Scopes with VMs", breakdown["summary"]["scopes_with_vms"]])
    summary_table.add_row(["Empty Scopes", breakdown["summary"]["empty_scopes"]])
    
    # Add validation info if available
    if "count_validation_mismatches" in breakdown["summary"]:
        validation_mismatches = breakdown["summary"]["count_validation_mismatches"]
        if validation_mismatches > 0:
            summary_table.add_row(["Count Validation Warnings", validation_mismatches])
        else:
            summary_table.add_row(["Count Validation", "All Passed"])
    
    print(summary_table)
    
    # VMs per scope
    if breakdown["scope_counts"]:
        print("\n=== VMs per Application Scope ===\n")
        
        scope_table = PrettyTable()
        scope_table.field_names = ["Application Scope", "VM Count", "Percentage"]
        scope_table.align["Application Scope"] = "l"
        scope_table.align["VM Count"] = "r"
        scope_table.align["Percentage"] = "r"
        
        # Sort scopes alphabetically
        sorted_scopes = sorted(breakdown["scope_counts"].items())
        total_vms = breakdown["summary"]["total_vms"]
        
        for scope_name, count in sorted_scopes:
            percentage = (count / total_vms * 100) if total_vms > 0 else 0
            scope_table.add_row([scope_name, f"{count:,}", f"{percentage:.1f}%"])
        
        print(scope_table)
        
        # Show VM details only if not counts_only and scope_map is provided
        if not counts_only and scope_map:
            print("\n=== VM Details by Scope ===\n")
            
            for scope_name in sorted([s for s in scope_map.keys() if scope_map[s]["count"] > 0]):
                vms = scope_map[scope_name]["vms"]
                count = len(vms)
                
                print(f"--- {scope_name} ({count} VMs) ---")
                
                if count <= 10:  # Show all if 10 or fewer
                    vm_table = PrettyTable()
                    vm_table.field_names = ["Name", "Cloud", "Region", "Risk", "Coverage"]
                    vm_table.align["Name"] = "l"
                    vm_table.align["Cloud"] = "l"
                    vm_table.align["Region"] = "l"
                    vm_table.align["Risk"] = "c"
                    vm_table.align["Coverage"] = "l"
                    
                    for vm in vms:
                        coverage = ', '.join(vm.get('covered_by', []))
                        if len(coverage) > 25:
                            coverage = coverage[:22] + "..."
                        
                        vm_table.add_row([
                            vm.get('name', 'N/A')[:25],
                            vm.get('cloud_provider', 'N/A'),
                            vm.get('region', 'N/A')[:15],
                            vm.get('highest_risk', 'N/A'),
                            coverage
                        ])
                    
                    print(vm_table)
                else:  # Show first 5 for large lists
                    vm_table = PrettyTable()
                    vm_table.field_names = ["Name", "Cloud", "Region", "Risk", "Coverage"]
                    vm_table.align["Name"] = "l"
                    vm_table.align["Cloud"] = "l"  
                    vm_table.align["Region"] = "l"
                    vm_table.align["Risk"] = "c"
                    vm_table.align["Coverage"] = "l"
                    
                    for vm in vms[:5]:
                        coverage = ', '.join(vm.get('covered_by', []))
                        if len(coverage) > 25:
                            coverage = coverage[:22] + "..."
                        
                        vm_table.add_row([
                            vm.get('name', 'N/A')[:25],
                            vm.get('cloud_provider', 'N/A'),
                            vm.get('region', 'N/A')[:15], 
                            vm.get('highest_risk', 'N/A'),
                            coverage
                        ])
                    
                    print(vm_table)
                    print(f"... and {count - 5} more VMs (use JSON output or --csv for complete list)")
                
                print()


def extract_global_args(args):
    """Extract global arguments that can appear anywhere in the command line"""
    global_args = {
        'verbose': False,
        'debug': False,
        'profile': 'default',
        'version': False
    }
    
    filtered_args = []
    i = 0
    
    while i < len(args):
        arg = args[i]
        
        if arg in ['-v', '--verbose']:
            global_args['verbose'] = True
        elif arg in ['-d', '--debug']:
            global_args['debug'] = True
        elif arg in ['-p', '--profile']:
            if i + 1 < len(args):
                global_args['profile'] = args[i + 1]
                i += 1  # Skip the profile name
            else:
                print("Error: --profile requires a profile name")
                sys.exit(1)
        elif arg == '--version':
            global_args['version'] = True
        else:
            filtered_args.append(arg)
        
        i += 1
    
    return global_args, filtered_args


def main():
    # Handle version display first
    if '--version' in sys.argv:
        print(f"Aqua VM Extraction Utility version {__version__}")
        sys.exit(0)
    
    # Extract global arguments
    global_args, filtered_args = extract_global_args(sys.argv[1:])
    
    # Show version and exit if requested
    if global_args['version']:
        print(f"Aqua VM Extraction Utility version {__version__}")
        sys.exit(0)
    
    # Now parse with the filtered args
    parser = argparse.ArgumentParser(
        description='Aqua VM Extraction Utility - Extract VM inventory for enforcer onboarding',
        prog='aqua_vm_extract',
        epilog='Global options can be placed before or after the command:\n'
               '  -v, --verbose        Show human-readable output instead of JSON\n'
               '  -d, --debug          Show debug output including API calls\n'
               '  -p, --profile        Configuration profile to use (default: default)\n'
               '  --version            Show program version',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    # Create subparsers for commands
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # Setup command
    setup_parser = subparsers.add_parser('setup', help='Interactive setup wizard')
    setup_parser.add_argument('profile_name', nargs='?', help='Profile name to create/update (optional)')
    
    # Profile command with subcommands
    profile_parser = subparsers.add_parser('profile', help='Manage configuration profiles')
    profile_subparsers = profile_parser.add_subparsers(dest='profile_command', help='Profile management commands')
    
    # Profile list
    profile_list_parser = profile_subparsers.add_parser('list', help='List available profiles')
    
    # Profile show
    profile_show_parser = profile_subparsers.add_parser('show', help='Show profile details')
    profile_show_parser.add_argument('name', nargs='?', help='Profile name to show (defaults to current default profile)')
    
    # Profile delete
    profile_delete_parser = profile_subparsers.add_parser('delete', help='Delete a profile')
    profile_delete_parser.add_argument('name', help='Profile name to delete')
    
    # Profile set-default
    profile_default_parser = profile_subparsers.add_parser('set-default', help='Set default profile')
    profile_default_parser.add_argument('name', help='Profile name to set as default')
    
    # VM command with subcommands
    vm_parser = subparsers.add_parser('vm', help='VM inventory commands')
    vm_subparsers = vm_parser.add_subparsers(dest='vm_command', help='VM commands')
    
    # VM list
    vm_list_parser = vm_subparsers.add_parser('list', help='List VMs (JSON by default, use -v for table, --csv for CSV)')
    vm_list_parser.add_argument('--no-enforcer', action='store_true',
                               help='Show only VMs without VM enforcer coverage')
    vm_list_parser.add_argument('--cloud', help='Filter by cloud provider (AWS, Azure, GCP)')
    vm_list_parser.add_argument('--region', help='Filter by region')
    vm_list_parser.add_argument('--risk', dest='risk_level', 
                               choices=['critical', 'high', 'medium', 'low'],
                               help='Filter by risk level')
    vm_list_parser.add_argument('--csv', action='store_true',
                               help='Output in CSV format instead of JSON')
    
    # Create mutual exclusion group for --breakdown and --scope in list
    vm_list_scope_group = vm_list_parser.add_mutually_exclusive_group()
    vm_list_scope_group.add_argument('--scope', help='Filter by application scope')
    vm_list_scope_group.add_argument('--breakdown', action='store_true',
                                    help='Show breakdown by application scope')
    
    # VM count
    vm_count_parser = vm_subparsers.add_parser('count', help='Show VM statistics (JSON by default, use -v for table)')
    
    # Create mutual exclusion group for --breakdown and --scope in count
    vm_count_scope_group = vm_count_parser.add_mutually_exclusive_group()
    vm_count_scope_group.add_argument('--scope', help='Filter by application scope')
    vm_count_scope_group.add_argument('--breakdown', action='store_true',
                                     help='Show breakdown by application scope')
    
    
    # Parse the filtered arguments
    args = parser.parse_args(filtered_args)
    
    # Add global args to the namespace
    args.verbose = global_args['verbose']
    args.debug = global_args['debug']
    args.profile = global_args['profile']
    
    # Show help if no command provided
    if args.command is None:
        parser.print_help()
        sys.exit(1)
    
    # Handle setup command
    if args.command == 'setup':
        # Use positional argument if provided, otherwise fall back to -p flag
        if hasattr(args, 'profile_name') and args.profile_name:
            profile_name = args.profile_name
        elif args.profile != 'default':
            profile_name = args.profile
        else:
            profile_name = None
        success = interactive_setup(profile_name, debug=args.debug)
        sys.exit(0 if success else 1)
    
    # Handle profile commands
    if args.command == 'profile':
        config_mgr = ConfigManager()
        
        # Handle profile list
        if args.profile_command == 'list':
            if not args.verbose:
                # JSON output by default
                profile_data = get_all_profiles_info()
                print(json.dumps(profile_data, indent=2))
            else:
                # Verbose mode shows human-readable output
                list_profiles(verbose=True)
            sys.exit(0)
        
        # Handle profile show
        elif args.profile_command == 'show':
            # If no name provided, use the default profile
            if args.name is None:
                config_mgr = ConfigManager()
                profile_name = config_mgr.get_default_profile()
            else:
                profile_name = args.name
            
            profile_info = get_profile_info(profile_name)
            if not profile_info:
                print(profile_not_found_response(profile_name, 'text' if args.verbose else 'json'))
                sys.exit(1)
            
            print(format_profile_info(profile_info, 'text' if args.verbose else 'json'))
            sys.exit(0)
        
        # Handle profile delete
        elif args.profile_command == 'delete':
            result = delete_profile_with_result(args.name)
            print(profile_operation_response(
                result['action'],
                result['profile'],
                result['success'],
                result.get('error'),
                'text' if args.verbose else 'json'
            ))
            sys.exit(0 if result['success'] else 1)
        
        # Handle profile set-default
        elif args.profile_command == 'set-default':
            result = set_default_profile_with_result(args.name)
            print(profile_operation_response(
                result['action'],
                result['profile'],
                result['success'],
                result.get('error'),
                'text' if args.verbose else 'json'
            ))
            sys.exit(0 if result['success'] else 1)
        
        # No subcommand specified
        else:
            print("Error: No profile subcommand specified")
            print("\nAvailable profile commands:")
            print("  profile list              List all profiles")
            print("  profile show <name>       Show profile details")
            print("  profile delete <name>     Delete a profile")
            print("  profile set-default <name> Set default profile")
            print("\nExample: python aqua_vm_extract.py profile list")
            sys.exit(1)
    
    # Handle VM commands
    if args.command == 'vm':
        # No subcommand specified
        if not hasattr(args, 'vm_command') or args.vm_command is None:
            print("Error: No VM subcommand specified")
            print("\nAvailable VM commands:")
            print("  vm list              List VMs (use --breakdown for scope breakdown)")
            print("  vm count             Show VM statistics (use --breakdown for scope breakdown)") 
            print("\nExample: python aqua_vm_extract.py vm list --no-enforcer")
            print("Example: python aqua_vm_extract.py vm count --breakdown")
            sys.exit(1)
    
    # For other commands, we need authentication
    # First try to load from profile
    profile_loaded = False
    actual_profile = args.profile
    if hasattr(args, 'profile'):
        result = load_profile_credentials(args.profile)
        if isinstance(result, tuple):
            profile_loaded, actual_profile = result
        else:
            # Backward compatibility if someone is using old version
            profile_loaded = result
    
    # Check if credentials are available (either from profile or environment)
    has_creds = os.environ.get('AQUA_USER')
    
    if not has_creds:
        if args.verbose:
            print("No credentials found.")
            print("\nYou can:")
            print("1. Run 'python aqua_vm_extract.py setup' to configure credentials")
            print("2. Set environment variables (AQUA_KEY, AQUA_SECRET, etc.)")
            print("3. Create an .env file with credentials")
        else:
            # JSON error output
            print(json.dumps({"error": "No credentials found. Run 'setup' command or set environment variables."}))
        sys.exit(1)
    
    # Print version info in debug mode
    if args.debug:
        print(f"DEBUG: Aqua VM Extraction Utility version: {__version__}")
        print()
    
    # Authenticate
    try:
        if profile_loaded and args.verbose:
            print(f"Using profile: {actual_profile}")
        if args.verbose:
            print("Authenticating with Aqua Security platform...")
        token = authenticate(verbose=args.debug)
        if args.verbose:
            print("Authentication successful!\n")
    except Exception as e:
        if args.verbose:
            print(f"Authentication failed: {e}")
        else:
            print(json.dumps({"error": f"Authentication failed: {str(e)}"}))
        sys.exit(1)
    
    # Get CSP endpoint from environment
    csp_endpoint = os.environ.get('CSP_ENDPOINT')
    
    if not csp_endpoint:
        if args.verbose:
            print("Error: CSP_ENDPOINT environment variable not set")
        else:
            print(json.dumps({"error": "CSP_ENDPOINT environment variable not set"}))
        sys.exit(1)
    
    # Execute VM commands
    try:
        if args.command == 'vm' and args.vm_command == 'list':
            # Debug: Show which endpoint we're using
            if args.debug:
                print(f"DEBUG: Using CSP endpoint for VM API: {csp_endpoint}")
            
            # Extract optional filters and flags
            no_enforcer = getattr(args, 'no_enforcer', False)
            cloud = getattr(args, 'cloud', None)
            region = getattr(args, 'region', None)
            risk_level = getattr(args, 'risk_level', None)
            scope = getattr(args, 'scope', None)
            csv_output = getattr(args, 'csv', False)
            breakdown = getattr(args, 'breakdown', False)
            
            vm_list(csp_endpoint, token, args.verbose, args.debug, 
                   no_enforcer=no_enforcer, cloud=cloud, region=region, 
                   risk_level=risk_level, scope=scope, csv_output=csv_output, breakdown=breakdown)
        
        elif args.command == 'vm' and args.vm_command == 'count':
            if args.debug:
                print(f"DEBUG: Using CSP endpoint for VM API: {csp_endpoint}")
            
            scope = getattr(args, 'scope', None)
            breakdown = getattr(args, 'breakdown', False)
            
            vm_count(csp_endpoint, token, args.verbose, args.debug, scope=scope, breakdown=breakdown)
        
    
    except KeyboardInterrupt:
        if args.verbose:
            print("\nOperation cancelled by user")
        else:
            print(json.dumps({"error": "Operation cancelled by user"}))
        sys.exit(1)
    except Exception as e:
        if args.verbose:
            print(f"Unexpected error: {e}")
        else:
            print(json.dumps({"error": f"Unexpected error: {str(e)}"}))
        sys.exit(1)


if __name__ == '__main__':
    main()