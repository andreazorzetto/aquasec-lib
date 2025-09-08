# Aqua Security Library Examples

This directory contains production-ready example implementations demonstrating how to use the `aquasec` library effectively.

## Installation Prerequisites

First, ensure you have the aquasec library installed:
```bash
pip install aquasec>=0.5.0
```

Or install the latest development version from this repository:
```bash
# From the aquasec-lib root directory
pip install -e .
```

## Available Examples

### 1. License Utility (`license-utility/`)
A command-line tool for analyzing Aqua Security license utilization and generating reports.

**Features:**
- License utilization analysis across multiple scopes
- Repository and enforcer count tracking
- Multiple output formats (table, JSON, CSV)
- Secure profile-based credential management
- Interactive setup wizard
- 50%+ performance improvement with optimized API calls

**Quick Start:**
```bash
cd examples/license-utility
pip install -r requirements.txt

# Setup credentials
python aqua_license_util.py setup

# Get license utilization
python aqua_license_util.py --all-results
```

### 2. Repository Breakdown (`repo-breakdown/`)
A CLI tool for analyzing repository scope assignments and identifying orphaned repositories in Aqua Security.

**Features:**
- List all repositories with their scope assignments
- Identify orphaned repositories (only in Global scope)
- Repository breakdown analysis by scope
- Export results to CSV or JSON
- Verbose debugging mode

**Quick Start:**
```bash
cd examples/repo-breakdown
pip install -r requirements.txt

# Setup credentials (shared with license utility)
python aqua_repo_breakdown.py setup

# Find orphaned repositories
python aqua_repo_breakdown.py repo list --orphan
```

### 3. VM Extract (`vm-extract/`)
A command-line utility for extracting VM inventory data from Aqua Security platform with advanced filtering capabilities.

**Features:**
- Extract comprehensive VM inventory data
- Advanced filtering by coverage type, cloud provider, region, and risk level
- Memory-efficient streaming processing for large datasets
- Export to CSV, JSON formats
- Support for multiple output modes
- Profile-based authentication

**Quick Start:**
```bash
cd examples/vm-extract
pip install -r requirements.txt

# Setup credentials
python aqua_vm_extract.py setup

# List VMs without enforcer coverage
python aqua_vm_extract.py vm list --no-enforcer

# Export all VMs to CSV
python aqua_vm_extract.py vm list --export-csv vm_inventory.csv
```

## Common Usage Patterns

These examples demonstrate several key patterns for using the aquasec library:

1. **Authentication & Configuration**: All examples show how to use the secure profile-based credential management
2. **API Integration**: Examples of calling different API endpoints (licenses, repositories, VMs, etc.)
3. **Data Processing**: Filtering, pagination, and efficient data handling
4. **Output Formatting**: Multiple output formats (table, JSON, CSV) with proper formatting
5. **Error Handling**: Robust error handling and user-friendly messages

## Legacy Repository Notice

These examples were previously maintained as separate repositories:
- **license-utility**: Formerly at `github.com/andreazorzetto/aquasec-license-util`
- **repo-breakdown**: Formerly at `github.com/andreazorzetto/aquasec-repo-breakdown` 
- **vm-extract**: Formerly at `github.com/andreazorzetto/aquasec-vm-extract`

The standalone repositories now contain redirect notices pointing to this consolidated location.

## Library Documentation

For detailed library API documentation, see the main [README](../README.md) in the parent directory.