# Aqua VM Extraction Utility

A focused tool for extracting VM inventory from the Aqua Security platform and identifying candidates for VM enforcer onboarding.

## Overview

This utility extracts full VM inventory from the Aqua Security platform and filters for VMs that do not have VM enforcer deployed. It's designed to help identify which VMs are candidates for VM enforcer onboarding.

## Features

- **VM Inventory Extraction**: Retrieve complete VM inventory from Aqua Security platform
- **Enforcer Coverage Filtering**: Identify VMs without VM enforcer coverage
- **Multiple Output Formats**: JSON (default), human-readable tables, CSV export
- **Flexible Filtering**: Filter by cloud provider, region, risk level
- **Profile-based Authentication**: Secure credential management with multiple profiles
- **Export Capabilities**: Export filtered results for onboarding processes

## Installation

### Prerequisites

- Python 3.8 or higher
- Access to Aqua Security platform
- Valid Aqua Security credentials

### Setup

1. Clone or download this repository
2. Navigate to the project directory:
   ```bash
   cd aquasec-extract-vms-for-onboarding
   ```
3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## Quick Start

### 1. Configure Credentials

Run the interactive setup wizard:
```bash
python aqua_vm_extract.py setup
```

This will guide you through setting up your Aqua Security credentials securely.

### 2. List All VMs

```bash
# JSON output (default)
python aqua_vm_extract.py vm list

# Human-readable table
python aqua_vm_extract.py vm list -v
```

### 3. Find VMs Without Enforcer Coverage

```bash
# JSON output
python aqua_vm_extract.py vm list --no-enforcer

# Table format
python aqua_vm_extract.py vm list --no-enforcer -v
```

### 4. Export for Onboarding

```bash
# Export to CSV and JSON
python aqua_vm_extract.py vm export

# Custom filenames
python aqua_vm_extract.py vm export --csv-file my_vms.csv --json-file my_vms.json
```

## Usage

### Commands

#### Setup and Profile Management
```bash
# Interactive setup
python aqua_vm_extract.py setup [profile_name]

# List profiles
python aqua_vm_extract.py profile list

# Show profile details
python aqua_vm_extract.py profile show [profile_name]

# Delete profile
python aqua_vm_extract.py profile delete <profile_name>

# Set default profile
python aqua_vm_extract.py profile set-default <profile_name>
```

#### VM Operations

##### VM List Commands
```bash
# List all VMs (JSON output by default)
python aqua_vm_extract.py vm list

# List all VMs (table format)
python aqua_vm_extract.py vm list -v

# Export VMs to CSV
python aqua_vm_extract.py vm list --csv

# List VMs without enforcer coverage
python aqua_vm_extract.py vm list --no-enforcer

# Filter by cloud provider
python aqua_vm_extract.py vm list --cloud AWS

# Filter by region
python aqua_vm_extract.py vm list --region us-west-1

# Filter by risk level
python aqua_vm_extract.py vm list --risk critical

# Filter by application scope
python aqua_vm_extract.py vm list --scope production

# Show breakdown by application scope
python aqua_vm_extract.py vm list --breakdown

# Export breakdown to CSV
python aqua_vm_extract.py vm list --breakdown --csv
```

##### VM Count Commands
```bash
# Show VM statistics (JSON output by default)
python aqua_vm_extract.py vm count

# Show VM statistics (table format)
python aqua_vm_extract.py vm count -v

# Show statistics for specific scope
python aqua_vm_extract.py vm count --scope production

# Show count breakdown by application scope
python aqua_vm_extract.py vm count --breakdown
```

**Note:** The `--breakdown` and `--scope` options are mutually exclusive.

### Global Options

Global options can be placed before or after the command:

- `-v, --verbose`: Show human-readable output instead of JSON
- `-d, --debug`: Show debug output including API calls  
- `-p, --profile`: Use specific configuration profile
- `--version`: Show program version

### Examples

```bash
# Verbose output for VMs without enforcer in AWS
python aqua_vm_extract.py -v vm list --no-enforcer --cloud AWS

# Debug mode with custom profile
python aqua_vm_extract.py -d -p production vm count

# Export high-risk VMs without enforcer to CSV
python aqua_vm_extract.py vm list --no-enforcer --risk high --csv

# Show VM breakdown across all application scopes
python aqua_vm_extract.py vm list --breakdown -v

# Count breakdown with debug information
python aqua_vm_extract.py -d vm count --breakdown

# Export scope breakdown analysis to CSV
python aqua_vm_extract.py vm list --breakdown --csv > vm_scope_analysis.csv
```

## Output Formats

### JSON Output (Default)
All commands output JSON by default for easy integration with scripts and automation:

```json
{
  "count": 150,
  "vms": [
    {
      "id": "vm-12345",
      "name": "web-server-1",
      "cloud_provider": "AWS",
      "region": "us-west-1",
      "covered_by": ["agentless"],
      "highest_risk": "high",
      ...
    }
  ]
}
```

### Table Output (-v flag)
Human-readable table format for interactive use:

```
+------------------+-------+----------+------------------+------+----------+----------+
|       Name       | Cloud |  Region  |        OS        | Risk | Coverage | Compliant|
+------------------+-------+----------+------------------+------+----------+----------+
| web-server-1     | AWS   | us-west-1| ubuntu 20.04     | high | agentless|    No    |
| db-server-2      | Azure | eastus   | Windows Server..| medium| agentless|    No    |
+------------------+-------+----------+------------------+------+----------+----------+
```

### CSV Export
Export VM data to CSV files for spreadsheet analysis:

```bash
python aqua_vm_extract.py vm list --no-enforcer --csv-file vms_for_onboarding.csv
```

## VM Filtering Logic

### Enforcer Coverage Types

VMs are considered "without VM enforcer" when their `covered_by` field does NOT include any of:
- `vm_enforcer` - VM Enforcer deployed
- `host_enforcer` - Host Enforcer deployed  
- `aqua_enforcer` - Aqua Enforcer (container/K8s)
- `agent` - Agent-based enforcement

VMs with only the following coverage types are candidates for onboarding:
- `agentless` - Agentless scanning only
- `cspm` - Cloud Security Posture Management only

### Filter Options

- **Cloud Provider**: Filter by AWS, Azure, GCP, etc.
- **Region**: Filter by specific cloud regions
- **Risk Level**: Filter by critical, high, medium, low risk levels
- **Enforcer Coverage**: Show only VMs without VM enforcer deployment

## Authentication

### Profile-based Authentication (Recommended)
The utility uses secure profile-based credential storage:

```bash
python aqua_vm_extract.py setup
```

Credentials are encrypted and stored in `~/.aqua/profiles.json`.

### Environment Variables
Alternatively, set these environment variables:

```bash
# For SaaS API Keys Authentication
export AQUA_KEY="your-api-key"
export AQUA_SECRET="your-api-secret"  
export AQUA_ROLE="api_admin_role"
export AQUA_METHODS="ANY"
export AQUA_ENDPOINT="https://eu-1.api.cloudsploit.com"

# For Username/Password Authentication
export AQUA_USER="your-email@company.com"
export AQUA_PASSWORD="your-password"

# Required for both methods
export CSP_ENDPOINT="https://your-tenant.cloud.aquasec.com"
```

## Development

### Running Tests

```bash
# Install test dependencies
pip install -r requirements-test.txt

# Run tests
python -m pytest tests/

# Run with coverage
python -m pytest tests/ --cov=. --cov-report=term
```

### Project Structure

```
aquasec-extract-vms-for-onboarding/
├── aqua_vm_extract.py         # Main CLI application
├── requirements.txt           # Runtime dependencies  
├── requirements-test.txt      # Test dependencies
├── README.md                  # This documentation
├── .github/workflows/         # CI/CD workflows
│   └── test.yml              # GitHub Actions testing
└── tests/                     # Test suite
    ├── __init__.py
    └── test_basic.py          # Basic functionality tests
```

## API Endpoints Used

The utility uses the following Aqua Security API endpoints:

- `GET /api/v2/hub/inventory/assets/vms/list` - Retrieve VM inventory
- `GET /api/v2/hub/inventory/assets/vms/list/count` - Get VM counts

## Troubleshooting

### Common Issues

1. **Authentication Failed**
   - Verify credentials are correct
   - Check CSP_ENDPOINT matches your tenant
   - Ensure API key has proper permissions

2. **No VMs Found**  
   - Verify you have access to VM inventory
   - Check if VMs exist in your Aqua Security platform
   - Try without filters first

3. **Permission Errors**
   - Ensure API key has "Auditor" or "Administrator" role
   - Check scope access permissions

### Debug Mode

Use `-d` flag to see detailed API calls and responses:

```bash
python aqua_vm_extract.py -d vm list --no-enforcer
```

### Getting Help

```bash
# Show main help
python aqua_vm_extract.py --help

# Show command-specific help
python aqua_vm_extract.py vm list --help
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes  
4. Add tests for new functionality
5. Ensure all tests pass
6. Submit a pull request

## License

This project follows the same licensing as the parent Aqua Security tools.

## Support

For issues and questions:
1. Check this README for common solutions
2. Use debug mode (`-d`) to troubleshoot
3. Check the GitHub issues for known problems
4. Contact your Aqua Security representative for platform-specific issues