# Aqua Security License Utility

A command-line tool for extracting and analyzing license utilization data from Aqua Security platform.

## Features

- Extract license information in JSON or table format
- **NEW**: Show actual utilization vs license limits with percentage calculations
- **NEW**: Support for serverless functions counting and tracking
- Generate license breakdown by application scope
- Export data to CSV and JSON files  
- Secure credential storage with profile management
- Clean JSON output for automation and integration
- **Enhanced**: 50%+ performance improvement with optimized API calls

## Installation

### From source

```bash
git clone https://github.com/andreazorzetto/aquasec-license-util.git
cd aquasec-license-util

# Optionally create a Python virtual environment
python -m venv .venv
source .venv/bin/activate

pip install -r requirements.txt
```

### Prerequisites

- **Authentication**: This utility requires username/password authentication to connect to Aqua Security platform
- **Python library**: The `aquasec` library must be installed:

```bash
pip install aquasec
```

## Quick Start

### Initial Setup

```bash
# Interactive setup wizard (creates/updates default profile)
python aqua_license_util.py setup

# Setup a specific profile
python aqua_license_util.py setup myprofile
# or
python aqua_license_util.py setup -p myprofile
```

### Basic Usage

```bash
# Show license information (JSON output)
python aqua_license_util.py license show

# Show license information in table format
python aqua_license_util.py license show -v

# Show actual utilization vs license limits (NEW in v0.4.0)
python aqua_license_util.py license count

# Show utilization vs limits in table format
python aqua_license_util.py license count -v

# Generate license breakdown by scope (JSON output)
python aqua_license_util.py license breakdown

# Generate license breakdown in table format
python aqua_license_util.py license breakdown -v

# Export to files
python aqua_license_util.py license breakdown --csv-file report.csv --json-file report.json
```

## Output Modes

1. **Default**: Clean JSON output with license totals only
2. **Verbose (-v)**: Human-readable table format showing license details
3. **Debug (-d)**: Detailed execution with API calls and debugging information (includes all API URLs for repository and enforcer counting)

## Environment Variables

If you prefer environment variables over the setup wizard:

### For SaaS Deployments

```bash
# Username/Password (Required)
export AQUA_USER=your-email@company.com
export AQUA_PASSWORD=your-password

# Endpoints (Required)
export CSP_ENDPOINT='https://xyz.cloud.aquasec.com'  # Your Aqua Console URL
export AQUA_ENDPOINT='https://api.cloudsploit.com'   # Regional API endpoint

# Regional API Endpoints:
# - US Region: https://api.cloudsploit.com
# - EU-1 Region: https://eu-1.api.cloudsploit.com
# - Asia Region: https://asia-1.api.cloudsploit.com
```

### For On-Premise Deployments

```bash
# Username/Password (Required)
export AQUA_USER=your-email@company.com
export AQUA_PASSWORD=your-password

# Console Endpoint (Required)
export CSP_ENDPOINT='https://aqua.company.internal'  # Your Aqua Console URL

# Note: Do NOT set AQUA_ENDPOINT for on-premise deployments
```

**Note**: This utility requires username/password authentication. API key authentication is not supported in this implementation.

## Profile Management

Manage multiple Aqua environments with profiles:

```bash
# List all profiles
python aqua_license_util.py profile list

# Show profile details
python aqua_license_util.py profile show production

# Show default profile (without specifying name)
python aqua_license_util.py profile show

# Delete a profile
python aqua_license_util.py profile delete old-profile

# Set default profile
python aqua_license_util.py profile set-default production

# Use specific profile with any command
python aqua_license_util.py -p production license show
```

## Command Reference

### License Commands

- `license show` - Display license totals (JSON by default, use -v for table)
- `license breakdown` - Show license usage per application scope

### Profile Commands

- `profile list` - List all configured profiles
- `profile show [name]` - Display profile details (defaults to current default profile)
- `profile delete <name>` - Remove a profile
- `profile set-default <name>` - Set the default profile

## Examples

### CI/CD Integration

```yaml
# GitHub Actions example
- name: Check Aqua License Usage
  run: |
    python aqua_license_util.py license show > license.json
    
    # Process the JSON output
    jq '.num_repositories' license.json
```

### Monitoring Script

```bash
#!/bin/bash
# Get license data as JSON
LICENSE_DATA=$(python aqua_license_util.py license show)

# Extract metrics
REPOS=$(echo "$LICENSE_DATA" | jq '.num_repositories')
ENFORCERS=$(echo "$LICENSE_DATA" | jq '.num_enforcers')

# Alert if approaching limits
if [ $REPOS -gt 900 ]; then
  echo "Warning: Repository usage at $REPOS/1000"
fi
```

## License

MIT License

## Contributing

Issues and pull requests are welcome at [github.com/andreazorzetto/aquasec-license-util](https://github.com/andreazorzetto/aquasec-license-util)