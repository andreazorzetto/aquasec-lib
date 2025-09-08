# Aqua Security Repository Breakdown Utility

A command-line tool for analyzing repository scope assignments and identifying orphaned repositories in Aqua Security platform.

## Features

- List all repositories with optional filtering
- Identify orphaned repositories (those without application scope assignments)
- Analyze repository distribution across application scopes
- View complete scope membership for each repository
- Export analysis results to CSV and JSON files

## Installation

### From source

```bash
git clone https://github.com/andreazorzetto/aquasec-repo-breakdown.git
cd aquasec-repo-breakdown

# Optionally create a Python virtual environment
python -m venv .venv
source .venv/bin/activate

pip install -r requirements.txt
```

### Prerequisites

- **Authentication**: This utility requires username/password authentication to connect to Aqua Security platform
- **Python library**: The `aquasec` library v0.4.0+ must be installed (v0.1.1 requires compatibility updates):

```bash
pip install aquasec
```

## Quick Start

### Initial Setup

```bash
# Interactive setup wizard (creates/updates default profile)
python aqua_repo_breakdown.py setup

# Setup a specific profile
python aqua_repo_breakdown.py setup myprofile
# or
python aqua_repo_breakdown.py setup -p myprofile
```

### Basic Usage

```bash
# List all repositories (default behavior return a JSON output)
python aqua_repo_breakdown.py repo list

# List with human-readable table format
python aqua_repo_breakdown.py repo list -v

# List only orphaned repositories
python aqua_repo_breakdown.py repo list --orphan

# Show all scope assignments for each repository
python aqua_repo_breakdown.py repo list --all-scopes -v

# Get repository breakdown analysis
python aqua_repo_breakdown.py repo breakdown -v
```

## Commands

### Repository Commands

#### `repo list` - List repositories

Default behavior shows all repositories. Options:
- `--orphan` - Show only orphaned repositories (no app scope assignments)
- `--all-scopes` - Display all scope memberships for each repository
- `--scope <name>` - Filter by specific application scope
- `--registry <name>` - Filter by registry

Examples:
```bash
# List all repositories (JSON format by default)
python aqua_repo_breakdown.py repo list

# List orphaned repositories with table format
python aqua_repo_breakdown.py repo list --orphan -v

# Show repositories with their scope assignments
python aqua_repo_breakdown.py repo list --all-scopes -v

# Filter by specific scope
python aqua_repo_breakdown.py repo list --scope production
```

#### `repo breakdown` - Analyze repository distribution

Shows comprehensive analysis of repository scope assignments:

```bash
# Show full analysis (JSON by default)
python aqua_repo_breakdown.py repo breakdown

# Human-readable analysis with tables
python aqua_repo_breakdown.py repo breakdown -v

# Export results
python aqua_repo_breakdown.py repo breakdown --json-file analysis.json --csv-file analysis.csv
```

## Profile Management

The utility uses a profile-based system for managing credentials:

```bash
# List all profiles
python aqua_repo_breakdown.py profile list

# Show profile details
python aqua_repo_breakdown.py profile show myprofile

# Set default profile
python aqua_repo_breakdown.py profile set-default myprofile

# Delete a profile
python aqua_repo_breakdown.py profile delete oldprofile
```

## Authentication Methods

### 1. Profile-based (Recommended)

Run the setup wizard to create an encrypted profile:
```bash
python aqua_repo_breakdown.py setup
```

### 2. Environment Variables

Set the following environment variables:
```bash
export AQUA_USER=your-username
export AQUA_PASSWORD=your-password  
export AQUA_URL=https://your-aqua-instance.com
export CSP_ENDPOINT=https://your-csp-endpoint.com
```

### 3. Using .env File

Create a `.env` file in the project directory:
```env
AQUA_USER=your-username
AQUA_PASSWORD=your-password
AQUA_URL=https://your-aqua-instance.com
CSP_ENDPOINT=https://your-csp-endpoint.com
```

## Global Options

These options can be placed before or after any command:

- `-v, --verbose` : Show human-readable output instead of JSON
- `-d, --debug` : Show debug output including API calls
- `-p, --profile <name>` : Use a specific configuration profile
- `--version` : Show program version

## Understanding Orphaned Repositories

In Aqua Security:
- All repositories implicitly belong to the "Global" scope
- Repositories can be assigned to additional application scopes
- **Orphaned repositories** are those that ONLY belong to Global and have no application scope assignments
- These represent unorganized repositories that may need attention

## Output Examples

### Repository List (Table Format)
```
Repository              Registry
------------------     -----------
nginx                  docker.io
redis                  docker.io
myapp/frontend         ecr.aws.com
myapp/backend          ecr.aws.com

Total repositories: 4
```

### Repository Breakdown Analysis
```
=== Repository Breakdown by Scope ===

Metric                  Count    Percentage
------------------      -----    ----------
Total Repositories      1,234    100%
Orphaned (Global only)    567    46.0%
With App Scopes           667    54.0%

=== Repositories per Scope ===

Scope          Repository Count    Percentage
---------      ----------------    ----------
Global                    1,234    100.0%
production                  234     19.0%
staging                     156     12.6%
development                  89      7.2%

⚠️  Alert: 567 repositories (46.0%) are not assigned to any application scope.
Use 'repo list --orphan' to see them.
```

## Examples

```bash
# Use a specific profile with verbose output
python aqua_repo_breakdown.py -p production repo list --orphan -v

# Export orphaned repositories to JSON
python aqua_repo_breakdown.py repo list --orphan --json-file orphaned-repos.json

# Debug mode to see API calls
python aqua_repo_breakdown.py -d repo breakdown

# Show repositories in multiple scopes
python aqua_repo_breakdown.py repo list --all-scopes -v
```

## Security

- Credentials are stored encrypted using the `cryptography` library
- Profile data is saved in `~/.aqua/profiles.json`
- Never commit credentials or `.env` files to version control

## License

MIT License - see LICENSE file for details