# Aqua Security Library Examples

This directory contains example implementations using the `aquasec` library.

## Full-Featured Utility Applications

For comprehensive examples of how to use the `aquasec` library, check out these two production-ready CLI utilities:

### 1. [Aqua Security License Utility](https://github.com/andreazorzetto/aquasec-license-utility)
A command-line tool for analyzing Aqua Security license utilization and generating reports.

**Features:**
- License utilization analysis across multiple scopes
- Repository and enforcer count tracking
- Multiple output formats (table, JSON, CSV)
- Secure profile-based credential management
- Interactive setup wizard

**Installation:**
```bash
git clone https://github.com/andreazorzetto/aquasec-license-utility.git
cd aquasec-license-utility
pip install -r requirements.txt
```

**Quick Start:**
```bash
# Setup credentials
python aqua_license_util.py setup

# Get license utilization
python aqua_license_util.py --all-results
```

### 2. [Aqua Security Repository Breakdown](https://github.com/andreazorzetto/aquasec-repo-breakdown)
A CLI tool for analyzing repository scope assignments and identifying orphaned repositories in Aqua Security.

**Features:**
- List all repositories with their scope assignments
- Identify orphaned repositories (only in Global scope)
- Repository breakdown analysis by scope
- Export results to CSV or JSON
- Verbose debugging mode

**Installation:**
```bash
git clone https://github.com/andreazorzetto/aquasec-repo-breakdown.git
cd aquasec-repo-breakdown
pip install -r requirements.txt
```

**Quick Start:**
```bash
# Setup credentials (shared with license utility)
python aqua_repo_breakdown.py setup

# Find orphaned repositories
python aqua_repo_breakdown.py repo list --orphan
```

## Library Documentation

For detailed library API documentation, see the main [README](../README.md) in the parent directory.