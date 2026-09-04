# Aqua Security License Utility

A command-line tool for extracting and analyzing license utilization data from Aqua Security platform.

## Features

- Extract license information in JSON or table format
- **NEW**: Show actual utilization vs license limits with percentage calculations
- **NEW**: Support for serverless functions counting and tracking
- **NEW**: Per-scope **host image** breakdown (`license host-images`) — counts images discovered on hosts/VMs by enforcers, by repository, per application scope
- **NEW**: Licensed **feature usage** by enforcer type (`license capabilities`) — how many enforcers actually run a separately licensed capability, such as Advanced Malware Protection
- Generate license breakdown by application scope (now including a host images column)
- Export data to CSV and JSON files  
- Secure credential storage with profile management
- Clean JSON output for automation and integration
- **Enhanced**: 50%+ performance improvement with optimized API calls

## Installation

```bash
# Create and activate a virtual environment
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

**Note**: This utility requires username/password authentication to connect to Aqua Security platform.

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
# Now includes a "Host Images" column (unique host image repos per scope)
python aqua_license_util.py license breakdown

# Generate license breakdown in table format
python aqua_license_util.py license breakdown -v

# Export to files
python aqua_license_util.py license breakdown --csv-file report.csv --json-file report.json

# Host image utilization per application scope (NEW in v0.5.0)
python aqua_license_util.py license host-images          # JSON
python aqua_license_util.py license host-images -v       # table

# Include the list of unique repository names per scope in the JSON output
python aqua_license_util.py license host-images --list-repos

# Export host image breakdown
python aqua_license_util.py license host-images --csv-file host_images.csv

# Licensed feature usage by enforcer type (NEW in v0.12.0)
python aqua_license_util.py license capabilities         # JSON
python aqua_license_util.py license capabilities -v      # table

# Include the enforcer groups that have it enabled, largest first
python aqua_license_util.py license capabilities -v --by-group

# Narrow to one control rather than the union
python aqua_license_util.py license capabilities --capability antivirus_protection

# Export
python aqua_license_util.py license capabilities --csv-file amp.csv --json-file amp.json
```

### Host Images by Scope

Host images are container images discovered running on hosts/VMs by Aqua enforcers.
In the General Images tab they land in a single bucket and are not attributed to an
application scope, but the Host Images API *does* support scope filtering (the
enforcer group that found the image is considered behind the scenes). This command
attributes them to a scope and counts them **by repository** (the image base name,
with the tag/digest stripped) — the unit relevant for licensing — rather than by each
individual image instance.

```bash
$ python aqua_license_util.py license host-images -v
+--------------------+------------------+---------------------+
| Scope              | Host Image Repos | Host Images (total) |
+--------------------+------------------+---------------------+
| Test-1             |               17 |                  24 |
| sri-app-scope-test |                3 |                   4 |
| Product-app1       |                1 |                   1 |
+--------------------+------------------+---------------------+
```

By default the `Global` scope is excluded (it would return everything); add
`--include-global` to include it.

### Licensed Feature Usage

`license capabilities` answers "if we drop this from the contract, what stops
working?" It reads the capability/settings block that the enforcer groups endpoint
already returns, so it costs **one paged sweep** (~15s for ~1,000 groups) rather than
the per-scope fan-out that `license breakdown` performs.

```bash
$ python aqua_license_util.py license capabilities -v
+---------------+-------+---------+-------+-------------+----------------+
| Enforcer Type |  With | Without | Total | Groups With | Groups Without |
+---------------+-------+---------+-------+-------------+----------------+
| agent         |   442 |       0 |   442 |         160 |             76 |
| host_enforcer | 2,905 |   1,641 | 4,546 |         236 |            103 |
| TOTAL         | 3,347 |   1,641 | 4,988 |         396 |            179 |
+---------------+-------+---------+-------+-------------+----------------+

3,347 of 4,988 connected enforcers (67.1%) are running Advanced Malware Protection.
Excluded: 1,768 connected enforcers cannot run this capability - kube_enforcer (44), micro_enforcer (1,724).
```

Counts are point-in-time. Micro Enforcers in particular are ephemeral, and connected
totals move by a few enforcers between runs on a live tenant, so quote the figure with
the date it was taken.

Two things this command gets right that a naive read of the API does not:

**AMP is two flags, not one.** `antivirus_protection` enables Real-time Malware
Protection in *host* runtime policies and `container_antivirus_protection` does the
same for *container* runtime policies. Both draw on the same licence, so the default
`--capability amp` counts a group if **either** is set. Use the individual capability
names to see one control on its own.

**Enforcer type decides whether a flag means anything.** KubeEnforcers and
MicroEnforcers store the AMP flags but cannot act on them — a KubeEnforcer is an
admission controller, a MicroEnforcer is an injected sidecar. Their groups are
excluded from the totals and reported separately, so the utilisation percentage is
of the estate that *could* use the feature, not the whole estate. Counting them
inflated a real tenant's figure by 261 enforcers.

Only AMP is currently reportable. The other group settings (`behavioral_engine`,
`network_protection`, the forensics collectors) are rejected rather than guessed at,
because the enforcer types they apply to have not been verified and a wrong total is
worse than an error.

Exports use an explicit field allowlist: raw enforcer group objects embed the
enforcer registration token, both in `token` and inside `install_command`.

`--by-group` with `--csv-file amp.csv` also writes `amp-groups.csv` with the per-group
detail, since that is a different row shape from the per-type summary. As with the
other export commands, `--json-file` **appends** if the file already exists, giving one
JSON object per line — convenient for accumulating daily snapshots, but use a fresh
path if you want a single parseable object.

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

> **Important — `CSP_ENDPOINT` must be your tenant console, not the regional login portal.**
> On SaaS, you sign in at a regional URL (e.g. `https://eu-1.cloud.aquasec.com`), but each
> tenant has its own dedicated console URL (e.g. `https://<tenant-id>.cloud.aquasec.com`).
> The data APIs (licenses, scopes, host images, …) live on the **tenant console**. If you set
> `CSP_ENDPOINT` to the regional login portal, sign-in succeeds but every subsequent API call
> returns **401**. The tenant console is the `csp_metadata.urls.ese_url` value in the JWT
> returned by sign-in; it is also the URL in your browser's address bar once you're logged into
> the Aqua console.

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
- `license count` - Show actual utilization vs license limits
- `license breakdown` - Show license usage per application scope (images, host images, code repos, enforcers)
- `license host-images` - Show host image repository counts per application scope

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