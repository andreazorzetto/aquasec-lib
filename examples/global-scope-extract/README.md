# Aqua Global-Scope Extract

Reports how image repositories and running containers map to your Aqua
application scopes — including the ones that aren't in any application scope.

Produces a summary on the console, an Excel workbook, and an interactive HTML
dashboard. Read-only: every API call is a `GET`.

## Getting started

**1. Create a virtual environment and install**

```bash
python3 -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

A venv keeps these dependencies off your system Python. On macOS it's effectively
required — a system `pip install` is blocked with
`error: externally-managed-environment`. Use `python3`, since `python` may not
exist. Once activated, `python` inside the venv is correct.

**2. Add your credentials** — interactive wizard, stored encrypted:

```bash
python aqua_global_scope_extract.py setup
```

On Aqua SaaS it only asks for your region and credentials — the console URL is
read from the token and verified before the profile is saved:

```
Testing connection...
✓ Authentication successful!
✓ Console URL detected: https://<tenant>.cloud.aquasec.com
✓ Console URL verified.
```

On-prem is asked for the console URL, since sign-in goes to the console itself.

**3. Run it**

```bash
python aqua_global_scope_extract.py extract -v
```

That prints a coverage summary plus the repositories and containers that aren't
in any application scope.

Re-activate the venv (`source .venv/bin/activate`) in any new terminal.

## Building the reports

```bash
python aqua_global_scope_extract.py extract -v --xlsx --dashboard --title "My Company"
```

Each run writes into its own `output_<timestamp>/` folder, so reports never pile
up in the project directory:

```
output_20260730-110301/
├── dashboard.html
└── report.xlsx
```

Open `dashboard.html` in a browser — it's a single self-contained file that works
offline. Pick a scope on the left to list its repositories and containers on the
right; the unscoped bucket sits at the top.

`report.xlsx` has one sheet per view: Summary, Scope Coverage, Unscoped
Repositories, By Registry, Unscoped Containers, By Cluster.

Use `--output-dir DIR` to choose the folder, or pass an explicit path to any
output flag (`--xlsx /tmp/report.xlsx`) to control a single file.

## Common commands

```bash
# Machine-readable JSON to stdout
python aqua_global_scope_extract.py extract

# Limit the scan
python aqua_global_scope_extract.py extract --repos-only
python aqua_global_scope_extract.py extract --containers-only

# Save raw data (into this run's output folder)
python aqua_global_scope_extract.py extract -v --json-file --csv-dir

# Show the API calls being made
python aqua_global_scope_extract.py extract -d
```

## Options

| Flag | What it does |
|------|--------------|
| `-v` | Readable tables instead of JSON |
| `-d` | Show API calls (debug) |
| `-p NAME` | Use a specific credential profile |
| `--repos-only` / `--containers-only` | Limit the scan |
| `--json-file [PATH]` | Full result as JSON |
| `--csv-dir [DIR]` | `unscoped_repositories.csv` + `unscoped_containers.csv` |
| `--xlsx [PATH]` | Excel workbook |
| `--dashboard [PATH]` | Self-contained HTML dashboard |
| `--output-dir DIR` | Where reports go (default `output_<timestamp>`) |
| `--title TEXT` | Title shown on the workbook and dashboard |

Output flags work with or without a path: bare, they use a default name inside
the run's output folder; with a path, that exact path is used.

Global options (`-v`, `-d`, `-p`) work before or after the command.

## Multiple tenants

One profile per tenant:

```bash
python aqua_global_scope_extract.py setup production
python aqua_global_scope_extract.py extract -p production -v --dashboard
```

Or set the environment directly instead of using a profile:

```bash
export AQUA_KEY=... AQUA_SECRET=... AQUA_ROLE=... AQUA_METHODS='ANY:*'
export AQUA_ENDPOINT='https://eu-1.api.cloudsploit.com'    # your region
export CSP_ENDPOINT='<tenant>.cloud.aquasec.com'           # scheme/port optional
```

## Scheduling

Coverage drifts as teams deploy, so it's worth re-running on a schedule and
keeping the snapshots:

```bash
python aqua_global_scope_extract.py extract -p production \
  --json-file "reports/coverage-$(date +%F).json" \
  --dashboard "reports/coverage-$(date +%F).html"
```

## Notes

**Permissions.** The API key or user needs read access to Repositories,
Containers, and Access Management (used to list application scopes).

**Generated files are confidential** — they contain scope, repository, cluster
and host names. They're written locally only, and `.gitignore` keeps them out of
git. Share deliberately.

## Testing

```bash
pip install -r requirements-test.txt
python -m pytest tests/ -v
```
