# Aqua Global-Scope Extract Utility

Find the image **repositories** and running **containers** that live only in the
**Global** scope — i.e. assets that are not covered by any custom application
scope, and therefore fall into "nobody's net": no team owns them, and they are
invisible on team dashboards even though they exist in the platform.

This fills a gap the Aqua console does not currently cover out of the box: there
is no built-in report/filter for "everything that is not assigned to an
application scope other than Global". A product enhancement request (RFE) tracks
adding this natively; in the meantime this utility produces the data on demand.

## Screenshot

<!-- Add a dashboard screenshot here once generated, e.g.:
     ![Dashboard](docs/dashboard.png)
     (keep screenshots free of real customer/tenant data before committing) -->

_Screenshot placeholder — drop a dashboard image here._

## What it does — the "scope delta"

1. List every application scope (excluding the built-in `Global`).
2. Fetch the full Global inventory (all repositories, all containers).
3. For each application scope, fetch the repositories/containers it selects and
   collect their identifiers.
4. Anything in the Global inventory whose identifier is in **no** application
   scope is reported as **unscoped** (Global-only).

- Repositories are keyed by `registry/name`.
- Containers are keyed by their unique instance id (`container_uid`, falling back
  to `id`) and are additionally grouped by **cluster → namespace** — the view a
  platform team needs to chase down uncovered workloads.

## Installation

```bash
# Installs the aquasec library (>=0.9.0) and this utility's dependencies
pip install -r requirements.txt
```

## Authentication

Uses the same profile-based auth as the other aquasec utilities. Two options:

### 1. Interactive setup (recommended)

```bash
python aqua_global_scope_extract.py setup
```

### 2. Environment variables / `.env`

```bash
# SaaS API-key auth
export AQUA_KEY=xxxxxxxx
export AQUA_SECRET=xxxxxxxx
export AQUA_ROLE=Administrator
export AQUA_METHODS='ANY:*'
export AQUA_ENDPOINT='https://eu-1.api.cloudsploit.com'   # region-specific
export CSP_ENDPOINT='https://<tenant>.cloud.aquasec.com'
```

> **Permission note:** the API key/role must have **Access Management (read)**
> permission. Listing application scopes calls
> `/api/v2/access_management/scopes`; without that permission the utility cannot
> compute the delta and will tell you so explicitly.

## Usage

```bash
# JSON summary + full lists (default, machine-readable)
python aqua_global_scope_extract.py extract

# Human-readable tables
python aqua_global_scope_extract.py extract -v

# Only repositories, or only containers
python aqua_global_scope_extract.py extract --repos-only
python aqua_global_scope_extract.py extract --containers-only

# Save results to files (re-run any time for a fresh snapshot)
python aqua_global_scope_extract.py extract --json-file report.json --csv-dir ./out

# Shareable Excel workbook and an interactive HTML dashboard
python aqua_global_scope_extract.py extract \
  --title "My Company" \
  --xlsx report.xlsx \
  --dashboard dashboard.html
```

### Output flags

| Flag | Output |
|------|--------|
| *(none)* | JSON summary + lists to stdout |
| `-v` | Human-readable tables |
| `--json-file PATH` | Full result as JSON |
| `--csv-dir DIR` | `unscoped_repositories.csv` + `unscoped_containers.csv` |
| `--xlsx PATH` | Multi-sheet Excel workbook (Summary, Scope Coverage, Unscoped Repositories, By Registry, Unscoped Containers, By Cluster) |
| `--dashboard PATH` | Single self-contained HTML dashboard (works offline) |
| `--title TEXT` | Title for the workbook/dashboard (e.g. an organization or tenant name) |

### The dashboard

The dashboard is a single self-contained HTML file (no external assets, opens
offline by double-click; theme-aware light/dark). It's a **two-pane explorer**
with a drag-to-resize splitter between the panes:

- **Stat tiles**: repository / container totals and the "no application scope"
  counts and percentages.
- **Left — application scope coverage heatmap**: every scope as a row, with bar
  length + colour shade encoding how many repositories (blue) and containers
  (green) it covers, normalised per column. The **unscoped bucket** (assets in no
  application scope) is pinned at the top. Sort by repositories, containers, or
  name; filter scopes by name; hover for exact counts and share-of-total.
- **Click any row** to drive the **right pane**, which lists **that selection's
  matched resources** in two clearly-labelled sections — Repositories
  (distribution by registry + a searchable list) and Containers (distribution by
  cluster + a searchable list). Opens on the unscoped bucket by default;
  deep-linkable via `#scope=<name>` (or `#unscoped`).

The colour encoding follows a data-viz method (one-hue sequential ramps for
magnitude) and was validated for colour-blind separation on the dark surface.

Because these files can contain sensitive inventory data (scope names, image
repositories, cluster/host names), they are written locally only. Treat them as
confidential — restrict their permissions, share deliberately, and consider
encrypting before sending. A repo-local `.gitignore` keeps generated reports
(`output/`, `*.json`, `*.csv`, `*.xlsx`, `dashboard*.html`, `*.log`) out of git.

Global options (`-v`, `-d`/`--debug`, `-p/--profile <name>`) can be placed
before or after the command.

## Output

`extract` produces a structure like:

```json
{
  "summary": {
    "repositories": {"total": 1472, "scoped": 900, "unscoped": 572, "unscoped_percentage": 38.86},
    "containers":   {"total": 79,   "scoped": 60,  "unscoped": 19,  "unscoped_percentage": 24.05}
  },
  "application_scope_count": 12,
  "application_scopes": ["Team A", "Team B", "..."],
  "unscoped_repositories": [{"name": "...", "registry": "...", "key": "registry/name"}],
  "unscoped_containers": [
    {"id": "...", "name": "...", "image_name": "...", "cluster_name": "...",
     "namespace_name": "...", "host_name": "...", "status": "running", "risk_level": ""}
  ],
  "unscoped_containers_by_cluster": {"cluster-a": {"namespace-x": 4, "namespace-y": 2}}
}
```

With `--csv-dir`, two files are written: `unscoped_repositories.csv` and
`unscoped_containers.csv`.

## Running as a recurring job

Because teams keep deploying, coverage drifts continuously. Run the utility on a
schedule (cron, CI, etc.) and diff the JSON/CSV over time to track how well the
onboarding gate is keeping new assets inside an application scope:

```bash
python aqua_global_scope_extract.py extract -p prod \
  --json-file "reports/unscoped-$(date +%F).json" \
  --csv-dir  "reports/csv-$(date +%F)"
```

## Testing

```bash
pip install -r requirements-test.txt
python -m pytest tests/ -v
```
