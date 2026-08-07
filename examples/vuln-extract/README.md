# Aqua Vulnerability Extract

Exports vulnerability findings from Aqua without paging
`/api/v2/risks/vulnerabilities` page by page.

| Command | What it does |
|---|---|
| `server-export` | The server builds a ZIP and streams it back. One call. **Start here.** |
| `extract` | Walks the image inventory and queries each image. Streams results, adds per-image attribution, reconciles the total. |
| `estimate` | Reports the tenant's real counts before you run either. |

## Installation

```bash
pip install -r requirements.txt
```

## Setup

```bash
python aqua_vuln_extract.py setup            # interactive
python aqua_vuln_extract.py profile list
```

Or set `AQUA_KEY`/`AQUA_SECRET` (or `AQUA_USER`/`AQUA_PASSWORD`) plus `CSP_ENDPOINT`.
With `CSP_ENDPOINT` unset, the console URL is read from the auth token.

Global options (`-v`, `-d`, `-p <profile>`) may appear before or after the command.

---

## server-export

```
POST /api/v2/risks/vulnerabilities/exporters/{entity_type}/export  -> {"token": ...}
POST /api/v2/risks/vulnerabilities/exporters/{entity_type}/stream  -> application/zip
```

The archive comes back in the HTTP response — no bucket, no destination
integration, no session to hold open.

```bash
# Running workloads, critical and high
python aqua_vuln_extract.py server-export --running-only --severities critical,high \
    --output findings.zip --csv findings.csv -v

# Everything
python aqua_vuln_extract.py server-export --output all.zip -v
```

| Flag | Meaning |
|---|---|
| `--entity-type` | `images` (default), `hosts`, `functions`, `containers` |
| `--running-only` | Only findings on images with running workloads |
| `--severities` | e.g. `critical,high` |
| `--registry`, `--cluster`, `--namespaces`, `--scope` | Server-side filters |
| `--output` | Where to write the ZIP |
| `--csv` | Also unpack the archive to CSV |
| `--exporter` | Exporter to use (default `Compressed CSV`) |
| `--columns-name` / `--columns` | Column set, or explicit columns |
| `--list-columns` | List selectable columns and exit |
| `--timeout` | Seconds to wait for the archive (default 3600) |

### Columns

~118 columns are selectable, including some the default set omits —
`epss_score`, `epss_percentile`, `scan_resource_id`, `num_running_workloads`,
`cluster`, `resource.purl`, `cisa_due_date`.

```bash
python aqua_vuln_extract.py server-export --list-columns -v
python aqua_vuln_extract.py server-export --columns name,aqua_severity,epss_score,cluster
```

### Gotchas

- `--exporter` must name an exporter that **already exists** on the tenant. It is
  not a free-text label.
- One of `--columns-name` / `--columns` is **required**.
- Both of the above fail with **HTTP 500**, not a 4xx.
- The archive's `manifest.json` can still read `"status": "Generating"` in a
  completed download — it is not a completeness signal. Check the row count.

---

## extract

Per-image walk. Slower to start than `server-export`, but streams results as it
goes, records which image each finding came from, and checks the total against
the endpoint's own count.

```bash
# Everything in a scope
python aqua_vuln_extract.py extract --scope my-app-scope --csv findings.csv -v

# Running workloads only, with the per-image and per-CVE rollups
python aqua_vuln_extract.py extract --running-only \
    --csv findings.csv --by-image by_image.csv --unique-cves cves.csv -v

# JSON Lines, more parallelism
python aqua_vuln_extract.py extract --jsonl findings.jsonl --workers 16 -v
```

Findings stream to disk per image, so memory stays flat regardless of estate size.

| Flag | Meaning |
|---|---|
| `--scope`, `--registry`, `--severities` | Filters |
| `--running-only` | Only images with running workloads |
| `--workers` | Images queried concurrently (default 8) |
| `--page-size` | Findings per request (default 500) |
| `--csv` / `--jsonl` | Per-finding output |
| `--by-image` | One row per image: findings, distinct CVEs, severity split |
| `--unique-cves` | One row per distinct CVE, with affected-image counts |
| `--dedupe` | Drop repeated findings (costs memory) |
| `--no-reconcile` | Skip the up-front count check |
| `--fail-fast` | Abort on the first failing image instead of skipping it |

### Outputs

| Output | One row per |
|---|---|
| `--csv` / `--jsonl` | finding — (image, package, CVE), same granularity as the API |
| `--by-image` | image |
| `--unique-cves` | distinct CVE |

A row is **one finding, not one unique CVE** — the same CVE appears once per
affected image and package. On a real tenant 2.1M findings collapsed to 34,050
distinct CVEs. Use `--unique-cves` if you want the CVE list.

CSV column order matches the console's own export, plus appended fields the
console omits (EPSS, running-workload counts, PURL, `scan_resource_id`).

---

## Measured on a 2.1M-finding tenant

| | Rows | Time |
|---|---|---|
| `server-export` (all) | 2,106,800 | 12.7 min |
| `extract` (all, 12 workers) | 2,111,019 | 7.7 min |
| endpoint's own count | 2,106,840 | — |

`extract` currently runs ~0.2% high against the endpoint's count; `server-export`
matches it to within 40 rows. Use `server-export` when the total has to be exact.

`--running-only` on the same tenant reduces 2,106,840 findings across 3,369 images
to 3,263 findings across 11 images.
