# Changelog

All notable changes to the Aqua Global-Scope Extract Utility are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [0.1.0] - 2026-07-24

### Added
- Initial release.
- `extract` command computes the **scope delta**: image repositories and running
  containers visible in the Global scope but not selected by any application scope.
- Output formats: JSON (default), human-readable tables (`-v`), JSON file
  (`--json-file`), CSV files (`--csv-dir`), a multi-sheet Excel workbook
  (`--xlsx`, via openpyxl), and a single self-contained HTML dashboard
  (`--dashboard`). `--title` sets the workbook/dashboard title.
- `analyze()` records per-scope coverage and *membership* in a single scope
  sweep: master `all_repositories` / `all_containers` lists plus, per scope,
  index arrays (`repo_ids` / `cont_ids`) into them — compact even when catch-all
  scopes each cover thousands of repos. Exposed as `scope_coverage` (with the
  "(unscoped)" bucket pinned first) and as a "Scope Coverage" Excel sheet.
- The dashboard (theme-aware light/dark, offline, no external assets) is a
  **two-pane explorer** with a drag-to-resize splitter between the panes. The
  left pane is an application-scope coverage heatmap (every scope's repository
  (blue) + container (green) counts, with the unscoped "no application scope"
  bucket pinned neutrally at the top; sort/search). **Clicking any row** drives
  the right pane, which lists that selection's **matched resources** in two
  clearly-labelled sections — Repositories (distribution by registry + a
  searchable list) and Containers (distribution by cluster + a searchable list).
  Deep-linkable via `#scope=<name>` / `#unscoped`. Colour encoding validated for
  colour-blind separation.
- `--repos-only` / `--containers-only` to limit the analysis.
- Unscoped containers are additionally grouped by cluster → namespace, the
  actionable view for platform teams chasing coverage gaps.
- Profile-based authentication (`setup` / `profile` commands) consistent with the
  other aquasec example utilities.
- Clear error when the API key/role lacks Access Management read permission
  (required to enumerate application scopes).
