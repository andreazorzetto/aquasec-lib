#!/usr/bin/env python3
"""
Aqua Global-Scope Extract

Reports how image repositories and running containers map to application scopes,
including the ones that are not in any application scope.

It lists the application scopes, reads the full inventory, then subtracts the
union of everything the scopes select; whatever is left is reported as unscoped.
All calls are read-only (GET).

Usage:
    python aqua_global_scope_extract.py setup                 # Interactive setup
    python aqua_global_scope_extract.py extract               # JSON summary + lists
    python aqua_global_scope_extract.py extract -v            # Human-readable tables
    python aqua_global_scope_extract.py extract --repos-only
    python aqua_global_scope_extract.py extract --containers-only
    python aqua_global_scope_extract.py extract --csv-dir ./out --json-file out.json
"""

import argparse
import datetime
import json
import os
import sys

from prettytable import PrettyTable

from aquasec import (
    authenticate,
    get_all_repositories,
    get_all_containers,
    get_app_scopes,
    container_key,
    get_console_url,
    load_profile_credentials,
    interactive_setup,
    list_profiles,
    ConfigManager,
    get_profile_info,
    get_all_profiles_info,
    format_profile_info,
    delete_profile_with_result,
    set_default_profile_with_result,
    profile_not_found_response,
    profile_operation_response,
)

# Version
__version__ = "0.1.0"

GLOBAL_SCOPE = "Global"

# Sentinel meaning "no path given for this output flag - use the default name
# inside the run's output directory".
DEFAULT_OUTPUT = "<default>"


def resolve_output_path(value, output_dir, default_name):
    """
    Resolve an output flag to a concrete path, creating the directory as needed.

    Reports go into ``output_dir`` unless a location is explicitly given:

    - flag with no value (``--xlsx``)      -> ``<output_dir>/<default_name>``
    - bare file name (``--xlsx r.xlsx``)   -> ``<output_dir>/r.xlsx``
    - path with a directory component
      (``--xlsx ./r.xlsx``, ``/tmp/r.xlsx``, ``sub/r.xlsx``) -> used as given

    A bare name is deliberately placed in the output folder: naming a file is not
    the same as asking for it in the current directory, and dropping reports next
    to the source is what we are trying to avoid. Include a directory (even
    ``./``) to choose the location yourself.

    Args:
        value: The flag value (DEFAULT_OUTPUT when the flag was given bare)
        output_dir: Directory for this run's reports
        default_name: File name to use when the flag was given bare

    Returns:
        The resolved path.
    """
    if value == DEFAULT_OUTPUT:
        path = os.path.join(output_dir, default_name)
    elif os.path.dirname(value):
        path = value
    else:
        path = os.path.join(output_dir, value)

    parent = os.path.dirname(os.path.abspath(path))
    os.makedirs(parent, exist_ok=True)
    return path


# ---------------------------------------------------------------------------
# Pure helpers (no network) -- unit-testable
# ---------------------------------------------------------------------------

def repo_key(repo):
    """Stable unique key for a repository: '<registry>/<name>'."""
    return f"{repo.get('registry', 'unknown')}/{repo.get('name', 'unknown')}"


def summarize(total, unscoped_count):
    """Build a small summary dict with a rounded unscoped percentage."""
    scoped = total - unscoped_count
    pct = round((unscoped_count / total * 100), 2) if total > 0 else 0
    return {
        "total": total,
        "scoped": scoped,
        "unscoped": unscoped_count,
        "unscoped_percentage": pct,
    }


def group_containers_by_cluster(containers):
    """
    Group containers by cluster -> namespace -> count.

    This is the actionable view for platform teams: which clusters/namespaces are
    running workloads that no application scope (and therefore no team) owns.
    """
    grouped = {}
    for c in containers:
        cluster = c.get("cluster_name") or "(none)"
        namespace = c.get("namespace_name") or "(none)"
        grouped.setdefault(cluster, {})
        grouped[cluster][namespace] = grouped[cluster].get(namespace, 0) + 1
    return grouped


def container_row(c):
    """Flatten a container to the fields that matter for coverage reporting."""
    return {
        "id": container_key(c),
        "name": c.get("name", ""),
        "image_name": c.get("image_name") or c.get("origin_image_name", "")
                      or c.get("registry_image_name", ""),
        "cluster_name": c.get("cluster_name", ""),
        "namespace_name": c.get("namespace_name", ""),
        "host_name": c.get("host_name", ""),
        "status": c.get("status", ""),
        "risk_level": c.get("risk_level", ""),
    }


# ---------------------------------------------------------------------------
# Orchestration (network)
# ---------------------------------------------------------------------------

def get_application_scope_names(server, token, verbose=False, debug=False):
    """
    Return the list of application scope names, excluding the built-in Global scope.

    Raises a clear error if the scopes API is not accessible (the API key needs
    Access Management read permission for the scope enumeration to work).
    """
    try:
        all_scopes = get_app_scopes(server, token, debug)
    except Exception as e:
        # get_app_scopes raises on a non-200 response. A 403 almost always means
        # the API key/role is missing Access Management read permission.
        if "403" in str(e):
            raise PermissionError(
                "Unable to list application scopes. The API key/role needs "
                "'Access Management' read permission (endpoint "
                "/api/v2/access_management/scopes returned HTTP 403)."
            )
        raise
    # Dedupe by name (order-preserving). Large tenants can return the same scope
    # across pages (pagination drift), and duplicates would only waste API calls.
    names = list(dict.fromkeys(
        s.get("name") for s in all_scopes
        if s.get("name") and s.get("name") != GLOBAL_SCOPE
    ))
    if verbose:
        print(f"Found {len(names)} application scope(s) (excluding {GLOBAL_SCOPE})")
    return names


def collect_scope_coverage(server, token, app_scopes, repo_index=None, cont_index=None,
                           include_repos=True, include_containers=True, verbose=False, debug=False):
    """
    Single sweep over the application scopes that collects, per scope, both the
    union of scoped keys (for the delta) and the *membership* -- expressed as
    index arrays into the master repository/container lists so the payload stays
    compact even when catch-all scopes each cover thousands of repos.

    Returns:
        (scoped_repo_keys, scoped_container_keys, coverage)
        where coverage is a list of
        {"scope", "repos", "containers", "repo_ids", "cont_ids"} dicts.
    """
    scoped_repo_keys = set()
    scoped_container_keys = set()
    coverage = []
    n = len(app_scopes)
    repo_index = repo_index or {}
    cont_index = cont_index or {}

    for i, scope in enumerate(app_scopes, 1):
        entry = {"scope": scope, "repos": 0, "containers": 0, "repo_ids": [], "cont_ids": []}
        if include_repos:
            repos = get_all_repositories(server, token, scope=scope, verbose=debug)
            ids = []
            for r in repos:
                k = repo_key(r)
                scoped_repo_keys.add(k)
                if k in repo_index:
                    ids.append(repo_index[k])
            entry["repos"] = len(repos)
            entry["repo_ids"] = sorted(set(ids))
        if include_containers:
            containers = get_all_containers(server, token, scope=scope, verbose=debug)
            ids = []
            for c in containers:
                k = container_key(c)
                scoped_container_keys.add(k)
                if k in cont_index:
                    ids.append(cont_index[k])
            entry["containers"] = len(containers)
            entry["cont_ids"] = sorted(set(ids))
        coverage.append(entry)
        if verbose:
            print(f"  scope {i}/{n}: {scope} "
                  f"(repos={entry['repos']}, containers={entry['containers']})")

    return scoped_repo_keys, scoped_container_keys, coverage


def analyze(server, token, include_repos=True, include_containers=True,
            verbose=False, debug=False):
    """
    Run the full Global-only analysis.

    Returns a dict with a summary, master resource lists, per-scope coverage +
    membership (for the interactive heatmap), and the lists of unscoped
    repositories and/or containers.
    """
    app_scopes = get_application_scope_names(server, token, verbose, debug)

    result = {
        "summary": {},
        "application_scopes": sorted(app_scopes),
        "application_scope_count": len(app_scopes),
    }

    # Master lists (the Global view) + key->index maps. Every scoped resource is a
    # subset of Global, so every scope's membership can be stored as indices here.
    master_repos, repo_index = [], {}
    master_containers, cont_index = [], {}

    if include_repos:
        if verbose:
            print("Fetching all repositories (Global view)...")
        all_repos = get_all_repositories(server, token, verbose=debug)
        if verbose:
            print(f"  {len(all_repos)} repositories in Global")
        for i, r in enumerate(all_repos):
            master_repos.append({"name": r.get("name", ""), "registry": r.get("registry", "")})
            repo_index[repo_key(r)] = i
        result["all_repositories"] = master_repos

    if include_containers:
        if verbose:
            print("Fetching all containers (Global view)...")
        all_containers = get_all_containers(server, token, verbose=debug)
        if verbose:
            print(f"  {len(all_containers)} containers in Global")
        for i, c in enumerate(all_containers):
            master_containers.append(container_row(c))
            cont_index[container_key(c)] = i
        result["all_containers"] = master_containers

    # One pass over the scopes: union keys for the delta + per-scope membership.
    scoped_repo_keys, scoped_container_keys, coverage = collect_scope_coverage(
        server, token, app_scopes, repo_index, cont_index,
        include_repos, include_containers, verbose, debug)

    unscoped_repo_ids, unscoped_cont_ids = [], []

    if include_repos:
        unscoped_repo_ids = sorted(
            (i for i, r in enumerate(all_repos) if repo_key(r) not in scoped_repo_keys),
            key=lambda i: (master_repos[i]["registry"], master_repos[i]["name"]))
        result["summary"]["repositories"] = summarize(len(all_repos), len(unscoped_repo_ids))
        result["unscoped_repositories"] = [
            {"name": master_repos[i]["name"], "registry": master_repos[i]["registry"],
             "key": f"{master_repos[i]['registry']}/{master_repos[i]['name']}"}
            for i in unscoped_repo_ids
        ]

    if include_containers:
        unscoped_cont_ids = sorted(
            (i for i, c in enumerate(all_containers) if container_key(c) not in scoped_container_keys),
            key=lambda i: (master_containers[i]["cluster_name"], master_containers[i]["name"]))
        result["summary"]["containers"] = summarize(len(all_containers), len(unscoped_cont_ids))
        result["unscoped_containers"] = [master_containers[i] for i in unscoped_cont_ids]
        result["unscoped_containers_by_cluster"] = group_containers_by_cluster(
            [master_containers[i] for i in unscoped_cont_ids])

    # Coverage table for the heatmap: the "(unscoped)" bucket pinned first (its
    # membership is the Global-only set), then every application scope.
    unscoped_entry = {
        "scope": "(unscoped)",
        "unscoped": True,
        "repos": len(unscoped_repo_ids),
        "containers": len(unscoped_cont_ids),
        "repo_ids": unscoped_repo_ids,
        "cont_ids": unscoped_cont_ids,
    }
    result["scope_coverage"] = [unscoped_entry] + coverage

    return result


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------

def print_tables(result):
    """Human-readable rendering of the analysis result."""
    print("\n=== Global-Only (Unscoped) Inventory ===\n")
    print(f"Application scopes analyzed: {result['application_scope_count']}")

    summary = result["summary"]
    stbl = PrettyTable()
    stbl.field_names = ["Asset type", "Total", "In an app scope", "Global-only", "Global-only %"]
    stbl.align = "r"
    stbl.align["Asset type"] = "l"
    if "repositories" in summary:
        s = summary["repositories"]
        stbl.add_row(["Repositories", s["total"], s["scoped"], s["unscoped"], f"{s['unscoped_percentage']:.1f}%"])
    if "containers" in summary:
        s = summary["containers"]
        stbl.add_row(["Containers", s["total"], s["scoped"], s["unscoped"], f"{s['unscoped_percentage']:.1f}%"])
    print(stbl)

    if "unscoped_repositories" in result:
        repos = result["unscoped_repositories"]
        print(f"\n--- Global-only repositories ({len(repos)}) ---")
        if repos:
            t = PrettyTable()
            t.field_names = ["Repository", "Registry"]
            t.align = "l"
            for r in repos:
                t.add_row([r["name"], r["registry"]])
            print(t)

    if "unscoped_containers" in result:
        containers = result["unscoped_containers"]
        print(f"\n--- Global-only containers ({len(containers)}) ---")
        if containers:
            t = PrettyTable()
            t.field_names = ["Container", "Image", "Cluster", "Namespace", "Status"]
            t.align = "l"
            for c in containers:
                t.add_row([c["name"], c["image_name"], c["cluster_name"], c["namespace_name"], c["status"]])
            print(t)

        by_cluster = result.get("unscoped_containers_by_cluster", {})
        if by_cluster:
            print("\n--- Global-only containers by cluster / namespace ---")
            ct = PrettyTable()
            ct.field_names = ["Cluster", "Namespace", "Containers"]
            ct.align["Cluster"] = "l"
            ct.align["Namespace"] = "l"
            ct.align["Containers"] = "r"
            for cluster in sorted(by_cluster):
                for namespace in sorted(by_cluster[cluster]):
                    ct.add_row([cluster, namespace, by_cluster[cluster][namespace]])
            print(ct)

    # Alerts
    alerts = []
    if "repositories" in summary and summary["repositories"]["unscoped"] > 0:
        s = summary["repositories"]
        alerts.append(f"{s['unscoped']} repositories ({s['unscoped_percentage']:.1f}%) are not in any application scope.")
    if "containers" in summary and summary["containers"]["unscoped"] > 0:
        s = summary["containers"]
        alerts.append(f"{s['unscoped']} containers ({s['unscoped_percentage']:.1f}%) are not in any application scope.")
    if alerts:
        print("\n⚠️  Coverage gaps:")
        for a in alerts:
            print(f"   - {a}")


def write_csv_files(result, csv_dir):
    """Write unscoped repositories and containers to CSV files in csv_dir."""
    import csv
    os.makedirs(csv_dir, exist_ok=True)
    written = []

    if "unscoped_repositories" in result:
        path = os.path.join(csv_dir, "unscoped_repositories.csv")
        with open(path, "w", newline="") as f:
            w = csv.writer(f)
            w.writerow(["name", "registry"])
            for r in result["unscoped_repositories"]:
                w.writerow([r["name"], r["registry"]])
        written.append(path)

    if "unscoped_containers" in result:
        path = os.path.join(csv_dir, "unscoped_containers.csv")
        with open(path, "w", newline="") as f:
            w = csv.writer(f)
            w.writerow(["id", "name", "image_name", "cluster_name", "namespace_name",
                        "host_name", "status", "risk_level"])
            for c in result["unscoped_containers"]:
                w.writerow([c["id"], c["name"], c["image_name"], c["cluster_name"],
                            c["namespace_name"], c["host_name"], c["status"], c["risk_level"]])
        written.append(path)

    return written


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_parser():
    parser = argparse.ArgumentParser(
        description="Aqua Global-Scope Extract - report how repositories and "
                    "containers map to application scopes, including unscoped ones",
        prog="aqua_global_scope_extract",
        epilog="Global options can be placed before or after the command:\n"
               "  -v, --verbose        Human-readable tables instead of JSON\n"
               "  -d, --debug          Show API-level debug output\n"
               "  -p, --profile        Configuration profile to use (default: default)\n"
               "  --version            Show program version",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    setup_parser = subparsers.add_parser("setup", help="Interactive setup wizard")
    setup_parser.add_argument("profile_name", nargs="?", help="Profile name to create/update (optional)")

    profile_parser = subparsers.add_parser("profile", help="Manage configuration profiles")
    profile_subparsers = profile_parser.add_subparsers(dest="profile_command")
    profile_subparsers.add_parser("list", help="List available profiles")
    show_p = profile_subparsers.add_parser("show", help="Show profile details")
    show_p.add_argument("name", nargs="?")
    del_p = profile_subparsers.add_parser("delete", help="Delete a profile")
    del_p.add_argument("name")
    def_p = profile_subparsers.add_parser("set-default", help="Set default profile")
    def_p.add_argument("name")

    extract_parser = subparsers.add_parser("extract", help="Extract Global-only repositories and containers")
    group = extract_parser.add_mutually_exclusive_group()
    group.add_argument("--repos-only", action="store_true", help="Only analyze repositories")
    group.add_argument("--containers-only", action="store_true", help="Only analyze containers")
    # Output flags take an optional path. Given bare (e.g. just --dashboard) the
    # file is written into the run's output directory with a default name, which
    # keeps generated reports out of the project root.
    extract_parser.add_argument("--json-file", dest="json_file", nargs="?", const=DEFAULT_OUTPUT,
                                help="Write full result as JSON (default: <output-dir>/report.json)")
    extract_parser.add_argument("--csv-dir", dest="csv_dir", nargs="?", const=DEFAULT_OUTPUT,
                                help="Write CSV files (default: <output-dir>/)")
    extract_parser.add_argument("--xlsx", dest="xlsx", nargs="?", const=DEFAULT_OUTPUT,
                                help="Write a multi-sheet Excel workbook (default: <output-dir>/report.xlsx)")
    extract_parser.add_argument("--dashboard", dest="dashboard", nargs="?", const=DEFAULT_OUTPUT,
                                help="Write a self-contained HTML dashboard (default: <output-dir>/dashboard.html)")
    extract_parser.add_argument("--output-dir", dest="output_dir",
                                help="Directory for generated reports (default: output_<timestamp>)")
    extract_parser.add_argument("--title", dest="title",
                                help="Report/dashboard title (e.g. an organization or tenant name)")

    return parser


def parse_global_args(raw_args):
    """Extract -v/-d/-p from anywhere in the args, mirroring repo-breakdown."""
    global_args = {"verbose": False, "debug": False, "profile": "default"}
    filtered = []
    i = 0
    while i < len(raw_args):
        arg = raw_args[i]
        if arg in ("-v", "--verbose"):
            global_args["verbose"] = True
        elif arg in ("-d", "--debug"):
            global_args["debug"] = True
        elif arg in ("-p", "--profile"):
            if i + 1 < len(raw_args):
                global_args["profile"] = raw_args[i + 1]
                i += 1
        else:
            filtered.append(arg)
        i += 1
    return global_args, filtered


def handle_profile_command(args):
    """Handle the 'profile' subcommands. Returns an exit code."""
    if args.profile_command == "list":
        if not args.verbose:
            print(json.dumps(get_all_profiles_info(), indent=2))
        else:
            list_profiles(verbose=True)
        return 0
    if args.profile_command == "show":
        profile_name = args.name or ConfigManager().get_default_profile()
        info = get_profile_info(profile_name)
        if not info:
            print(profile_not_found_response(profile_name, "text" if args.verbose else "json"))
            return 1
        print(format_profile_info(info, "text" if args.verbose else "json"))
        return 0
    if args.profile_command == "delete":
        result = delete_profile_with_result(args.name)
        print(profile_operation_response(result["action"], result["profile"], result["success"],
                                         result.get("error"), "text" if args.verbose else "json"))
        return 0 if result["success"] else 1
    if args.profile_command == "set-default":
        result = set_default_profile_with_result(args.name)
        print(profile_operation_response(result["action"], result["profile"], result["success"],
                                         result.get("error"), "text" if args.verbose else "json"))
        return 0 if result["success"] else 1
    print("Error: No profile subcommand specified (list | show | delete | set-default)")
    return 1


def main():
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    raw_args = sys.argv[1:]
    if "--version" in raw_args:
        print(f"aqua_global_scope_extract {__version__}")
        sys.exit(0)

    global_args, filtered_args = parse_global_args(raw_args)
    parser = build_parser()
    args = parser.parse_args(filtered_args)
    args.verbose = global_args["verbose"]
    args.debug = global_args["debug"]
    args.profile = global_args["profile"]

    if args.command is None:
        parser.print_help()
        sys.exit(1)

    # Setup command
    if args.command == "setup":
        if getattr(args, "profile_name", None):
            profile_name = args.profile_name
        elif args.profile != "default":
            profile_name = args.profile
        else:
            profile_name = None
        sys.exit(0 if interactive_setup(profile_name, debug=args.debug) else 1)

    # Profile command
    if args.command == "profile":
        sys.exit(handle_profile_command(args))

    # From here we need authentication
    result = load_profile_credentials(args.profile)
    profile_loaded, actual_profile = result if isinstance(result, tuple) else (result, args.profile)

    if not (os.environ.get("AQUA_USER") or os.environ.get("AQUA_KEY")):
        msg = "No credentials found. Run 'setup' or set environment variables."
        print(msg if args.verbose else json.dumps({"error": msg}))
        sys.exit(1)

    try:
        if args.verbose and profile_loaded:
            print(f"Using profile: {actual_profile}")
            print("Authenticating with Aqua Security platform...")
        token = authenticate(verbose=args.debug)
        if args.verbose:
            print("Authentication successful!\n")
    except Exception as e:
        print(f"Authentication failed: {e}" if args.verbose else json.dumps({"error": f"Authentication failed: {e}"}))
        sys.exit(1)

    # Normalised, so a bare host / :443 / trailing slash all work.
    csp_endpoint = get_console_url()
    if not csp_endpoint:
        msg = "CSP_ENDPOINT environment variable not set"
        print(f"Error: {msg}" if args.verbose else json.dumps({"error": msg}))
        sys.exit(1)

    if args.command == "extract":
        include_repos = not args.containers_only
        include_containers = not args.repos_only
        try:
            result = analyze(csp_endpoint, token, include_repos, include_containers,
                             args.verbose, args.debug)
        except PermissionError as e:
            print(f"Error: {e}" if args.verbose else json.dumps({"error": str(e)}))
            sys.exit(1)
        except Exception as e:
            if args.verbose:
                import traceback
                traceback.print_exc()
            print(f"Error: {e}" if args.verbose else json.dumps({"error": str(e)}))
            sys.exit(1)

        now = datetime.datetime.now()
        generated_at = now.strftime("%Y-%m-%d %H:%M")
        report_title = args.title or "Application-scope Coverage"
        # One folder per run keeps reports together and out of the project root.
        output_dir = args.output_dir or f"output_{now.strftime('%Y%m%d-%H%M%S')}"
        written_paths = []

        if args.json_file:
            path = resolve_output_path(args.json_file, output_dir, "report.json")
            # Overwrite (not append): a report is a single clean JSON document.
            with open(path, "w", encoding="utf-8") as f:
                json.dump(result, f, indent=2)
            written_paths.append(path)
        if args.csv_dir:
            # Same rule as the file flags: a bare name lands inside the output
            # folder, a path with a directory component is used as given.
            if args.csv_dir == DEFAULT_OUTPUT:
                csv_dir = output_dir
            elif os.path.dirname(args.csv_dir):
                csv_dir = args.csv_dir
            else:
                csv_dir = os.path.join(output_dir, args.csv_dir)
            written_paths.extend(write_csv_files(result, csv_dir))
        if args.xlsx:
            path = resolve_output_path(args.xlsx, output_dir, "report.xlsx")
            try:
                import reporting
                reporting.write_xlsx(result, path, title=report_title, generated_at=generated_at)
                written_paths.append(path)
            except ImportError:
                msg = "Excel export requires openpyxl (pip install openpyxl)"
                print(f"Error: {msg}" if args.verbose else json.dumps({"error": msg}))
                sys.exit(1)
        if args.dashboard:
            path = resolve_output_path(args.dashboard, output_dir, "dashboard.html")
            import reporting
            reporting.write_dashboard(result, path, title=report_title, generated_at=generated_at)
            written_paths.append(path)

        if written_paths and args.verbose:
            print(f"\nReports written to {os.path.dirname(os.path.abspath(written_paths[0]))}:")
            for p in written_paths:
                print(f"  {os.path.basename(p)}")

        if args.verbose:
            print_tables(result)
        else:
            print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
