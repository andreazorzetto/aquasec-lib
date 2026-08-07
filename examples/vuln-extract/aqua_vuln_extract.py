#!/usr/bin/env python3
"""
Aqua Vulnerability Extract

Gets vulnerability findings out of Aqua without paging
/api/v2/risks/vulnerabilities from page 1 to page N. Two routes, both here:

  server-export  The server builds a ZIP and streams it back. One call, filtered
                 server-side. This is the documented REST path and the one the
                 console's export dialog points you to. Start here.

  extract        Walks the image inventory and queries each image's findings.
                 Slower to start, but streams results as it goes, records which
                 image each finding came from, and reconciles the total against
                 the endpoint's own count.

Why not page the endpoint directly: offset pagination makes the database produce
and discard every row before the requested page, so reading page N costs roughly
N pages of work. A full walk of N pages costs on the order of N^2/2 -- the run
gets slower as it goes, and runtime grows quadratically with the data.

Usage:
    python aqua_vuln_extract.py setup                                  # Interactive setup
    python aqua_vuln_extract.py server-export --running-only --csv out.csv
    python aqua_vuln_extract.py server-export --severities critical,high --output out.zip
    python aqua_vuln_extract.py server-export --list-columns -v        # ~118 to choose from
    python aqua_vuln_extract.py estimate --scope my-app-scope           # Size the job first
    python aqua_vuln_extract.py extract --scope my-app-scope --csv out.csv
    python aqua_vuln_extract.py extract --running-only --by-image by_image.csv
"""

import argparse
import datetime
import json
import os
import sys
import time

from aquasec import (
    authenticate,
    get_all_inventory_images,
    get_vulnerability_count,
    iter_all_vulnerabilities,
    export_vulnerabilities,
    extract_export_csv,
    get_exporter_names,
    get_available_columns,
    finding_key,
    summarise_by_image,
    write_vulnerabilities_csv,
    write_image_summary_csv,
    write_unique_cves_csv,
    resolve_console_url,
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

__version__ = "0.1.0"

# Observed average for a deep page against a large production scope
# (pagesize=1000). Used only to put an order of magnitude on the estimate.
DEEP_PAGE_SECONDS = 41.5

# A single-image query is selective, so it behaves like a shallow page.
IMAGE_QUERY_SECONDS = 1.0


def cmd_estimate(server, token, args):
    """Size the extract and compare deep pagination against the per-image walk."""
    started = time.time()

    total_vulns = get_vulnerability_count(
        server, token,
        scope=args.scope,
        has_workloads=True if args.running_only else None,
        severities=args.severities,
        verbose=args.debug,
    )

    images = get_all_inventory_images(
        server, token,
        scope=args.scope,
        has_workloads=True if args.running_only else None,
        registry_name=args.registry,
        verbose=args.debug,
    )

    page_size = args.page_size
    deep_pages = -(-total_vulns // page_size) if total_vulns else 0

    # Reading page p costs ~p pages of work, so a full walk costs ~N^2/2.
    deep_page_reads = deep_pages * (deep_pages + 1) // 2
    deep_seconds = deep_pages * DEEP_PAGE_SECONDS

    # Per-image: one query per image (plus the terminating page), parallelised.
    image_queries = len(images) * 2
    per_image_seconds = image_queries * IMAGE_QUERY_SECONDS / max(args.workers, 1)

    result = {
        "scope": args.scope or "(all)",
        "running_workloads_only": bool(args.running_only),
        "severities": args.severities,
        "vulnerability_count": total_vulns,
        "image_count": len(images),
        "deep_pagination": {
            "pages": deep_pages,
            "page_reads_including_discarded": deep_page_reads,
            "row_amplification": round(deep_page_reads / deep_pages, 1) if deep_pages else 0,
            "estimated_hours": round(deep_seconds / 3600, 1),
        },
        "per_image": {
            "queries": image_queries,
            "workers": args.workers,
            "estimated_hours": round(per_image_seconds / 3600, 2),
        },
        "elapsed_seconds": round(time.time() - started, 1),
    }

    if not args.verbose:
        print(json.dumps(result, indent=2))
        return 0

    deep = result["deep_pagination"]
    per = result["per_image"]
    print(f"Scope:                 {result['scope']}")
    print(f"Running workloads only: {result['running_workloads_only']}")
    if args.severities:
        print(f"Severities:            {args.severities}")
    print(f"Vulnerabilities:       {total_vulns:,}")
    print(f"Images:                {len(images):,}")
    print()
    print(f"Deep pagination (pagesize={page_size}):")
    print(f"  pages to walk:       {deep['pages']:,}")
    print(f"  pages of DB work:    {deep['page_reads_including_discarded']:,} "
          f"({deep['row_amplification']}x amplification)")
    print(f"  estimated runtime:   ~{deep['estimated_hours']} h")
    print()
    print(f"Per-image extract ({args.workers} workers):")
    print(f"  queries:             {per['queries']:,}")
    print(f"  estimated runtime:   ~{per['estimated_hours']} h")
    print()
    print("Estimates are indicative. For a bulk pull prefer `server-export`, where")
    print("the server builds the archive in one call; use `extract` when you want")
    print("results streamed, attributed per image, and reconciled.")
    return 0


def cmd_extract(server, token, args):
    """Run the per-image extract, streaming results to disk."""
    started = time.time()
    csv_path = args.csv
    jsonl_path = args.jsonl

    if not csv_path and not jsonl_path:
        stamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        csv_path = f"vulnerabilities_{stamp}.csv"
        if args.verbose:
            print(f"No output specified; writing to {csv_path}")

    # Truncate any previous run so the append-per-image writes build one file.
    for path in (csv_path, jsonl_path):
        if path and os.path.exists(path):
            os.remove(path)

    # One cheap aggregate up front, so the run can prove it collected everything
    # the endpoint says exists rather than asking anyone to take it on trust.
    expected = None
    if not args.no_reconcile:
        expected = get_vulnerability_count(
            server, token,
            scope=args.scope,
            has_workloads=True if args.running_only else None,
            severities=args.severities,
            verbose=args.debug,
        )
        if args.verbose:
            print(f"Endpoint reports {expected:,} findings for these filters.")

    total_vulns = 0
    images_done = 0
    images_with_findings = 0
    image_rows = []
    cve_rollup = {}
    seen_findings = set() if args.dedupe else None
    duplicates_dropped = 0

    def progress(done, total, label, count):
        if args.verbose and (done % 25 == 0 or done == total):
            elapsed = time.time() - started
            rate = done / elapsed if elapsed else 0
            remaining = (total - done) / rate if rate else 0
            print(f"  [{done}/{total}] {total_vulns:,} findings | "
                  f"{rate:.1f} images/s | ~{remaining / 60:.0f} min left")

    jsonl_handle = open(jsonl_path, "a", encoding="utf-8") if jsonl_path else None

    try:
        for image, vulns in iter_all_vulnerabilities(
            server, token,
            scope=args.scope,
            has_workloads=True if args.running_only else None,
            registry_name=args.registry,
            severities=args.severities,
            page_size=args.page_size,
            max_workers=args.workers,
            skip_errors=not args.fail_fast,
            progress=progress,
            verbose=args.debug,
        ):
            images_done += 1
            if not vulns:
                continue

            if seen_findings is not None:
                fresh = []
                for vuln in vulns:
                    key = finding_key(vuln)
                    if key in seen_findings:
                        duplicates_dropped += 1
                        continue
                    seen_findings.add(key)
                    fresh.append(vuln)
                vulns = fresh
                if not vulns:
                    continue

            images_with_findings += 1
            total_vulns += len(vulns)

            # Accumulated while streaming: the per-image breakdown is free here,
            # because the walk already knows which image each finding came from.
            if args.by_image:
                image_rows.append(summarise_by_image(image, vulns))

            if args.unique_cves:
                for vuln in vulns:
                    cve = vuln.get("name")
                    if not cve:
                        continue
                    entry = cve_rollup.get(cve)
                    if entry is None:
                        entry = cve_rollup[cve] = {
                            "cve": cve,
                            "severity": (vuln.get("aqua_severity")
                                         or vuln.get("vendor_severity") or ""),
                            "occurrences": 0,
                            "images": set(),
                        }
                    entry["occurrences"] += 1
                    image_label = (vuln.get("image_repository_name")
                                   or vuln.get("image_name") or vuln.get("image_digest"))
                    if image_label:
                        entry["images"].add(image_label)

            if csv_path:
                write_vulnerabilities_csv(vulns, csv_path, append=True)
            if jsonl_handle:
                for vuln in vulns:
                    jsonl_handle.write(json.dumps(vuln) + "\n")
    finally:
        if jsonl_handle:
            jsonl_handle.close()

    if args.by_image:
        image_rows.sort(key=lambda r: -r["findings"])
        write_image_summary_csv(image_rows, args.by_image)

    distinct_cves = None
    if args.unique_cves:
        for entry in cve_rollup.values():
            entry["image_count"] = len(entry["images"])
            entry["images"] = sorted(entry["images"])
        distinct_cves = write_unique_cves_csv(cve_rollup, args.unique_cves)

    elapsed = time.time() - started
    summary = {
        "scope": args.scope or "(all)",
        "running_workloads_only": bool(args.running_only),
        "images_queried": images_done,
        "images_with_findings": images_with_findings,
        "findings": total_vulns,
        "distinct_cves": distinct_cves,
        "elapsed_minutes": round(elapsed / 60, 1),
        "csv_file": csv_path,
        "jsonl_file": jsonl_path,
        "by_image_file": args.by_image,
        "unique_cves_file": args.unique_cves,
    }
    if args.dedupe:
        summary["duplicate_findings_dropped"] = duplicates_dropped
    if expected is not None:
        summary["expected_findings"] = expected
        summary["reconciled"] = total_vulns == expected

    if args.verbose:
        print()
        print(f"Images queried:       {images_done:,}")
        print(f"Images with findings: {images_with_findings:,}")
        print(f"Findings:             {total_vulns:,}")
        if distinct_cves is not None:
            print(f"Distinct CVEs:        {distinct_cves:,}")
        if args.dedupe:
            print(f"Duplicates dropped:   {duplicates_dropped:,}")
        print(f"Elapsed:              {elapsed / 60:.1f} min")
        for path in (csv_path, jsonl_path, args.by_image, args.unique_cves):
            if path:
                print(f"Written:              {path}")
        if expected is not None:
            print()
            if total_vulns == expected:
                print(f"Reconciled: collected {total_vulns:,} of {expected:,} reported.")
            else:
                delta = total_vulns - expected
                pct = 100 * delta / expected if expected else 0
                print(f"NOTE: collected {total_vulns:,} against a reported {expected:,} "
                      f"({delta:+,}, {pct:+.2f}%).")
                if delta < 0:
                    print("  A shortfall means images carrying findings were missing from "
                          "the enumeration (e.g. images outside the Hub inventory).")
                else:
                    # The count is taken before the walk starts, so on a live tenant
                    # scans landing mid-run legitimately push the total above it.
                    print("  A small excess is normal: the count is taken up front, and "
                          "scans completing during the run add findings.")
    else:
        print(json.dumps(summary, indent=2))

    return 0


def cmd_server_export(server, token, args):
    """Ask the server to build the archive, and stream it back."""
    if args.list_exporters:
        names = get_exporter_names(server, token, entity_type=args.entity_type,
                                   verbose=args.debug)
        if args.verbose:
            print(f"Exporters for '{args.entity_type}':")
            for name in names:
                print(f"  {name}")
        else:
            print(json.dumps(names, indent=2))
        return 0

    if args.list_columns:
        columns = get_available_columns(server, token, entity_type=args.entity_type,
                                        verbose=args.debug)
        if args.verbose:
            print(f"{len(columns)} selectable columns for '{args.entity_type}':\n")
            for name, display in sorted(columns.items()):
                print(f"  {name:34} {display}")
        else:
            print(json.dumps(columns, indent=2))
        return 0

    filters = {}
    if args.running_only:
        filters["has_workloads"] = "true"
    if args.severities:
        filters["severities"] = [s.strip() for s in args.severities.split(",") if s.strip()]
    if args.registry:
        filters["registry_name"] = args.registry
    if args.cluster:
        filters["cluster"] = args.cluster
    if args.namespaces:
        filters["namespace_names"] = [n.strip() for n in args.namespaces.split(",") if n.strip()]

    output = args.output or (f"vulnerabilities_"
                             f"{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.zip")

    started = time.time()
    if args.verbose:
        print(f"Requesting a server-side export ({args.entity_type}) ...")
        if filters:
            print(f"Filters: {filters}")

    archive = export_vulnerabilities(
        server, token,
        entity_type=args.entity_type,
        filters=filters or None,
        name=args.exporter,
        columns_name=args.columns_name,
        columns=args.columns,
        application_scope=args.scope,
        output_file=output,
        timeout=args.timeout,
        verbose=args.debug,
    )
    elapsed = time.time() - started

    # Streamed rather than parsed into memory: the archive compresses hard, so a
    # 32 MB download is millions of rows and would cost gigabytes as dicts.
    row_count = extract_export_csv(archive, args.csv) if args.csv else None

    summary = {
        "entity_type": args.entity_type,
        "filters": filters,
        "archive": output,
        "archive_bytes": len(archive),
        "rows": row_count,
        "elapsed_minutes": round(elapsed / 60, 2),
    }

    if args.verbose:
        print(f"\nArchive:  {output} ({len(archive):,} bytes)")
        if row_count is not None:
            print(f"Rows:     {row_count:,} -> {args.csv}")
        print(f"Elapsed:  {elapsed / 60:.2f} min")
    else:
        print(json.dumps(summary, indent=2))

    return 0


def build_parser():
    parser = argparse.ArgumentParser(
        description="Export Aqua vulnerability findings: server-side archive, or a per-image walk",
        prog="aqua_vuln_extract",
        epilog="Global options can be placed before or after the command:\n"
               "  -v, --verbose        Human-readable output instead of JSON\n"
               "  -d, --debug          Show API-level debug output\n"
               "  -p, --profile        Configuration profile to use (default: default)\n"
               "  --version            Show program version",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    setup_parser = subparsers.add_parser("setup", help="Interactive setup wizard")
    setup_parser.add_argument("profile_name", nargs="?", help="Profile name to create/update")

    profile_parser = subparsers.add_parser("profile", help="Manage configuration profiles")
    profile_subparsers = profile_parser.add_subparsers(dest="profile_command")
    profile_subparsers.add_parser("list", help="List available profiles")
    show_p = profile_subparsers.add_parser("show", help="Show profile details")
    show_p.add_argument("name", nargs="?")
    del_p = profile_subparsers.add_parser("delete", help="Delete a profile")
    del_p.add_argument("name")
    def_p = profile_subparsers.add_parser("set-default", help="Set default profile")
    def_p.add_argument("name")

    def add_filters(p):
        p.add_argument("--scope", help="Application scope to restrict the extract to")
        p.add_argument("--registry", help="Registry name filter")
        p.add_argument("--severities", help="Comma-separated severities (e.g. critical,high)")
        p.add_argument("--running-only", action="store_true",
                       help="Only images that have running workloads (applied server-side)")
        p.add_argument("--page-size", type=int, default=500,
                       help="Findings per request (default: 500)")
        p.add_argument("--workers", type=int, default=8,
                       help="Images queried concurrently (default: 8)")

    estimate_parser = subparsers.add_parser(
        "estimate", help="Size the job and compare deep pagination vs per-image")
    add_filters(estimate_parser)

    extract_parser = subparsers.add_parser("extract", help="Run the per-image extract")
    add_filters(extract_parser)
    extract_parser.add_argument("--csv", help="Write findings to this CSV file")
    extract_parser.add_argument("--jsonl", help="Write findings to this JSON Lines file")
    extract_parser.add_argument("--by-image", dest="by_image",
                                help="Write a per-image breakdown CSV (findings and "
                                     "distinct CVEs per image, by severity)")
    extract_parser.add_argument("--unique-cves", dest="unique_cves",
                                help="Write a distinct-CVE rollup CSV (one row per CVE, "
                                     "with how many images it affects)")
    extract_parser.add_argument("--dedupe", action="store_true",
                                help="Drop repeated (image, package, CVE) findings. Costs "
                                     "memory proportional to the result set; the walk "
                                     "already skips duplicate images")
    extract_parser.add_argument("--no-reconcile", dest="no_reconcile", action="store_true",
                                help="Skip the up-front count used to verify the extract "
                                     "collected everything the endpoint reports")
    export_parser = subparsers.add_parser(
        "server-export",
        help="Ask the server to build the archive (the documented REST path)")
    export_parser.add_argument("--entity-type", dest="entity_type", default="images",
                               choices=["images", "hosts", "functions", "containers"])
    export_parser.add_argument("--running-only", action="store_true",
                               help="Only findings on images with running workloads")
    export_parser.add_argument("--severities", help="Comma-separated severities")
    export_parser.add_argument("--registry", help="Registry name filter")
    export_parser.add_argument("--cluster", help="Cluster filter")
    export_parser.add_argument("--namespaces", help="Comma-separated namespaces")
    export_parser.add_argument("--scope", help="Application scope")
    export_parser.add_argument("--output", help="Write the ZIP archive here")
    export_parser.add_argument("--csv", help="Also unpack the archive to this CSV")
    export_parser.add_argument("--exporter", default="Compressed CSV",
                               help="Name of an EXISTING exporter (default: Compressed CSV)")
    export_parser.add_argument("--columns-name", dest="columns_name",
                               default="aqua_recommended",
                               help="Named column set (default: aqua_recommended)")
    export_parser.add_argument("--columns",
                               help="Explicit comma-separated columns; overrides --columns-name")
    export_parser.add_argument("--list-columns", action="store_true",
                               help="List the selectable columns and exit")
    export_parser.add_argument("--list-exporters", dest="list_exporters",
                               action="store_true",
                               help="List the tenant's exporters and exit")
    export_parser.add_argument("--timeout", type=int, default=3600,
                               help="Seconds to wait for the archive (default: 3600)")

    extract_parser.add_argument("--fail-fast", action="store_true",
                                help="Abort on the first image that fails (default: skip and continue)")

    return parser


def parse_global_args(raw_args):
    """Extract -v/-d/-p from anywhere in the args, mirroring the other examples."""
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
        print(f"aqua_vuln_extract {__version__}")
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

    if args.command == "setup":
        if getattr(args, "profile_name", None):
            profile_name = args.profile_name
        elif args.profile != "default":
            profile_name = args.profile
        else:
            profile_name = None
        sys.exit(0 if interactive_setup(profile_name, debug=args.debug) else 1)

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
        msg = f"Authentication failed: {e}"
        print(msg if args.verbose else json.dumps({"error": msg}))
        sys.exit(1)

    # Falls back to the console URL carried in the token when CSP_ENDPOINT is unset.
    csp_endpoint = resolve_console_url(token, verbose=args.debug)
    if not csp_endpoint:
        msg = "Could not determine the console URL. Set CSP_ENDPOINT or re-run setup."
        print(f"Error: {msg}" if args.verbose else json.dumps({"error": msg}))
        sys.exit(1)

    handlers = {"estimate": cmd_estimate, "extract": cmd_extract,
                "server-export": cmd_server_export}
    handler = handlers[args.command]

    try:
        sys.exit(handler(csp_endpoint, token, args))
    except KeyboardInterrupt:
        print("\nInterrupted.")
        sys.exit(130)
    except Exception as e:
        if args.debug:
            import traceback
            traceback.print_exc()
        print(f"Error: {e}" if args.verbose else json.dumps({"error": str(e)}))
        sys.exit(1)


if __name__ == "__main__":
    main()
