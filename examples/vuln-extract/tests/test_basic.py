"""Basic tests: syntax, version, and global-arg parsing."""
import os
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import aqua_vuln_extract as ave


SCRIPT = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                      "aqua_vuln_extract.py")


def test_script_compiles():
    subprocess.run([sys.executable, "-m", "py_compile", SCRIPT], check=True)


def test_has_version():
    assert ave.__version__


def test_global_args_parsed_from_anywhere():
    """-v/-d/-p may appear before or after the subcommand."""
    globals_, rest = ave.parse_global_args(["extract", "-v", "-p", "prod", "--csv", "x.csv"])
    assert globals_["verbose"] is True
    assert globals_["profile"] == "prod"
    assert rest == ["extract", "--csv", "x.csv"]


def test_global_args_defaults():
    globals_, rest = ave.parse_global_args(["estimate"])
    assert globals_ == {"verbose": False, "debug": False, "profile": "default"}
    assert rest == ["estimate"]


def test_parser_exposes_both_extraction_routes():
    parser = ave.build_parser()
    args = parser.parse_args(["server-export", "--running-only"])
    assert args.command == "server-export"
    assert args.running_only is True

    args = parser.parse_args(["extract", "--workers", "16"])
    assert args.command == "extract"
    assert args.workers == 16


def test_server_export_defaults():
    args = ave.build_parser().parse_args(["server-export"])
    assert args.entity_type == "images"
    assert args.exporter == "Compressed CSV"
    assert args.columns_name == "aqua_recommended"
