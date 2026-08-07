"""Tests for the command handlers, with the library mocked out."""
import os
import sys
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import aqua_vuln_extract as ave


def _args(command, **overrides):
    args = ave.build_parser().parse_args([command])
    args.verbose = False
    args.debug = False
    args.profile = "default"
    for key, value in overrides.items():
        setattr(args, key, value)
    return args


class TestServerExport:
    @patch("aqua_vuln_extract.extract_export_csv")
    @patch("aqua_vuln_extract.export_vulnerabilities")
    def test_builds_filters_from_flags(self, mock_export, mock_csv, tmp_path):
        mock_export.return_value = b"PK\x03\x04"
        mock_csv.return_value = 5
        args = _args("server-export", running_only=True, severities="critical,high",
                     cluster="prod", namespaces="web, api",
                     output=str(tmp_path / "o.zip"), csv=str(tmp_path / "o.csv"))

        assert ave.cmd_server_export("https://t", "tok", args) == 0

        filters = mock_export.call_args[1]["filters"]
        assert filters["has_workloads"] == "true"
        assert filters["severities"] == ["critical", "high"]
        assert filters["cluster"] == "prod"
        # Whitespace around a comma-separated value must not leak into the filter.
        assert filters["namespace_names"] == ["web", "api"]

    @patch("aqua_vuln_extract.extract_export_csv")
    @patch("aqua_vuln_extract.export_vulnerabilities")
    def test_no_filters_sends_none(self, mock_export, mock_csv, tmp_path):
        mock_export.return_value = b"PK\x03\x04"
        args = _args("server-export", output=str(tmp_path / "o.zip"), csv=None)

        ave.cmd_server_export("https://t", "tok", args)
        assert mock_export.call_args[1]["filters"] is None
        assert not mock_csv.called

    @patch("aqua_vuln_extract.extract_export_csv")
    @patch("aqua_vuln_extract.export_vulnerabilities")
    def test_streams_csv_rather_than_parsing(self, mock_export, mock_csv, tmp_path):
        """An estate-sized archive must never be materialised in memory."""
        mock_export.return_value = b"PK\x03\x04"
        mock_csv.return_value = 2_106_800
        out = str(tmp_path / "o.csv")
        args = _args("server-export", output=str(tmp_path / "o.zip"), csv=out)

        ave.cmd_server_export("https://t", "tok", args)
        assert mock_csv.call_args[0][1] == out

    @patch("aqua_vuln_extract.get_available_columns")
    def test_list_columns_short_circuits(self, mock_cols, capsys):
        mock_cols.return_value = {"epss_score": "EPSS Score"}
        args = _args("server-export", list_columns=True)

        assert ave.cmd_server_export("https://t", "tok", args) == 0
        assert "epss_score" in capsys.readouterr().out


class TestExtract:
    @patch("aqua_vuln_extract.get_vulnerability_count")
    @patch("aqua_vuln_extract.iter_all_vulnerabilities")
    def test_reconciles_against_the_endpoint_count(self, mock_iter, mock_count, tmp_path):
        mock_count.return_value = 2
        mock_iter.return_value = [({"registry": "r", "name": "a", "digest": "d"},
                                   [{"name": "CVE-1"}, {"name": "CVE-2"}])]
        args = _args("extract", csv=str(tmp_path / "o.csv"), jsonl=None)

        assert ave.cmd_extract("https://t", "tok", args) == 0
        assert mock_count.called

    @patch("aqua_vuln_extract.get_vulnerability_count")
    @patch("aqua_vuln_extract.iter_all_vulnerabilities")
    def test_no_reconcile_skips_the_count(self, mock_iter, mock_count, tmp_path):
        mock_iter.return_value = []
        args = _args("extract", csv=str(tmp_path / "o.csv"), jsonl=None,
                     no_reconcile=True)

        ave.cmd_extract("https://t", "tok", args)
        assert not mock_count.called
