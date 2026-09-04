"""Tests for the `license capabilities` command.

Covers the two things that can go wrong in the output layer: leaking the
enforcer registration token into an export, and folding enforcer types that
cannot run the capability into the totals.
"""

import csv
import io
import json
import os
import sys
from unittest.mock import patch

import pytest

# Add parent directories to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

import aqua_license_util
from aqua_license_util import license_capabilities

TOKEN = "ae3eb30e-9ffe-4cd5-bf2a-da2e80adaa0a"


def _group(group_type, host_av=False, connected=0, name="grp"):
    return {
        "id": name,
        "logicalname": name,
        "type": group_type,
        "antivirus_protection": host_av,
        "container_antivirus_protection": False,
        "connected_count": connected,
        "disconnected_count": 0,
        "hosts_count": connected,
        "aqua_version": "2601.5",
        "last_update": 1701702379,
        # Both of these carry the registration token.
        "token": TOKEN,
        "install_command": "docker run -e AQUA_TOKEN=%s ..." % TOKEN,
        "command": {"default": "docker run -e AQUA_TOKEN=%s ..." % TOKEN},
    }


GROUPS = [
    _group("host_enforcer", host_av=True, connected=1308, name="big-prod"),
    _group("host_enforcer", connected=100, name="no-amp"),
    _group("agent", host_av=True, connected=42, name="nodes"),
    _group("kube_enforcer", host_av=True, connected=9, name="kube-inert"),
    _group("micro_enforcer", host_av=True, connected=5, name="micro-inert"),
]


@pytest.fixture
def patched_groups():
    with patch.object(aqua_license_util, 'get_all_enforcer_groups', return_value=GROUPS):
        yield


def _run(capsys, **kwargs):
    license_capabilities("https://t.cloud.aquasec.com", "tok", **kwargs)
    return capsys.readouterr().out


class TestJsonOutput:

    def test_totals_exclude_inert_types(self, patched_groups, capsys):
        payload = json.loads(_run(capsys))
        # 1308 + 42; the kube and micro groups are not added in.
        assert payload["totals"]["connected_enabled"] == 1350
        assert payload["totals"]["connected_disabled"] == 100

    def test_excluded_types_are_reported(self, patched_groups, capsys):
        payload = json.loads(_run(capsys))
        assert payload["excluded_types"]["kube_enforcer"]["connected"] == 9
        assert payload["excluded_types"]["micro_enforcer"]["connected"] == 5

    def test_json_output_contains_no_token(self, patched_groups, capsys):
        assert TOKEN not in _run(capsys, by_group=True)

    def test_by_group_uses_the_export_allowlist(self, patched_groups, capsys):
        payload = json.loads(_run(capsys, by_group=True))
        names = [g["logicalname"] for g in payload["groups"]]
        assert names == ["big-prod", "nodes"]          # enabled only, largest first
        for entry in payload["groups"]:
            assert "token" not in entry
            assert "install_command" not in entry
            assert "command" not in entry

    def test_groups_absent_unless_requested(self, patched_groups, capsys):
        assert "groups" not in json.loads(_run(capsys))


class TestCsvExport:

    def test_csv_rows_and_total(self, patched_groups, capsys, tmp_path):
        target = tmp_path / "caps.csv"
        _run(capsys, csv_file=str(target))

        rows = list(csv.DictReader(io.StringIO(target.read_text())))
        by_type = {r["enforcer_type"]: r for r in rows}
        assert by_type["host_enforcer"]["with_capability"] == "1308"
        assert by_type["host_enforcer"]["without_capability"] == "100"
        assert by_type["agent"]["with_capability"] == "42"
        assert by_type["TOTAL"]["with_capability"] == "1350"
        # Inert types must not appear as rows at all.
        assert "kube_enforcer" not in by_type
        assert "micro_enforcer" not in by_type

    def test_by_group_writes_a_companion_groups_csv(self, patched_groups, capsys, tmp_path):
        target = tmp_path / "amp.csv"
        _run(capsys, csv_file=str(target), by_group=True)

        companion = tmp_path / "amp-groups.csv"
        assert companion.exists(), "--by-group must not be silently ignored for --csv-file"
        rows = list(csv.DictReader(io.StringIO(companion.read_text())))
        assert [r["logicalname"] for r in rows] == ["big-prod", "nodes"]
        assert "token" not in rows[0]
        assert TOKEN not in companion.read_text()

    def test_no_companion_csv_without_by_group(self, patched_groups, capsys, tmp_path):
        target = tmp_path / "amp.csv"
        _run(capsys, csv_file=str(target))
        assert not (tmp_path / "amp-groups.csv").exists()

    def test_csv_contains_no_token(self, patched_groups, capsys, tmp_path):
        target = tmp_path / "caps.csv"
        _run(capsys, csv_file=str(target), by_group=True)
        assert TOKEN not in target.read_text()

    def test_json_file_export_contains_no_token(self, patched_groups, capsys, tmp_path):
        target = tmp_path / "caps.json"
        _run(capsys, json_file=str(target), by_group=True)
        assert TOKEN not in target.read_text()


class TestTableOutput:

    def test_verbose_table_reports_utilization_and_exclusions(self, patched_groups, capsys):
        out = _run(capsys, verbose=True)
        assert "1,350" in out
        assert "93.1%" in out                       # 1350 / 1450 capable
        assert "cannot run this capability" in out
        assert "kube_enforcer (9)" in out


class TestCapabilityValidation:

    def test_unknown_capability_raises(self, patched_groups, capsys):
        with pytest.raises(ValueError):
            license_capabilities("https://t.cloud.aquasec.com", "tok",
                                 capability="behavioral_engine")
