"""Tests for `license count` — the merged licence + AMP table.

Two behaviours are load-bearing here: no utilisation percentage is printed (the
limit a row is divided by is a licensing question, and a percentage against the
wrong denominator reads as authoritative), and the AMP column distinguishes
"no AMP" from "cannot run AMP".
"""

import json
import os
import sys
from unittest.mock import patch

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

import aqua_license_util
from aqua_license_util import license_count

LICENCES = {
    "num_repositories": 5900,
    "num_enforcers": -1,
    "num_microenforcers": 1180,
    "num_vm_enforcers": 11900,
    "num_functions": 12900,
    "num_code_repositories": -1,
    "num_protected_kube_nodes": 1180,
    "malware_protection": True,
    "num_active": 1,
}

ENFORCERS = {
    "agent": 520, "kube_enforcer": 41, "host_enforcer": 4591,
    "micro_enforcer": 1416, "nano_enforcer": 0, "pod_enforcer": 0,
}

ROLLUP = {
    "capability": "amp",
    "label": "Advanced Malware Protection",
    "utilization_pct": 67.7,
    "by_type": {
        "agent": {"connected_enabled": 520, "connected_disabled": 0},
        "host_enforcer": {"connected_enabled": 2939, "connected_disabled": 1651},
    },
    "totals": {"connected_enabled": 3459, "connected_disabled": 1651},
    "excluded_types": {
        "kube_enforcer": {"groups": 186, "connected": 41},
        "micro_enforcer": {"groups": 296, "connected": 1416},
    },
}


@pytest.fixture
def patched():
    with patch.object(aqua_license_util, 'get_licences', return_value=LICENCES), \
         patch.object(aqua_license_util, 'get_function_count', return_value=16528), \
         patch.object(aqua_license_util, 'get_capability_rollup', return_value=ROLLUP), \
         patch('aquasec.get_repo_count', return_value=3344), \
         patch('aquasec.get_code_repo_count', return_value=562), \
         patch('aquasec.get_enforcer_count', return_value=ENFORCERS):
        yield


def _run(capsys, **kwargs):
    license_count("https://t.cloud.aquasec.com", "tok", **kwargs)
    return capsys.readouterr().out


class TestNoPercentages:
    """A percentage against a questionable denominator reads as authoritative."""

    def test_table_has_no_utilization_column(self, patched, capsys):
        out = _run(capsys, verbose=True)
        assert "Utilization" not in out

    def test_no_percentage_against_a_licence_limit(self, patched, capsys):
        out = _run(capsys, verbose=True)
        # 520/1180 = 44.1%, the figure that was being printed against
        # num_protected_kube_nodes rather than num_enforcers (unlimited).
        assert "44.1%" not in out

    def test_limit_and_used_are_both_still_shown(self, patched, capsys):
        out = _run(capsys, verbose=True)
        assert "11,900" in out and "4,591" in out
        assert "Unlimited" in out          # num_enforcers / num_code_repositories == -1


class TestAmpColumn:

    def test_amp_counts_on_capable_rows(self, patched, capsys):
        out = _run(capsys, verbose=True)
        assert "With AMP" in out
        assert "2,939" in out              # VM enforcers with AMP
        assert "520" in out                # every Aqua enforcer

    def test_incapable_rows_say_na_not_zero(self, patched, capsys):
        out = _run(capsys, verbose=True)
        # "n/a" and 0 mean different things: Kube/Micro cannot run AMP at all.
        kube_row = [l for l in out.splitlines() if "Kube Enforcers" in l][0]
        micro_row = [l for l in out.splitlines() if "Micro Enforcers" in l][0]
        assert "n/a" in kube_row
        assert "n/a" in micro_row

    def test_non_enforcer_rows_are_blank(self, patched, capsys):
        out = _run(capsys, verbose=True)
        repo_row = [l for l in out.splitlines() if "Image Repositories" in l][0]
        assert repo_row.rstrip().endswith("- |")

    def test_footnote_explains_coverage_and_entitlement(self, patched, capsys):
        out = _run(capsys, verbose=True)
        assert "3,459 of 5,110 capable enforcers (67.7%)" in out
        assert "not a seat count" in out


class TestNoAmpFlag:

    def test_column_absent(self, patched, capsys):
        out = _run(capsys, verbose=True, include_amp=False)
        assert "With AMP" not in out
        assert "Utilization" not in out
        assert "4,591" in out

    def test_rollup_not_fetched(self, patched, capsys):
        _run(capsys, verbose=True, include_amp=False)
        aqua_license_util.get_capability_rollup.assert_not_called()

    def test_amp_failure_does_not_break_the_table(self, patched, capsys):
        with patch.object(aqua_license_util, 'get_capability_rollup',
                          side_effect=Exception("403")):
            out = _run(capsys, verbose=True)
        assert "4,591" in out              # licence counts still render


class TestJsonOutput:

    def test_amp_block_present(self, patched, capsys):
        payload = json.loads(_run(capsys))
        amp = payload["advanced_malware_protection"]
        assert amp["enforcers"] == 3459
        assert amp["capable_enforcers"] == 5110
        assert amp["by_type"] == {"agent": 520, "host_enforcer": 2939}
        assert amp["not_capable"] == {"kube_enforcer": 41, "micro_enforcer": 1416}

    def test_amp_block_absent_when_skipped(self, patched, capsys):
        payload = json.loads(_run(capsys, include_amp=False))
        assert "advanced_malware_protection" not in payload
        assert payload["usage"]["vm_enforcers"] == 4591
