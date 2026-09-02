"""Tests for enforcer group capability reporting (licensed feature usage).

The load-bearing behaviour here is type gating: KubeEnforcer and MicroEnforcer
groups carry the AMP flags in their stored settings but cannot act on them, so
counting them overstates usage. Every count path must exclude them.
"""

import os
import sys
from unittest.mock import Mock, patch

import pytest

# Add the parent directory to the path so we can import the aquasec module
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from aquasec.enforcers import (
    AMP_CAPABLE_TYPES,
    CAPABILITIES,
    GROUP_EXPORT_FIELDS,
    SENSITIVE_GROUP_FIELDS,
    get_all_enforcer_groups,
    get_capability_rollup,
    get_enforcer_groups_with_capability,
    group_has_capability,
    group_supports_capability,
    redact_enforcer_group,
    resolve_capability,
)


def _group(group_type, host_av=False, container_av=False, connected=0,
           disconnected=0, hosts=0, name="grp"):
    return {
        "id": name,
        "logicalname": name,
        "type": group_type,
        "antivirus_protection": host_av,
        "container_antivirus_protection": container_av,
        "connected_count": connected,
        "disconnected_count": disconnected,
        "hosts_count": hosts,
        "token": "secret-token",
        "install_command": "docker run -e AQUA_TOKEN=secret-token ...",
    }


def _resp(status=200, payload=None):
    m = Mock()
    m.status_code = status
    m.json.return_value = payload if payload is not None else {}
    m.text = ""
    return m


class TestResolveCapability:
    """Unverified capabilities must fail loudly, not be counted generically."""

    def test_known_capabilities(self):
        assert resolve_capability("amp")["fields"] == (
            "antivirus_protection", "container_antivirus_protection")
        assert resolve_capability("antivirus_protection")["types"] == AMP_CAPABLE_TYPES

    def test_unknown_capability_raises(self):
        # behavioral_engine is a real group field, but which enforcer types act
        # on it has not been verified - it must not be silently reported.
        with pytest.raises(ValueError) as exc:
            resolve_capability("behavioral_engine")
        assert "behavioral_engine" in str(exc.value)

    def test_every_capability_declares_types_and_fields(self):
        for name, spec in CAPABILITIES.items():
            assert spec["types"], f"{name} has no applicable types"
            assert spec["fields"], f"{name} has no fields"
            assert spec["label"]


class TestTypeGating:
    """The regression that produced a wrong AMP total: inert flags counted."""

    def test_kube_enforcer_never_has_amp(self):
        # Both flags set, as they genuinely are on 21 groups in a live tenant.
        group = _group("kube_enforcer", host_av=True, container_av=True)
        assert group_supports_capability(group, "amp") is False
        assert group_has_capability(group, "amp") is False

    def test_micro_enforcer_never_has_amp(self):
        group = _group("micro_enforcer", host_av=True, container_av=True)
        assert group_supports_capability(group, "amp") is False
        assert group_has_capability(group, "amp") is False

    def test_vm_and_node_enforcers_do(self):
        assert group_has_capability(_group("host_enforcer", host_av=True), "amp") is True
        assert group_has_capability(_group("agent", container_av=True), "amp") is True

    def test_capable_type_with_flags_off(self):
        assert group_supports_capability(_group("host_enforcer"), "amp") is True
        assert group_has_capability(_group("host_enforcer"), "amp") is False


class TestAmpIsTheUnion:
    """Both controls draw on the same licence, so either one counts."""

    def test_host_only(self):
        assert group_has_capability(_group("agent", host_av=True), "amp") is True

    def test_container_only(self):
        assert group_has_capability(_group("agent", container_av=True), "amp") is True

    def test_narrower_capabilities_do_not_union(self):
        container_only = _group("agent", container_av=True)
        assert group_has_capability(container_only, "antivirus_protection") is False
        assert group_has_capability(container_only, "container_antivirus_protection") is True

    def test_non_boolean_truthy_is_not_enabled(self):
        # The API returns real booleans; a string must not read as enabled.
        group = _group("agent")
        group["antivirus_protection"] = "true"
        assert group_has_capability(group, "amp") is False


class TestRedaction:
    """Group objects carry the enforcer registration token."""

    def test_sensitive_fields_stripped(self):
        clean = redact_enforcer_group(_group("agent", host_av=True))
        for field in SENSITIVE_GROUP_FIELDS:
            assert field not in clean
        assert clean["logicalname"] == "grp"

    def test_export_allowlist_has_no_secrets(self):
        assert not set(GROUP_EXPORT_FIELDS) & set(SENSITIVE_GROUP_FIELDS)

    def test_no_export_field_leaks_a_token(self):
        group = _group("agent", host_av=True)
        exported = {f: group.get(f) for f in GROUP_EXPORT_FIELDS}
        assert "secret-token" not in str(exported)


class TestCapabilityRollup:

    def _groups(self):
        return [
            _group("host_enforcer", host_av=True, connected=100, disconnected=5, hosts=105),
            _group("host_enforcer", connected=50, disconnected=1, hosts=51),
            _group("agent", container_av=True, connected=10, hosts=10),
            # Inert: flags set but the type cannot act on them.
            _group("kube_enforcer", host_av=True, container_av=True, connected=7),
            _group("micro_enforcer", host_av=True, connected=3),
        ]

    def test_totals_exclude_incapable_types(self):
        rollup = get_capability_rollup("s", "t", "amp", groups=self._groups())
        assert rollup["totals"]["connected_enabled"] == 110    # 100 + 10, not 120
        assert rollup["totals"]["connected_disabled"] == 50
        assert rollup["totals"]["groups_enabled"] == 2

    def test_incapable_types_reported_separately(self):
        rollup = get_capability_rollup("s", "t", "amp", groups=self._groups())
        assert rollup["excluded_types"]["kube_enforcer"] == {"groups": 1, "connected": 7}
        assert rollup["excluded_types"]["micro_enforcer"] == {"groups": 1, "connected": 3}
        assert "host_enforcer" not in rollup["excluded_types"]

    def test_utilization_is_over_capable_estate_only(self):
        rollup = get_capability_rollup("s", "t", "amp", groups=self._groups())
        # 110 of 160 capable connected, NOT of the 170 total estate.
        assert rollup["utilization_pct"] == 68.8

    def test_per_type_breakdown(self):
        rollup = get_capability_rollup("s", "t", "amp", groups=self._groups())
        host = rollup["by_type"]["host_enforcer"]
        assert host["connected_enabled"] == 100
        assert host["connected_disabled"] == 50
        assert host["disconnected_enabled"] == 5
        assert host["registered_enabled"] == 105

    def test_empty_estate_has_no_utilization(self):
        rollup = get_capability_rollup("s", "t", "amp", groups=[])
        assert rollup["utilization_pct"] is None
        assert rollup["totals"]["connected_enabled"] == 0

    def test_empty_estate_verbose_does_not_print_na_percent(self, capsys):
        get_capability_rollup("s", "t", "amp", groups=[], verbose=True)
        out = capsys.readouterr().out
        assert "n/a" in out
        assert "n/a%" not in out

    def test_missing_count_fields_treated_as_zero(self):
        rollup = get_capability_rollup("s", "t", "amp", groups=[
            {"type": "agent", "antivirus_protection": True},
        ])
        assert rollup["totals"]["connected_enabled"] == 0
        assert rollup["totals"]["groups_enabled"] == 1

    def test_metadata_describes_the_question(self):
        rollup = get_capability_rollup("s", "t", "amp", groups=self._groups())
        assert rollup["capability"] == "amp"
        assert rollup["label"] == "Advanced Malware Protection"
        assert sorted(rollup["capable_types"]) == ["agent", "host_enforcer"]

    def test_unknown_capability_raises_before_fetching(self):
        with pytest.raises(ValueError):
            get_capability_rollup("s", "t", "no_such_capability", groups=[])


class TestGroupsWithCapability:

    def test_filters_to_capable_types_in_both_directions(self):
        groups = [
            _group("host_enforcer", host_av=True, name="on"),
            _group("host_enforcer", name="off"),
            _group("kube_enforcer", host_av=True, name="inert"),
        ]
        on = get_enforcer_groups_with_capability("s", "t", "amp", enabled=True, groups=groups)
        off = get_enforcer_groups_with_capability("s", "t", "amp", enabled=False, groups=groups)

        assert [g["logicalname"] for g in on] == ["on"]
        # The KubeEnforcer group is out of scope entirely, not "without AMP".
        assert [g["logicalname"] for g in off] == ["off"]


class TestFetching:

    @patch('aquasec.enforcers.api_get_enforcer_groups')
    def test_get_all_enforcer_groups_paginates(self, mock_api):
        mock_api.side_effect = [
            _resp(200, {"count": 3, "result": [_group("agent"), _group("agent")]}),
            _resp(200, {"count": 3, "result": [_group("agent")]}),
            _resp(200, {"count": 3, "result": []}),
        ]
        groups = get_all_enforcer_groups("https://t.aquasec.com", "tok")
        assert len(groups) == 3

    @patch('aquasec.enforcers.api_get_enforcer_groups')
    def test_non_200_raises_rather_than_exiting(self, mock_api):
        # get_enforcer_groups() calls sys.exit() on an API error, which a caller
        # cannot intercept with `except Exception` - so structured output would be
        # replaced by a bare English line and exit 1. This paginator must raise.
        mock_api.return_value = _resp(403, {})
        mock_api.return_value.text = "forbidden"

        with pytest.raises(Exception) as exc:
            get_all_enforcer_groups("https://t.aquasec.com", "tok")
        assert not isinstance(exc.value, SystemExit)
        assert "403" in str(exc.value)

    @patch('aquasec.enforcers.api_get_enforcer_groups')
    def test_rollup_propagates_api_errors(self, mock_api):
        mock_api.return_value = _resp(500, {})
        mock_api.return_value.text = "boom"
        with pytest.raises(Exception) as exc:
            get_capability_rollup("https://t.aquasec.com", "tok", "amp")
        assert not isinstance(exc.value, SystemExit)

    @patch('aquasec.enforcers.api_get_enforcer_groups')
    def test_rollup_fetches_when_groups_not_supplied(self, mock_api):
        mock_api.side_effect = [
            _resp(200, {"count": 1, "result": [
                _group("host_enforcer", host_av=True, connected=4)]}),
            _resp(200, {"count": 1, "result": []}),
        ]
        rollup = get_capability_rollup("https://t.aquasec.com", "tok", "amp")
        assert rollup["totals"]["connected_enabled"] == 4
