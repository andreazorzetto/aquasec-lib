"""Tests for the exports module (CNAPP scheduled export service)"""

import os
import sys
from unittest.mock import Mock, patch

# Add the parent directory to the path so we can import the aquasec module
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from aquasec.exports import (
    DEFAULT_REGION,
    resolve_region,
    get_export_base_url,
    api_create_export,
    api_delete_exports,
    api_set_export_active,
    get_exports,
    get_export_capacity,
    get_export_entities,
    get_integrations,
    create_export,
)

BASE = "https://eu-central-1.edge.cloud.aquasec.com/cnapp/export"


def _resp(status=200, payload=None):
    m = Mock()
    m.status_code = status
    m.json.return_value = payload if payload is not None else {}
    m.text = ""
    return m


class TestResolveRegion:
    """The export service lives on a regional host, unlike the tenant console."""

    def test_env_wins(self, monkeypatch):
        monkeypatch.setenv("AQUA_REGION", "ap-southeast-2")
        assert resolve_region("tok") == "ap-southeast-2"

    @patch('aquasec.exports.decode_token_claims')
    def test_maps_regional_prefix_from_token(self, mock_claims, monkeypatch):
        monkeypatch.delenv("AQUA_REGION", raising=False)
        mock_claims.return_value = {"cspm_url": "https://eu-1.cloud.aquasec.com"}
        assert resolve_region("tok") == "eu-central-1"

    @patch('aquasec.exports.decode_token_claims')
    def test_unprefixed_host_is_the_us_region(self, mock_claims, monkeypatch):
        monkeypatch.delenv("AQUA_REGION", raising=False)
        mock_claims.return_value = {"cspm_url": "https://cloud.aquasec.com"}
        assert resolve_region("tok") == DEFAULT_REGION

    @patch('aquasec.exports.decode_token_claims')
    def test_falls_back_to_aqua_endpoint(self, mock_claims, monkeypatch):
        monkeypatch.delenv("AQUA_REGION", raising=False)
        monkeypatch.setenv("AQUA_ENDPOINT", "https://asia-1.api.cloudsploit.com")
        mock_claims.return_value = {}
        assert resolve_region("tok") == "ap-southeast-1"

    @patch('aquasec.exports.decode_token_claims')
    def test_tolerates_token_without_claims(self, mock_claims, monkeypatch):
        monkeypatch.delenv("AQUA_REGION", raising=False)
        monkeypatch.delenv("AQUA_ENDPOINT", raising=False)
        mock_claims.side_effect = Exception("not a JWT")
        assert resolve_region("tok") is None


class TestExportBaseUrl:
    def test_builds_regional_host(self):
        assert get_export_base_url(region="eu-central-1") == BASE

    def test_raises_when_region_unknown(self, monkeypatch):
        monkeypatch.delenv("AQUA_REGION", raising=False)
        monkeypatch.delenv("AQUA_ENDPOINT", raising=False)
        try:
            get_export_base_url()
        except ValueError as e:
            assert "region" in str(e).lower()
        else:
            raise AssertionError("expected a ValueError")


class TestCreateExport:
    @patch('aquasec.exports._request_with_retry')
    def test_posts_expected_payload(self, mock_req):
        mock_req.return_value = _resp(201, {"export_id": "abc"})
        api_create_export(BASE, "tok", name="nightly", integration_id="int-1",
                          entity_type="vulnerabilities", filter_name="All",
                          frequency="daily", export_format="csv")

        args, kwargs = mock_req.call_args
        assert args[0] == 'POST'
        assert args[1] == f"{BASE}/api/v1/exports"
        p = kwargs['json']
        assert p['name'] == "nightly"
        assert p['integration_id'] == "int-1"
        assert p['entity_type'] == "vulnerabilities"
        assert p['filter_name'] == "All"
        assert p['frequency'] == "daily"
        assert p['format'] == "csv"

    @patch('aquasec.exports.get_export_capacity')
    @patch('aquasec.exports.api_create_export')
    def test_returns_export_id(self, mock_create, mock_cap):
        mock_cap.return_value = (2, 5)
        mock_create.return_value = _resp(201, {"export_id": "exp-123"})
        assert create_export(BASE, "tok", "nightly", "int-1") == "exp-123"

    @patch('aquasec.exports.get_export_capacity')
    @patch('aquasec.exports.api_create_export')
    def test_refuses_when_at_capacity(self, mock_create, mock_cap):
        """The cap is low and a bare 429 does not explain itself."""
        mock_cap.return_value = (5, 5)
        try:
            create_export(BASE, "tok", "nightly", "int-1")
        except Exception as e:
            assert "limit (5/5)" in str(e)
        else:
            raise AssertionError("expected the create to be refused")
        assert not mock_create.called

    @patch('aquasec.exports.get_export_capacity')
    @patch('aquasec.exports.api_create_export')
    def test_explains_known_failures(self, mock_create, mock_cap):
        mock_cap.return_value = (1, 5)
        for status, phrase in ((404, "integration was not found"),
                               (409, "name already exists"),
                               (429, "active-export limit")):
            mock_create.return_value = _resp(status, {})
            try:
                create_export(BASE, "tok", "nightly", "int-1")
            except Exception as e:
                assert phrase in str(e), f"{status} -> {e}"
            else:
                raise AssertionError(f"expected {status} to raise")

    @patch('aquasec.exports.get_export_capacity')
    @patch('aquasec.exports.api_create_export')
    def test_can_skip_the_capacity_check(self, mock_create, mock_cap):
        mock_create.return_value = _resp(201, {"export_id": "exp-1"})
        create_export(BASE, "tok", "nightly", "int-1", check_capacity=False)
        assert not mock_cap.called


class TestReadHelpers:
    @patch('aquasec.exports._request_with_retry')
    def test_capacity_reads_active_and_limit(self, mock_req):
        mock_req.return_value = _resp(200, {"data": {"exports_active_amount": 5,
                                                     "exports_active_limit": 5}})
        assert get_export_capacity(BASE, "tok") == (5, 5)

    @patch('aquasec.exports._request_with_retry')
    def test_exports_returns_data_list(self, mock_req):
        mock_req.return_value = _resp(200, {"data": [{"id": "a"}, {"id": "b"}]})
        assert len(get_exports(BASE, "tok")) == 2

    @patch('aquasec.exports._request_with_retry')
    def test_exports_raises_on_failure(self, mock_req):
        mock_req.return_value = _resp(500, {})
        try:
            get_exports(BASE, "tok")
        except Exception as e:
            assert "Failed to list exports" in str(e)
        else:
            raise AssertionError("expected an error")

    @patch('aquasec.exports._request_with_retry')
    def test_entities_expose_saved_filter_names(self, mock_req):
        """Filters are server-defined; callers must not invent filter names."""
        mock_req.return_value = _resp(200, {"data": {"resources": [
            {"label": "vulnerabilities", "name": "Image Vulnerabilities",
             "data_columns": ["CVE"], "saved_filters": [{"name": "All"}]},
            {"label": "containers", "name": "Containers",
             "data_columns": [], "saved_filters": []},
        ]}})
        entities = get_export_entities(BASE, "tok")

        assert entities["vulnerabilities"]["saved_filters"] == ["All"]
        assert entities["vulnerabilities"]["name"] == "Image Vulnerabilities"
        assert entities["containers"]["saved_filters"] == []

    @patch('aquasec.exports._request_with_retry')
    def test_can_filter_to_working_integrations(self, mock_req):
        """A failed integration still accepts an export, then fails every run."""
        mock_req.return_value = _resp(200, {"data": [
            {"id": "ok", "status": "succeeded"},
            {"id": "broken", "status": "failed"},
        ]})
        assert len(get_integrations(BASE, "tok")) == 2
        working = get_integrations(BASE, "tok", only_working=True)
        assert [i["id"] for i in working] == ["ok"]


class TestMutations:
    @patch('aquasec.exports._request_with_retry')
    def test_delete_posts_ids(self, mock_req):
        mock_req.return_value = _resp(200, {})
        api_delete_exports(BASE, "tok", ["a", "b"])

        args, kwargs = mock_req.call_args
        assert args[0] == 'POST'
        assert args[1] == f"{BASE}/api/v1/exports/delete"
        assert kwargs['json'] == {"ids": ["a", "b"]}

    @patch('aquasec.exports._request_with_retry')
    def test_activity_status_uses_put(self, mock_req):
        mock_req.return_value = _resp(200, {})
        api_set_export_active(BASE, "tok", "exp-1", False)

        args, kwargs = mock_req.call_args
        assert args[0] == 'PUT'
        assert args[1] == f"{BASE}/api/v1/exports/exp-1/activity-status"
        assert kwargs['json'] == {"is_active": False}
