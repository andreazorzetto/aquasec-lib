"""Tests for the containers module (running workload inventory)"""

import os
import sys
from unittest.mock import Mock, patch

# Add the parent directory to the path so we can import the aquasec module
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from aquasec.containers import (
    api_get_containers,
    get_container_count,
    get_all_containers,
    get_container_count_by_scope,
    container_key,
)


def _resp(status=200, payload=None):
    m = Mock()
    m.status_code = status
    m.json.return_value = payload if payload is not None else {}
    m.text = ""
    return m


class TestApiGetContainers:
    """Filters must travel as request params so they are URL-encoded."""

    @patch('aquasec.containers._request_with_retry')
    def test_scope_and_filters_passed_as_params(self, mock_req):
        mock_req.return_value = _resp(200, {"result": [], "count": 0})
        api_get_containers("https://t.aquasec.com", "tok", page=2, page_size=50,
                           scope="App Group", cluster="prod", namespace="web", status="running")

        args, kwargs = mock_req.call_args
        assert args[0] == 'GET'
        assert args[1] == "https://t.aquasec.com/api/v2/containers"
        p = kwargs['params']
        assert p['scope'] == "App Group"
        assert p['cluster'] == "prod"
        assert p['namespace'] == "web"
        assert p['status'] == "running"
        assert p['page'] == 2
        assert p['pagesize'] == 50

    @patch('aquasec.containers._request_with_retry')
    def test_no_filters_omits_optional_params(self, mock_req):
        mock_req.return_value = _resp(200, {"result": [], "count": 0})
        api_get_containers("https://t.aquasec.com", "tok")

        _, kwargs = mock_req.call_args
        p = kwargs['params']
        for key in ('scope', 'cluster', 'namespace', 'status'):
            assert key not in p


class TestContainerKey:
    def test_prefers_container_uid(self):
        assert container_key({"container_uid": "uid-1", "id": "id-1"}) == "uid-1"

    def test_falls_back_to_id(self):
        assert container_key({"id": "id-1"}) == "id-1"

    def test_none_when_missing(self):
        assert container_key({}) is None


class TestGetContainerCount:
    @patch('aquasec.containers.api_get_containers')
    def test_reads_count_field(self, mock_api):
        mock_api.return_value = _resp(200, {"count": 42, "result": []})
        assert get_container_count("s", "t") == 42

    @patch('aquasec.containers.api_get_containers')
    def test_non_200_returns_zero(self, mock_api):
        mock_api.return_value = _resp(403, {})
        assert get_container_count("s", "t") == 0


class TestGetAllContainers:
    @patch('aquasec.containers.api_get_containers')
    def test_paginates_until_complete(self, mock_api):
        # count=3 total, page size 2 -> two pages
        page1 = _resp(200, {"result": [{"id": "1"}, {"id": "2"}], "count": 3})
        page2 = _resp(200, {"result": [{"id": "3"}], "count": 3})
        mock_api.side_effect = [page1, page2]
        out = get_all_containers("s", "t", page_size=2)
        assert [c["id"] for c in out] == ["1", "2", "3"]
        assert mock_api.call_count == 2

    @patch('aquasec.containers.api_get_containers')
    def test_stops_on_empty_result(self, mock_api):
        mock_api.return_value = _resp(200, {"result": [], "count": 0})
        assert get_all_containers("s", "t") == []

    @patch('aquasec.containers.api_get_containers')
    def test_raises_on_error_status(self, mock_api):
        mock_api.return_value = _resp(500, {})
        try:
            get_all_containers("s", "t")
            assert False, "expected exception"
        except Exception as e:
            assert "500" in str(e)


class TestGetContainerCountByScope:
    @patch('aquasec.containers.get_container_count')
    def test_maps_each_scope(self, mock_count):
        mock_count.side_effect = [5, 0, 12]
        out = get_container_count_by_scope("s", "t", ["a", "b", "c"])
        assert out == {"a": 5, "b": 0, "c": 12}
