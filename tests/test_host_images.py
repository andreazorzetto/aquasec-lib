"""Tests for host_images module (images discovered on hosts/VMs by enforcers)"""

import os
import sys
from unittest.mock import Mock, patch

# Add the parent directory to the path so we can import the aquasec module
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from aquasec.host_images import (
    api_get_host_images,
    get_host_image_count,
    extract_repo_base,
    get_all_host_images,
    get_host_image_repos,
    get_host_image_repo_count_by_scope,
)


def _resp(status=200, payload=None):
    m = Mock()
    m.status_code = status
    m.json.return_value = payload if payload is not None else {}
    m.text = ""
    return m


class TestExtractRepoBase:
    """The repo base name is the licensing unit; tag/digest must be stripped."""

    def test_simple_tag(self):
        assert extract_repo_base("caddy:latest") == "caddy"

    def test_digest_reference(self):
        assert extract_repo_base("caddy@sha256:abc123") == "caddy"

    def test_registry_prefix_with_tag(self):
        assert extract_repo_base("registry.aquasec.com/enforcer:2022.4") == "registry.aquasec.com/enforcer"

    def test_registry_port_is_preserved(self):
        # The port colon must NOT be mistaken for a tag separator
        assert extract_repo_base("192.168.49.2:32736/my-app/alpine:latest") == "192.168.49.2:32736/my-app/alpine"

    def test_digest_on_namespaced_repo(self):
        assert extract_repo_base("andreazorzetto/enhanced-me@sha256:deadbeef") == "andreazorzetto/enhanced-me"

    def test_numeric_tag(self):
        assert extract_repo_base("registry:2") == "registry"

    def test_no_tag(self):
        assert extract_repo_base("nginx") == "nginx"

    def test_empty_and_none_passthrough(self):
        assert extract_repo_base("") == ""
        assert extract_repo_base(None) is None


class TestApiGetHostImages:
    """The scope filter must travel as a request param so it is URL-encoded."""

    @patch('aquasec.host_images._request_with_retry')
    def test_scope_passed_as_param(self, mock_req):
        mock_req.return_value = _resp(200, {"result": [], "count": 0})
        api_get_host_images("https://t.aquasec.com", "tok", page=1, page_size=50, scope="App Group")

        args, kwargs = mock_req.call_args
        assert args[0] == 'GET'
        assert args[1] == "https://t.aquasec.com/api/v1/hosts/images"
        assert kwargs['params']['scope'] == "App Group"
        assert kwargs['params']['page'] == 1
        assert kwargs['params']['pagesize'] == 50

    @patch('aquasec.host_images._request_with_retry')
    def test_no_scope_omits_param(self, mock_req):
        mock_req.return_value = _resp(200, {"result": [], "count": 0})
        api_get_host_images("https://t.aquasec.com", "tok")
        assert 'scope' not in mock_req.call_args.kwargs['params']


class TestGetHostImageCount:

    @patch('aquasec.host_images._request_with_retry')
    def test_returns_count_field(self, mock_req):
        mock_req.return_value = _resp(200, {"result": [{}], "count": 55})
        assert get_host_image_count("https://t.aquasec.com", "tok") == 55

    @patch('aquasec.host_images._request_with_retry')
    def test_error_returns_zero(self, mock_req):
        mock_req.return_value = _resp(500, {})
        assert get_host_image_count("https://t.aquasec.com", "tok") == 0


class TestGetAllHostImages:

    @patch('aquasec.host_images._request_with_retry')
    def test_paginates_until_count_reached(self, mock_req):
        page1 = _resp(200, {"result": [{"name": f"img{i}:latest"} for i in range(200)], "count": 250})
        page2 = _resp(200, {"result": [{"name": f"img{i}:latest"} for i in range(50)], "count": 250})
        mock_req.side_effect = [page1, page2]

        images = get_all_host_images("https://t.aquasec.com", "tok")
        assert len(images) == 250
        assert mock_req.call_count == 2

    @patch('aquasec.host_images._request_with_retry')
    def test_empty_result_stops(self, mock_req):
        mock_req.return_value = _resp(200, {"result": [], "count": 0})
        assert get_all_host_images("https://t.aquasec.com", "tok") == []


class TestRepoCounting:
    """Counting by repo collapses tags/digests of the same repository."""

    SAMPLE = [
        {"name": "caddy:latest"},
        {"name": "caddy@sha256:aaa"},          # same repo as above -> dedup
        {"name": "caddy@sha256:bbb"},          # same repo -> dedup
        {"name": "registry.aquasec.com/enforcer:2022.4"},
        {"name": "registry.aquasec.com/enforcer:10"},   # same repo, diff tag -> dedup
        {"name": "nginx:latest"},
        {"name": ""},                          # ignored
        {"name": None},                        # ignored
    ]

    @patch('aquasec.host_images.get_all_host_images')
    def test_get_host_image_repos_dedups(self, mock_all):
        mock_all.return_value = self.SAMPLE
        repos = get_host_image_repos("https://t.aquasec.com", "tok", scope="Test-1")
        assert repos == ["caddy", "nginx", "registry.aquasec.com/enforcer"]

    @patch('aquasec.host_images.get_all_host_images')
    def test_repo_count_by_scope(self, mock_all):
        def fake(server, token, scope=None, verbose=False):
            return self.SAMPLE if scope == "Test-1" else []
        mock_all.side_effect = fake

        counts = get_host_image_repo_count_by_scope(
            "https://t.aquasec.com", "tok", ["Test-1", "Empty-Scope"])
        assert counts == {"Test-1": 3, "Empty-Scope": 0}

    @patch('aquasec.host_images.get_all_host_images')
    def test_repo_count_handles_scope_error(self, mock_all):
        mock_all.side_effect = Exception("boom")
        counts = get_host_image_repo_count_by_scope("https://t.aquasec.com", "tok", ["X"])
        assert counts == {"X": 0}
