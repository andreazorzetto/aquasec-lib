"""Tests for the vulnerabilities module (per-image extraction)"""

import csv
import os
import sys
from unittest.mock import Mock, patch

# Add the parent directory to the path so we can import the aquasec module
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from aquasec.vulnerabilities import (
    CSV_COLUMNS,
    api_get_vulnerabilities,
    get_vulnerability_count,
    image_ref,
    get_image_vulnerabilities,
    iter_all_vulnerabilities,
    get_all_vulnerabilities,
    finding_key,
    unique_cves,
    summarise_by_image,
    vulnerability_to_row,
    write_vulnerabilities_csv,
    write_image_summary_csv,
    write_unique_cves_csv,
)


def _resp(status=200, payload=None):
    m = Mock()
    m.status_code = status
    m.json.return_value = payload if payload is not None else {}
    m.text = ""
    return m


class TestApiGetVulnerabilities:
    """Filters must travel as request params so they are URL-encoded."""

    @patch('aquasec.vulnerabilities._request_with_retry')
    def test_filters_passed_as_params(self, mock_req):
        mock_req.return_value = _resp(200, {"result": []})
        api_get_vulnerabilities("https://t.aquasec.com", "tok", page=3, page_size=500,
                                scope="App Group", image_name="repo/app:1.0",
                                registry_name="My Registry", severities=["critical", "high"],
                                cluster="prod", namespaces=["web", "api"],
                                has_workloads=True, acknowledged=False)

        args, kwargs = mock_req.call_args
        assert args[0] == 'GET'
        assert args[1] == "https://t.aquasec.com/api/v2/risks/vulnerabilities"
        p = kwargs['params']
        assert p['page'] == 3
        assert p['pagesize'] == 500
        assert p['scope'] == "App Group"
        assert p['image_name'] == "repo/app:1.0"
        assert p['image_name_exact_match'] == "true"
        assert p['registry_name'] == "My Registry"
        assert p['severities'] == "critical,high"
        assert p['cluster'] == "prod"
        assert p['namespace_names'] == "web,api"
        assert p['has_workloads'] == "true"
        assert p['acknowledge_status'] == "false"

    @patch('aquasec.vulnerabilities._request_with_retry')
    def test_skips_count_by_default(self, mock_req):
        """Counting is a separate aggregate; a paginating caller must not pay for it."""
        mock_req.return_value = _resp(200, {"result": []})
        api_get_vulnerabilities("https://t.aquasec.com", "tok")

        assert mock_req.call_args[1]['params']['skip_count'] == "true"

    @patch('aquasec.vulnerabilities._request_with_retry')
    def test_no_filters_omits_optional_params(self, mock_req):
        mock_req.return_value = _resp(200, {"result": []})
        api_get_vulnerabilities("https://t.aquasec.com", "tok")

        p = mock_req.call_args[1]['params']
        for key in ('scope', 'image_name', 'registry_name', 'digest', 'severities',
                    'cluster', 'namespace_names', 'has_workloads', 'acknowledge_status'):
            assert key not in p

    @patch('aquasec.vulnerabilities._request_with_retry')
    def test_severities_accepts_plain_string(self, mock_req):
        mock_req.return_value = _resp(200, {"result": []})
        api_get_vulnerabilities("https://t.aquasec.com", "tok", severities="critical")

        assert mock_req.call_args[1]['params']['severities'] == "critical"


class TestGetVulnerabilityCount:
    @patch('aquasec.vulnerabilities._request_with_retry')
    def test_requests_the_count(self, mock_req):
        mock_req.return_value = _resp(200, {"count": 436000, "result": []})
        assert get_vulnerability_count("https://t.aquasec.com", "tok", scope="gcp") == 436000

        p = mock_req.call_args[1]['params']
        assert p['skip_count'] == "false"
        assert p['pagesize'] == 1
        assert p['scope'] == "gcp"

    @patch('aquasec.vulnerabilities._request_with_retry')
    def test_returns_zero_on_failure(self, mock_req):
        mock_req.return_value = _resp(500, {})
        assert get_vulnerability_count("https://t.aquasec.com", "tok") == 0


class TestImageRef:
    def test_prefers_digest_and_keeps_registry(self):
        ref = image_ref({"registry": "reg", "name": "repo/app:1.0", "digest": "sha256:abc"})
        assert ref["digest"] == "sha256:abc"
        assert ref["registry_name"] == "reg"
        assert ref["image_name"] == "repo/app:1.0"
        assert ref["exact_match"] is True

    def test_falls_back_to_registry_and_name(self):
        ref = image_ref({"registry": "reg", "name": "repo/app:1.0"})
        assert "digest" not in ref
        assert ref["image_name"] == "repo/app:1.0"
        assert ref["label"] == "reg/repo/app:1.0"

    def test_joins_separate_repository_and_tag(self):
        ref = image_ref({"registry": "reg", "repository": "repo/app", "tag": "1.0"})
        assert ref["image_name"] == "repo/app:1.0"

    def test_does_not_double_up_tag_already_in_name(self):
        ref = image_ref({"registry": "reg", "name": "repo/app:1.0", "tag": "1.0"})
        assert ref["image_name"] == "repo/app:1.0"

    def test_accepts_alternate_field_names(self):
        ref = image_ref({"registry_name": "reg", "image_name": "repo/app:1.0"})
        assert ref["registry_name"] == "reg"
        assert ref["image_name"] == "repo/app:1.0"

    def test_returns_empty_when_unidentifiable(self):
        assert image_ref({"unrelated": "value"}) == {}


class TestGetImageVulnerabilities:
    @patch('aquasec.vulnerabilities.api_get_vulnerabilities')
    def test_paginates_until_empty_page(self, mock_api):
        """A short page must not end the walk: some filters apply after pagination."""
        mock_api.side_effect = [
            _resp(200, {"result": [{"name": f"CVE-{i}"} for i in range(500)]}),
            _resp(200, {"result": [{"name": "CVE-short-page"}]}),
            _resp(200, {"result": [{"name": "CVE-after-short-page"}]}),
            _resp(200, {"result": []}),
        ]
        vulns = get_image_vulnerabilities("https://t.aquasec.com", "tok",
                                          digest="sha256:abc", page_size=500)

        assert len(vulns) == 502
        assert vulns[-1]["name"] == "CVE-after-short-page"
        assert mock_api.call_count == 4

    @patch('aquasec.vulnerabilities.api_get_vulnerabilities')
    def test_stops_on_empty_first_page(self, mock_api):
        mock_api.return_value = _resp(200, {"result": []})
        assert get_image_vulnerabilities("https://t.aquasec.com", "tok",
                                         digest="sha256:abc") == []

    @patch('aquasec.vulnerabilities.api_get_vulnerabilities')
    def test_drops_label_before_calling_api(self, mock_api):
        """image_ref carries a label for logging that is not a valid API filter."""
        mock_api.return_value = _resp(200, {"result": []})
        get_image_vulnerabilities("https://t.aquasec.com", "tok",
                                  digest="sha256:abc", label="reg/repo/app:1.0")

        assert 'label' not in mock_api.call_args[1]

    @patch('aquasec.vulnerabilities.time.sleep')
    @patch('aquasec.vulnerabilities.api_get_vulnerabilities')
    def test_retries_replication_conflict_then_succeeds(self, mock_api, mock_sleep):
        """A 500 mid-extract is the SQLSTATE 40001 conflict; one image is cheap to retry."""
        mock_api.side_effect = [
            _resp(500, {}),
            _resp(200, {"result": [{"name": "CVE-1"}]}),
            _resp(200, {"result": []}),
        ]
        vulns = get_image_vulnerabilities("https://t.aquasec.com", "tok",
                                          digest="sha256:abc", page_size=500)

        assert len(vulns) == 1
        assert mock_sleep.called

    @patch('aquasec.vulnerabilities.time.sleep')
    @patch('aquasec.vulnerabilities.api_get_vulnerabilities')
    def test_raises_after_exhausting_retries(self, mock_api, mock_sleep):
        mock_api.return_value = _resp(500, {})
        try:
            get_image_vulnerabilities("https://t.aquasec.com", "tok",
                                      digest="sha256:abc", max_retries=3)
        except Exception as e:
            assert "after 3 attempts" in str(e)
        else:
            raise AssertionError("expected the extract to raise")

    @patch('aquasec.vulnerabilities.time.sleep')
    @patch('aquasec.vulnerabilities.api_get_vulnerabilities')
    def test_does_not_retry_client_error(self, mock_api, mock_sleep):
        mock_api.return_value = _resp(400, {})
        try:
            get_image_vulnerabilities("https://t.aquasec.com", "tok", digest="sha256:abc")
        except Exception:
            pass
        assert mock_api.call_count == 1
        assert not mock_sleep.called


class TestIterAllVulnerabilities:
    IMAGES = [
        {"registry": "reg", "name": "repo/a:1", "digest": "sha256:a"},
        {"registry": "reg", "name": "repo/b:1", "digest": "sha256:b"},
    ]

    @patch('aquasec.vulnerabilities.get_image_vulnerabilities')
    def test_yields_per_image_results(self, mock_get):
        mock_get.side_effect = lambda *a, **k: [{"name": "CVE-1"}]
        out = dict()
        for image, vulns in iter_all_vulnerabilities("https://t.aquasec.com", "tok",
                                                     images=self.IMAGES, max_workers=1):
            out[image["digest"]] = vulns

        assert set(out) == {"sha256:a", "sha256:b"}
        assert all(len(v) == 1 for v in out.values())

    @patch('aquasec.vulnerabilities.get_all_inventory_images')
    @patch('aquasec.vulnerabilities.get_image_vulnerabilities')
    def test_enumerates_only_images_with_workloads_when_asked(self, mock_get, mock_images):
        """has_workloads is the single biggest reduction, and must be applied server-side."""
        mock_images.return_value = self.IMAGES
        mock_get.return_value = []
        list(iter_all_vulnerabilities("https://t.aquasec.com", "tok",
                                      scope="my-app-scope", has_workloads=True, max_workers=1))

        assert mock_images.call_args[1]['has_workloads'] is True
        assert mock_images.call_args[1]['scope'] == "my-app-scope"

    @patch('aquasec.vulnerabilities.get_image_vulnerabilities')
    def test_skips_failing_image_by_default(self, mock_get):
        mock_get.side_effect = [Exception("boom"), [{"name": "CVE-1"}]]
        results = list(iter_all_vulnerabilities("https://t.aquasec.com", "tok",
                                                images=self.IMAGES, max_workers=1))

        assert len(results) == 1

    @patch('aquasec.vulnerabilities.get_image_vulnerabilities')
    def test_raises_on_failure_when_skip_errors_false(self, mock_get):
        mock_get.side_effect = Exception("boom")
        try:
            list(iter_all_vulnerabilities("https://t.aquasec.com", "tok",
                                          images=self.IMAGES, max_workers=1,
                                          skip_errors=False))
        except Exception as e:
            assert "boom" in str(e)
        else:
            raise AssertionError("expected the extract to raise")

    @patch('aquasec.vulnerabilities.get_image_vulnerabilities')
    def test_reports_progress(self, mock_get):
        mock_get.return_value = [{"name": "CVE-1"}]
        seen = []
        list(iter_all_vulnerabilities("https://t.aquasec.com", "tok", images=self.IMAGES,
                                      max_workers=1,
                                      progress=lambda *a: seen.append(a)))

        assert [s[0] for s in seen] == [1, 2]
        assert all(s[1] == 2 for s in seen)

    @patch('aquasec.vulnerabilities.get_image_vulnerabilities')
    def test_get_all_flattens(self, mock_get):
        mock_get.return_value = [{"name": "CVE-1"}]
        assert len(get_all_vulnerabilities("https://t.aquasec.com", "tok",
                                           images=self.IMAGES, max_workers=1)) == 2


class TestCsvOutput:
    VULN = {
        "registry": "reg",
        "image_repository_name": "repo/app:1.0",
        "name": "CVE-2024-1234",
        "aqua_severity": "critical",
        "resource": {"name": "openssl", "version": "1.1.1", "type": "package"},
        "docker_labels": {"team": "platform"},
    }

    def test_flattens_nested_resource_fields(self):
        row = vulnerability_to_row(self.VULN)
        assert row["Resource"] == "openssl"
        assert row["Installed Version"] == "1.1.1"
        assert row["Resource Type"] == "package"
        assert row["Vulnerability Name"] == "CVE-2024-1234"
        assert row["Aqua severity"] == "critical"

    def test_missing_fields_become_empty(self):
        row = vulnerability_to_row({"name": "CVE-1"})
        assert row["Fix Version"] == ""
        assert set(row) == set(CSV_COLUMNS)

    def test_stringifies_structured_values(self):
        assert "platform" in vulnerability_to_row(self.VULN)["Docker Labels"]

    def test_write_then_append_keeps_single_header(self, tmp_path):
        path = str(tmp_path / "vulns.csv")
        assert write_vulnerabilities_csv([self.VULN], path) == 1
        assert write_vulnerabilities_csv([self.VULN], path, append=True) == 1

        with open(path) as handle:
            lines = [line for line in handle if line.strip()]

        assert len(lines) == 3
        assert lines[0].startswith("Registry,")
        assert "CVE-2024-1234" in lines[1]
        assert "CVE-2024-1234" in lines[2]


def _finding(cve, image, package="openssl", version="1.1.1", severity="critical",
             registry="reg", digest=None):
    """One (image, package, CVE) occurrence -- the granularity the API returns."""
    return {
        "name": cve,
        "registry": registry,
        "image_repository_name": image,
        "image_digest": digest or f"sha256:{image}",
        "aqua_severity": severity,
        "resource": {"name": package, "version": version, "type": "package",
                     "path": f"/usr/lib/{package}"},
    }


class TestFindingIdentity:
    """A row is one CVE on one package in one image, not a unique CVE."""

    def test_same_cve_on_two_images_are_distinct_findings(self):
        assert finding_key(_finding("CVE-1", "app-a")) != finding_key(_finding("CVE-1", "app-b"))

    def test_same_cve_on_two_packages_are_distinct_findings(self):
        a = _finding("CVE-1", "app-a", package="openssl")
        b = _finding("CVE-1", "app-a", package="libcrypto")
        assert finding_key(a) != finding_key(b)

    def test_identical_occurrence_has_stable_key(self):
        assert finding_key(_finding("CVE-1", "app-a")) == finding_key(_finding("CVE-1", "app-a"))


class TestUniqueCves:
    FINDINGS = [
        _finding("CVE-1", "app-a"),
        _finding("CVE-1", "app-b"),
        _finding("CVE-1", "app-c"),
        _finding("CVE-2", "app-a", severity="high"),
    ]

    def test_collapses_to_distinct_cves(self):
        summary = unique_cves(self.FINDINGS)
        assert set(summary) == {"CVE-1", "CVE-2"}

    def test_counts_occurrences_and_images(self):
        summary = unique_cves(self.FINDINGS)
        assert summary["CVE-1"]["occurrences"] == 3
        assert summary["CVE-1"]["image_count"] == 3
        assert summary["CVE-1"]["images"] == ["app-a", "app-b", "app-c"]
        assert summary["CVE-2"]["occurrences"] == 1

    def test_carries_severity(self):
        summary = unique_cves(self.FINDINGS)
        assert summary["CVE-1"]["severity"] == "critical"
        assert summary["CVE-2"]["severity"] == "high"

    def test_writes_csv_most_widespread_first(self, tmp_path):
        path = str(tmp_path / "cves.csv")
        assert write_unique_cves_csv(unique_cves(self.FINDINGS), path) == 2
        rows = list(csv.DictReader(open(path)))
        assert rows[0]["cve"] == "CVE-1"
        assert rows[0]["image_count"] == "3"


class TestSummariseByImage:
    def test_counts_findings_and_distinct_cves_by_severity(self):
        image = {"registry": "reg", "name": "repo/app:1.0", "digest": "sha256:abc"}
        vulns = [
            _finding("CVE-1", "repo/app:1.0"),
            _finding("CVE-1", "repo/app:1.0", package="libcrypto"),
            _finding("CVE-2", "repo/app:1.0", severity="high"),
        ]
        row = summarise_by_image(image, vulns)

        assert row["findings"] == 3
        assert row["distinct_cves"] == 2
        assert row["critical"] == 2
        assert row["high"] == 1
        assert row["digest"] == "sha256:abc"

    def test_writes_csv(self, tmp_path):
        path = str(tmp_path / "by_image.csv")
        image = {"registry": "reg", "name": "repo/app:1.0"}
        rows = [summarise_by_image(image, [_finding("CVE-1", "repo/app:1.0")])]
        assert write_image_summary_csv(rows, path) == 1
        assert list(csv.DictReader(open(path)))[0]["findings"] == "1"


class TestEnumerationDeduplication:
    """The one way a per-image walk could inflate results versus a full walk."""

    @patch('aquasec.vulnerabilities.get_image_vulnerabilities')
    def test_duplicate_images_are_queried_once(self, mock_get):
        mock_get.return_value = [{"name": "CVE-1"}]
        images = [
            {"registry": "reg", "name": "repo/a:1", "digest": "sha256:a"},
            {"registry": "reg", "name": "repo/a:1", "digest": "sha256:a"},
            {"registry": "reg", "name": "repo/b:1", "digest": "sha256:b"},
        ]
        results = list(iter_all_vulnerabilities("https://t.aquasec.com", "tok",
                                                images=images, max_workers=1))

        assert len(results) == 2
        assert mock_get.call_count == 2

    @patch('aquasec.vulnerabilities.get_image_vulnerabilities')
    def test_unidentifiable_images_are_not_collapsed_together(self, mock_get):
        mock_get.return_value = []
        images = [{"unrelated": "a"}, {"unrelated": "b"}]
        assert len(list(iter_all_vulnerabilities("https://t.aquasec.com", "tok",
                                                 images=images, max_workers=1))) == 2


class TestFilterPassthrough:
    IMAGES = [{"registry": "reg", "name": "repo/a:1", "digest": "sha256:a"}]

    @patch('aquasec.vulnerabilities.get_image_vulnerabilities')
    def test_extra_filters_reach_each_image_query(self, mock_get):
        mock_get.return_value = []
        list(iter_all_vulnerabilities("https://t.aquasec.com", "tok", images=self.IMAGES,
                                      max_workers=1, cluster="prod",
                                      include_vpatch_info=True))

        assert mock_get.call_args[1]["cluster"] == "prod"
        assert mock_get.call_args[1]["include_vpatch_info"] is True

    @patch('aquasec.vulnerabilities.get_image_vulnerabilities')
    def test_image_identity_overrides_caller_filter(self, mock_get):
        """Colliding kwargs must not raise -- skip_errors would hide it as data loss."""
        mock_get.return_value = [{"name": "CVE-1"}]
        results = list(iter_all_vulnerabilities("https://t.aquasec.com", "tok",
                                                images=self.IMAGES, max_workers=1,
                                                digest="sha256:someone-elses"))

        assert len(results) == 1
        assert mock_get.call_args[1]["digest"] == "sha256:a"


class TestSharedDigestImages:
    """Identical content registered under several names is several findings."""

    def test_finding_key_separates_images_sharing_a_digest(self):
        a = dict(_finding("CVE-1", "team/app-a"), image_digest="sha256:same")
        b = dict(_finding("CVE-1", "team/app-b"), image_digest="sha256:same")
        assert finding_key(a) != finding_key(b)

    def test_finding_key_still_matches_the_same_image(self):
        a = dict(_finding("CVE-1", "team/app-a"), image_digest="sha256:same")
        b = dict(_finding("CVE-1", "team/app-a"), image_digest="sha256:same")
        assert finding_key(a) == finding_key(b)

    @patch('aquasec.vulnerabilities.get_image_vulnerabilities')
    def test_enumeration_keeps_images_sharing_a_digest(self, mock_get):
        """Keying dedupe on digest alone dropped ~15% of a real tenant's findings."""
        mock_get.return_value = [{"name": "CVE-1"}]
        images = [
            {"registry": "reg", "name": "team/app-a", "digest": "sha256:same"},
            {"registry": "reg", "name": "team/app-b", "digest": "sha256:same"},
            {"registry": "reg", "name": "team/app-c", "digest": "sha256:same"},
        ]
        results = list(iter_all_vulnerabilities("https://t.aquasec.com", "tok",
                                                images=images, max_workers=1))

        assert len(results) == 3
        assert mock_get.call_count == 3

    @patch('aquasec.vulnerabilities.get_image_vulnerabilities')
    def test_truly_identical_entries_are_still_collapsed(self, mock_get):
        mock_get.return_value = []
        images = [
            {"registry": "reg", "name": "team/app-a", "digest": "sha256:same"},
            {"registry": "reg", "name": "team/app-a", "digest": "sha256:same"},
        ]
        list(iter_all_vulnerabilities("https://t.aquasec.com", "tok",
                                      images=images, max_workers=1))

        assert mock_get.call_count == 1


class TestServerSideExport:
    """The documented REST export: the server builds the archive, not the browser."""

    @patch('aquasec.vulnerabilities._request_with_retry')
    def test_trigger_posts_expected_payload(self, mock_req):
        from aquasec.vulnerabilities import api_trigger_export
        mock_req.return_value = _resp(200, {"token": "job-1"})
        api_trigger_export("https://t.aquasec.com", "tok", entity_type="images",
                           filters={"has_workloads": "true", "severities": ["critical"]})

        args, kwargs = mock_req.call_args
        assert args[0] == 'POST'
        assert args[1] == ("https://t.aquasec.com/api/v2/risks/vulnerabilities"
                           "/exporters/images/export")
        p = kwargs['json']
        assert p['name'] == "Compressed CSV"
        assert p['columns_name'] == "aqua_recommended"
        assert p['filter']['has_workloads'] == "true"

    @patch('aquasec.vulnerabilities._request_with_retry')
    def test_explicit_columns_replace_columns_name(self, mock_req):
        """Either columns_name or columns is required; sending both is redundant."""
        from aquasec.vulnerabilities import api_trigger_export
        mock_req.return_value = _resp(200, {"token": "job-1"})
        api_trigger_export("https://t.aquasec.com", "tok",
                           columns=["name", "aqua_severity", "epss_score"])

        p = mock_req.call_args[1]['json']
        assert p['columns'] == "name,aqua_severity,epss_score"
        assert 'columns_name' not in p

    @patch('aquasec.vulnerabilities._request_with_retry')
    def test_job_status_url(self, mock_req):
        from aquasec.vulnerabilities import api_get_export_job
        mock_req.return_value = _resp(200, {"status": "Ready"})
        api_get_export_job("https://t.aquasec.com", "tok", "job-1")

        assert mock_req.call_args[0][1] == ("https://t.aquasec.com/api/v2/risks"
                                            "/vulnerabilities/exporters/images/jobs/job-1")

    @patch('aquasec.vulnerabilities.api_stream_export')
    @patch('aquasec.vulnerabilities.api_trigger_export')
    def test_end_to_end_returns_archive(self, mock_trigger, mock_stream, tmp_path):
        from aquasec.vulnerabilities import export_vulnerabilities
        mock_trigger.return_value = _resp(200, {"token": "job-1"})
        zip_resp = _resp(200, {})
        zip_resp.content = b'PK\x03\x04rest-of-archive'
        mock_stream.return_value = zip_resp

        out = str(tmp_path / "export.zip")
        archive = export_vulnerabilities("https://t.aquasec.com", "tok", output_file=out)

        assert archive.startswith(b'PK')
        assert open(out, "rb").read() == archive
        assert mock_stream.call_args[0][2] == "job-1"

    @patch('aquasec.vulnerabilities.api_trigger_export')
    def test_raises_when_trigger_fails(self, mock_trigger):
        """An unknown exporter name fails with 500, not 404 -- surface the body."""
        from aquasec.vulnerabilities import export_vulnerabilities
        res = _resp(500, {})
        res.text = "Exporter with name vulnerabilities.images, nope not found"
        mock_trigger.return_value = res
        try:
            export_vulnerabilities("https://t.aquasec.com", "tok", name="nope")
        except Exception as e:
            assert "not found" in str(e)
        else:
            raise AssertionError("expected the trigger failure to raise")

    @patch('aquasec.vulnerabilities.api_stream_export')
    @patch('aquasec.vulnerabilities.api_trigger_export')
    def test_rejects_non_zip_response(self, mock_trigger, mock_stream):
        from aquasec.vulnerabilities import export_vulnerabilities
        mock_trigger.return_value = _resp(200, {"token": "job-1"})
        bad = _resp(200, {})
        bad.content = b'{"message":"nope"}'
        mock_stream.return_value = bad
        try:
            export_vulnerabilities("https://t.aquasec.com", "tok")
        except Exception as e:
            assert "ZIP" in str(e)
        else:
            raise AssertionError("expected a non-ZIP body to raise")

    def test_reads_csv_and_manifest_from_archive(self):
        import io as _io, json as _json, zipfile as _zip
        from aquasec.vulnerabilities import read_export_archive
        buf = _io.BytesIO()
        with _zip.ZipFile(buf, "w") as z:
            z.writestr("aqua_export.csv", "Vulnerability Name,Severity\nCVE-1,high\n")
            z.writestr("manifest.json", _json.dumps({"status": "Ready"}))
        rows, manifest = read_export_archive(buf.getvalue())

        assert len(rows) == 1
        assert rows[0]["Vulnerability Name"] == "CVE-1"
        assert manifest["status"] == "Ready"

    def test_available_columns_flattened(self):
        from aquasec.vulnerabilities import get_available_columns
        with patch('aquasec.vulnerabilities._request_with_retry') as mock_req:
            mock_req.return_value = _resp(200, [
                {"name": "VulnerabilityColumns",
                 "attributes": {"epss_score": {"display_name": "EPSS Score"},
                                "name": {"display_name": "Vulnerability Name"}}},
                {"name": "ResourceColumns",
                 "attributes": {"resource.purl": {"display_name": "Purl"}}},
            ])
            cols = get_available_columns("https://t.aquasec.com", "tok")

        assert cols["epss_score"] == "EPSS Score"
        assert cols["resource.purl"] == "Purl"


class TestStreamingArchiveExtraction:
    """Estate-sized archives must never be materialised as dicts."""

    @staticmethod
    def _archive(members):
        import io as _io, zipfile as _zip
        buf = _io.BytesIO()
        with _zip.ZipFile(buf, "w") as z:
            for name, body in members.items():
                z.writestr(name, body)
        return buf.getvalue()

    def test_writes_rows_and_returns_count(self, tmp_path):
        from aquasec.vulnerabilities import extract_export_csv
        archive = self._archive({
            "aqua_export.csv": "Vulnerability Name,Severity\nCVE-1,high\nCVE-2,low\n",
            "manifest.json": "{}",
        })
        out = str(tmp_path / "out.csv")
        assert extract_export_csv(archive, out) == 2

        lines = [l for l in open(out).read().splitlines() if l]
        assert lines[0] == "Vulnerability Name,Severity"
        assert len(lines) == 3

    def test_split_archives_keep_one_header(self, tmp_path):
        """Exports can be split across members; a repeated header corrupts the file."""
        from aquasec.vulnerabilities import extract_export_csv
        archive = self._archive({
            "aqua_export_1.csv": "Vulnerability Name,Severity\nCVE-1,high\n",
            "aqua_export_2.csv": "Vulnerability Name,Severity\nCVE-2,low\n",
        })
        out = str(tmp_path / "out.csv")
        assert extract_export_csv(archive, out) == 2

        lines = [l for l in open(out).read().splitlines() if l]
        assert lines.count("Vulnerability Name,Severity") == 1
        assert len(lines) == 3

    def test_preserves_embedded_newlines_and_commas(self, tmp_path):
        from aquasec.vulnerabilities import extract_export_csv
        import csv as _csv
        archive = self._archive({
            "aqua_export.csv": 'Name,Description\nCVE-1,"line one\nline two, with comma"\n',
        })
        out = str(tmp_path / "out.csv")
        assert extract_export_csv(archive, out) == 1

        rows = list(_csv.DictReader(open(out, newline="")))
        assert rows[0]["Description"] == "line one\nline two, with comma"
