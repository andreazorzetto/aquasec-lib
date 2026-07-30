"""Tests for the Global-only (scope delta) analysis logic."""
import csv
import os
import sys
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import aqua_global_scope_extract as gse


# --- Pure helpers -----------------------------------------------------------

def test_repo_key():
    assert gse.repo_key({"registry": "Docker Hub", "name": "nginx"}) == "Docker Hub/nginx"
    assert gse.repo_key({}) == "unknown/unknown"


def test_resolve_output_path_keeps_reports_out_of_cwd(tmp_path, monkeypatch):
    """A named file must not land next to the source; only an explicit
    directory component opts out of the run's output folder."""
    monkeypatch.chdir(tmp_path)
    out = "output_20260730-120000"

    # flag given bare -> default name inside the output folder
    assert gse.resolve_output_path(gse.DEFAULT_OUTPUT, out, "report.xlsx") == \
        os.path.join(out, "report.xlsx")
    # bare file name -> also inside the output folder (the reported surprise)
    assert gse.resolve_output_path("report.xlsx", out, "report.xlsx") == \
        os.path.join(out, "report.xlsx")
    # a directory component means "put it exactly here"
    assert gse.resolve_output_path("./report.xlsx", out, "report.xlsx") == "./report.xlsx"
    assert gse.resolve_output_path("sub/report.xlsx", out, "report.xlsx") == "sub/report.xlsx"
    assert gse.resolve_output_path(str(tmp_path / "abs.xlsx"), out, "report.xlsx") == \
        str(tmp_path / "abs.xlsx")


def test_container_row_omits_removed_exposure_field():
    row = gse.container_row({"container_uid": "u", "name": "n", "image_name": "i:1",
                             "cluster_name": "c", "namespace_name": "ns", "host_name": "h",
                             "status": "running", "risk_level": "", "internet_exposure": "exposed"})
    assert "internet_exposure" not in row
    assert set(row) == {"id", "name", "image_name", "cluster_name",
                        "namespace_name", "host_name", "status", "risk_level"}


def test_write_csv_files_columns(tmp_path):
    result = {
        "unscoped_repositories": [{"name": "nginx", "registry": "Docker Hub", "key": "Docker Hub/nginx"}],
        "unscoped_containers": [
            {"id": "1", "name": "a", "image_name": "nginx:1", "cluster_name": "poc",
             "namespace_name": "web", "host_name": "n", "status": "running", "risk_level": ""},
        ],
    }
    written = gse.write_csv_files(result, str(tmp_path))
    assert len(written) == 2

    with open(tmp_path / "unscoped_repositories.csv", newline="") as f:
        rows = list(csv.reader(f))
    assert rows[0] == ["name", "registry"]
    assert rows[1] == ["nginx", "Docker Hub"]

    with open(tmp_path / "unscoped_containers.csv", newline="") as f:
        rows = list(csv.reader(f))
    assert rows[0] == ["id", "name", "image_name", "cluster_name",
                       "namespace_name", "host_name", "status", "risk_level"]
    assert "internet_exposure" not in rows[0]


def test_summarize():
    s = gse.summarize(10, 4)
    assert s == {"total": 10, "scoped": 6, "unscoped": 4, "unscoped_percentage": 40.0}


def test_summarize_zero_total():
    s = gse.summarize(0, 0)
    assert s["unscoped_percentage"] == 0


def test_group_containers_by_cluster():
    containers = [
        {"cluster_name": "c1", "namespace_name": "ns1"},
        {"cluster_name": "c1", "namespace_name": "ns1"},
        {"cluster_name": "c1", "namespace_name": "ns2"},
        {"cluster_name": "c2", "namespace_name": None},
    ]
    grouped = gse.group_containers_by_cluster(containers)
    assert grouped["c1"] == {"ns1": 2, "ns2": 1}
    assert grouped["c2"] == {"(none)": 1}


def test_container_row_image_fallback():
    row = gse.container_row({"container_uid": "u", "name": "n", "image_name": "",
                             "origin_image_name": "orig:tag", "cluster_name": "c"})
    assert row["image_name"] == "orig:tag"
    assert row["id"] == "u"


# --- get_application_scope_names -------------------------------------------

def test_scope_names_excludes_global():
    with patch.object(gse, 'get_app_scopes', return_value=[
        {"name": "Global"}, {"name": "TeamA"}, {"name": "TeamB"}
    ]):
        names = gse.get_application_scope_names("s", "t")
    assert sorted(names) == ["TeamA", "TeamB"]


def test_scope_names_dedupes_and_preserves_order():
    # Large tenants can return the same scope across pages (pagination drift).
    with patch.object(gse, 'get_app_scopes', return_value=[
        {"name": "Team B"}, {"name": "Team A"}, {"name": "Global"},
        {"name": "Team B"}, {"name": "Team A"},
    ]):
        names = gse.get_application_scope_names("s", "t")
    assert names == ["Team B", "Team A"]  # deduped, first-seen order, Global excluded


def test_scope_names_403_raises_permission_error():
    with patch.object(gse, 'get_app_scopes', side_effect=Exception("Failed to list application scopes: HTTP 403 - denied")):
        try:
            gse.get_application_scope_names("s", "t")
            assert False, "expected PermissionError"
        except PermissionError as e:
            assert "Access Management" in str(e)


def test_scope_names_other_error_propagates():
    with patch.object(gse, 'get_app_scopes', side_effect=Exception("boom 500")):
        try:
            gse.get_application_scope_names("s", "t")
            assert False, "expected Exception"
        except PermissionError:
            assert False, "should not be PermissionError"
        except Exception as e:
            assert "boom" in str(e)


# --- analyze (full delta with mocked fetchers) ------------------------------

def _repos(server=None, token=None, scope=None, **kwargs):
    ALL = [
        {"registry": "r", "name": "shared"},   # in TeamA
        {"registry": "r", "name": "orphan1"},  # in no scope
        {"registry": "r", "name": "orphan2"},  # in no scope
    ]
    if scope == "TeamA":
        return [{"registry": "r", "name": "shared"}]
    if scope is None:
        return ALL
    return []


def _containers(server=None, token=None, scope=None, **kwargs):
    ALL = [
        {"container_uid": "1", "name": "c-shared", "cluster_name": "prod", "namespace_name": "ns"},
        {"container_uid": "2", "name": "c-orphan", "cluster_name": "dev", "namespace_name": "ns"},
    ]
    if scope == "TeamA":
        return [{"container_uid": "1", "name": "c-shared", "cluster_name": "prod", "namespace_name": "ns"}]
    if scope is None:
        return ALL
    return []


def test_analyze_full():
    with patch.object(gse, 'get_app_scopes', return_value=[{"name": "Global"}, {"name": "TeamA"}]), \
         patch.object(gse, 'get_all_repositories', side_effect=_repos), \
         patch.object(gse, 'get_all_containers', side_effect=_containers):
        result = gse.analyze("s", "t", include_repos=True, include_containers=True)

    rs = result["summary"]["repositories"]
    assert rs == {"total": 3, "scoped": 1, "unscoped": 2, "unscoped_percentage": round(2/3*100, 2)}
    assert [r["name"] for r in result["unscoped_repositories"]] == ["orphan1", "orphan2"]

    cs = result["summary"]["containers"]
    assert cs == {"total": 2, "scoped": 1, "unscoped": 1, "unscoped_percentage": 50.0}
    assert [c["name"] for c in result["unscoped_containers"]] == ["c-orphan"]
    assert result["unscoped_containers_by_cluster"] == {"dev": {"ns": 1}}
    assert result["application_scopes"] == ["TeamA"]

    # master lists (the Global view) that membership indexes into
    assert result["all_repositories"] == [
        {"name": "shared", "registry": "r"},
        {"name": "orphan1", "registry": "r"},
        {"name": "orphan2", "registry": "r"},
    ]
    assert len(result["all_containers"]) == 2

    # scope coverage: (unscoped) bucket pinned first, then each scope's counts,
    # with membership stored as indices into the master lists.
    cov = result["scope_coverage"]
    assert cov[0]["unscoped"] is True and cov[0]["repos"] == 2 and cov[0]["containers"] == 1
    assert cov[0]["repo_ids"] == [1, 2] and cov[0]["cont_ids"] == [1]
    assert cov[1]["scope"] == "TeamA" and cov[1]["repos"] == 1 and cov[1]["containers"] == 1
    assert cov[1]["repo_ids"] == [0] and cov[1]["cont_ids"] == [0]


def test_analyze_repos_only():
    with patch.object(gse, 'get_app_scopes', return_value=[{"name": "Global"}, {"name": "TeamA"}]), \
         patch.object(gse, 'get_all_repositories', side_effect=_repos), \
         patch.object(gse, 'get_all_containers', side_effect=_containers):
        result = gse.analyze("s", "t", include_repos=True, include_containers=False)
    assert "repositories" in result["summary"]
    assert "containers" not in result["summary"]
    assert "unscoped_containers" not in result
