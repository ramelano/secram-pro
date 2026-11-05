import importlib.metadata
import json
import os
import stat

import pytest

from secram.modules.vulnerability.advisories import AdvisoryStore


def advisory(
    advisory_id="OSV-TEST-RANGE",
    *,
    name="Example_Pkg",
    ecosystem="PyPI",
    ranges=None,
    versions=None,
    withdrawn=None,
):
    affected = {"package": {"ecosystem": ecosystem, "name": name}}
    if ranges is not None:
        affected["ranges"] = ranges
    if versions is not None:
        affected["versions"] = versions
    record = {
        "id": advisory_id,
        "aliases": ["OSV-TEST-ALIAS"],
        "summary": "OSV test advisory fixture",
        "references": [{"type": "WEB", "url": "https://example.invalid/OSV-TEST-RANGE"}],
        "affected": [affected],
    }
    if withdrawn is not None:
        record["withdrawn"] = withdrawn
    return record


def import_records(tmp_path, records):
    source = tmp_path / "source.json"
    source.write_text(json.dumps(records), encoding="utf-8")
    store = AdvisoryStore(tmp_path / "private" / "advisories.json")
    result = store.import_osv(source)
    assert result["accepted"] is True
    return store


def test_empty_status_is_data_unavailable(tmp_path):
    result = AdvisoryStore(tmp_path / "private" / "advisories.json").status()
    assert result["data_available"] is False
    assert result["status"] == "data_unavailable"
    assert result["record_count"] == 0
    assert result["vulnerabilities"] == []
    assert result["limitations"]


@pytest.mark.parametrize(
    "payload",
    [
        advisory(advisory_id="OSV-TEST-SINGLE", versions=["1.2.3"]),
        [advisory(advisory_id="OSV-TEST-LIST", versions=["1.2.3"])],
        {"vulns": [advisory(advisory_id="OSV-TEST-ENVELOPE", versions=["1.2.3"])]},
    ],
)
def test_import_accepts_osv_single_list_and_envelope(tmp_path, payload):
    source = tmp_path / "source.json"
    source.write_text(json.dumps(payload), encoding="utf-8")
    store = AdvisoryStore(tmp_path / "advisories.json")
    assert store.import_osv(source)["accepted"] is True
    assert store.status()["record_count"] == 1


def test_range_boundaries_introduced_inclusive_fixed_exclusive(tmp_path):
    store = import_records(
        tmp_path,
        [
            advisory(
                advisory_id="OSV-TEST-INTRO-FIXED",
                ranges=[
                    {
                        "type": "ECOSYSTEM",
                        "events": [{"introduced": "1.2.3"}, {"fixed": "1.2.5"}],
                    }
                ],
            )
        ],
    )
    assert store.match_packages([{"name": "example-pkg", "version": "1.2.3"}])["clean"] is False
    assert store.match_packages([{"name": "example-pkg", "version": "1.2.4"}])["candidates"]
    fixed = store.match_packages([{"name": "example-pkg", "version": "1.2.5"}])
    assert fixed["clean"] is False
    assert fixed["match_result"] == "no_matches_in_imported_snapshot"
    assert fixed["candidates"] == []


def test_range_boundaries_last_affected_inclusive_limit_exclusive(tmp_path):
    store = import_records(
        tmp_path,
        [
            advisory(
                advisory_id="OSV-TEST-LAST",
                ranges=[
                    {
                        "type": "ECOSYSTEM",
                        "events": [{"introduced": "0"}, {"last_affected": "2.0.0"}],
                    }
                ],
            ),
            advisory(
                advisory_id="OSV-TEST-LIMIT",
                name="Limit_Pkg",
                ranges=[
                    {
                        "type": "ECOSYSTEM",
                        "events": [{"introduced": "1.0.0"}, {"limit": "2.0.0"}],
                    }
                ],
            ),
        ],
    )
    assert store.match_packages([{"name": "example-pkg", "version": "2.0.0"}])["candidates"]
    assert store.match_packages([{"name": "limit-pkg", "version": "1.9.9"}])["candidates"]
    assert store.match_packages([{"name": "limit-pkg", "version": "2.0.0"}])["candidates"] == []


def test_explicit_versions_and_name_canonicalization(tmp_path):
    store = import_records(
        tmp_path,
        [advisory(advisory_id="OSV-TEST-EXPLICIT", versions=["3.1.0"])],
    )
    result = store.match_packages([{"name": "EXAMPLE_pkg", "version": "3.1.0"}])
    candidate = result["candidates"][0]
    assert candidate["id"] == "OSV-TEST-EXPLICIT"
    assert candidate["aliases"] == ["OSV-TEST-ALIAS"]
    assert candidate["summary"] == "OSV test advisory fixture"
    assert candidate["references"][0]["url"].endswith("OSV-TEST-RANGE")
    assert candidate["matchedname"] == "example-pkg"
    assert candidate["version"] == "3.1.0"
    assert candidate["importsha"] == result["importsha"]
    assert candidate["importtime"] == result["importtime"]
    assert "not confirmed compromise" in candidate["reason"]


def test_withdrawn_advisory_is_not_active(tmp_path):
    store = import_records(
        tmp_path,
        [advisory(advisory_id="OSV-TEST-WITHDRAWN", versions=["1.0.0"], withdrawn="2026-01-01T00:00:00Z")],
    )
    result = store.match_packages([{"name": "example-pkg", "version": "1.0.0"}])
    assert result["clean"] is False
    assert result["candidates"] == []


def test_unsupported_nonpypi_git_and_unparseable_coverage_is_not_clean(tmp_path):
    store = import_records(
        tmp_path,
        [
            advisory(advisory_id="OSV-TEST-NONPYPI", ecosystem="npm", versions=["1.0.0"]),
            advisory(
                advisory_id="OSV-TEST-GIT",
                ranges=[{"type": "GIT", "events": [{"introduced": "abc"}]}],
            ),
            advisory(advisory_id="OSV-TEST-BADVERSION", versions=["not-a-version"]),
        ],
    )
    result = store.match_packages([{"name": "example-pkg", "version": "1.0.0"}])
    assert result["candidates"] == []
    assert result["clean"] is False
    assert result["limitations"]

    invalid_installed = store.match_packages([{"name": "example-pkg", "version": "not-a-version"}])
    assert invalid_installed["clean"] is False
    assert invalid_installed["limitations"]


def test_invalid_import_preserves_prior_good_store_atomically(tmp_path):
    store = import_records(tmp_path, [advisory(advisory_id="OSV-TEST-GOOD", versions=["1.0.0"])])
    stored_path = tmp_path / "private" / "advisories.json"
    before = stored_path.read_bytes()
    bad_source = tmp_path / "bad.json"
    bad_source.write_text('{"vulns": [{"id": "OSV-TEST-BAD",', encoding="utf-8")
    rejected = store.import_osv(bad_source)
    assert rejected["accepted"] is False
    assert stored_path.read_bytes() == before
    assert store.status()["vulnerabilities"] == ["OSV-TEST-GOOD"]


def test_symlink_source_is_rejected(tmp_path):
    real_source = tmp_path / "real.json"
    real_source.write_text(json.dumps([advisory(versions=["1.0.0"])]), encoding="utf-8")
    link = tmp_path / "source-link.json"
    link.symlink_to(real_source)
    store = AdvisoryStore(tmp_path / "advisories.json")
    result = store.import_osv(link)
    assert result["accepted"] is False
    assert store.status()["data_available"] is False


def test_private_store_modes(tmp_path):
    store = import_records(tmp_path, [advisory(versions=["1.0.0"])])
    path = tmp_path / "private" / "advisories.json"
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert stat.S_IMODE(path.parent.stat().st_mode) == 0o700


def test_actual_installed_inventory_metadata_sample(tmp_path):
    try:
        installed_version = importlib.metadata.version("packaging")
    except importlib.metadata.PackageNotFoundError:
        pytest.skip("packaging is not installed in this test environment")
    store = import_records(
        tmp_path,
        [advisory(advisory_id="OSV-TEST-INSTALLED", name="packaging", versions=[installed_version])],
    )
    result = store.match_installed()
    assert result["inventory_source"] == "importlib.metadata"
    assert result["inventory_count"] > 0
    assert any(candidate["id"] == "OSV-TEST-INSTALLED" for candidate in result["candidates"])
    assert not any("network" in limitation.lower() for limitation in result["limitations"])


def test_record_limit_is_enforced_without_replacement(tmp_path):
    store = import_records(tmp_path, [advisory(advisory_id="OSV-TEST-GOOD", versions=["1.0.0"])])
    source = tmp_path / "too-many.json"
    source.write_text(json.dumps([advisory(advisory_id=f"OSV-TEST-{i}") for i in range(5001)]), encoding="utf-8")
    result = store.import_osv(source)
    assert result["accepted"] is False
    assert store.status()["vulnerabilities"] == ["OSV-TEST-GOOD"]
