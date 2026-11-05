from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path

import pytest

from secram.reporting.exporter import export_assessment


def _inputs() -> tuple[dict, list[dict], list[dict], list[dict], dict]:
    assessment = {
        "id": "../../<script>alert('id')</script>",
        "title": "Yerel <img src=x onerror=alert(1)> değerlendirmesi",
        "created_at": datetime(2026, 11, 3, 18, 0, tzinfo=timezone.utc),
        "scope": {
            "cidrs": ["192.0.2.0/24"],
            "allowed_operations": ["host.snapshot"],
            "starts_at": "2026-11-03T17:00:00+00:00",
            "expires_at": "2026-11-04T17:00:00+00:00",
        },
        "authorization": {"approved_by": "local owner", "statement": "authorized local lab"},
        "tools": ["python-runtime"],
    }
    tasks = [
        {
            "id": "task-1",
            "state": "succeeded",
            "operation": "host.snapshot",
            "result": {"evidence": "local snapshot", "password": "do-not-export"},
        }
    ]
    findings = [
        {
            "id": "finding-1",
            "status": "candidate",
            "rule_id": "local.rule",
            "evidence": "authentication failed with status 401; useful evidence remains",
            "recommendation": "Review local authentication policy.",
            "details": {"Authorization": "Bearer never-export-this", "secret": "hidden"},
        }
    ]
    events = [
        {
            "id": "00000000-0000-4000-8000-000000000001",
            "observed_at": "2026-11-03T18:01:00+00:00",
            "source": "python-runtime",
            "event_type": "auth.failure",
            "severity": "low",
            "details": {"message": "authentication failure observed", "token": "hidden"},
            "rule_id": None,
            "target": "192.0.2.10",
            "port": 443,
            "task_id": "task-1",
            "assessment_id": assessment["id"],
        }
    ]
    purple = {
        "metrics": {"coverage": 0.5},
        "limitations": ["Only supplied offline exercise data was measured."],
    }
    return assessment, tasks, findings, events, purple


def test_all_requested_formats_create_private_real_files(tmp_path: Path) -> None:
    values = _inputs()
    result = export_assessment(*values, output_dir=tmp_path)

    assert set(result["requested_formats"]) == {"json", "md", "html", "csv", "pdf"}
    assert set(result["files"]) == {"json", "md", "html", "csv"} | (
        {"pdf"} if "pdf" not in result["unavailable_formats"] else set()
    )
    bundle = Path(result["bundle_dir"])
    assert bundle.is_dir()
    assert bundle.stat().st_mode & 0o777 == 0o700
    assert Path(result["manifest_path"]).is_file()
    assert Path(result["manifest_path"]).stat().st_mode & 0o777 == 0o600

    for format_name, file_name in result["files"].items():
        path = Path(file_name)
        assert path.parent == bundle
        assert path.stat().st_mode & 0o777 == 0o600
        assert result["hashes"][format_name] == hashlib.sha256(path.read_bytes()).hexdigest()
        assert result["manifest"][path.name] == result["hashes"][format_name]
    if "pdf" in result["files"]:
        assert Path(result["files"]["pdf"]).read_bytes().startswith(b"%PDF")
    else:
        assert "PDF unavailable" in " ".join(result["limitations"])


def test_html_escapes_untrusted_values(tmp_path: Path) -> None:
    result = export_assessment(*_inputs(), output_dir=tmp_path, formats=("html",))
    content = Path(result["files"]["html"]).read_text(encoding="utf-8")
    assert "&lt;script&gt;" in content
    assert "&lt;img src=x onerror=alert(1)&gt;" in content
    assert "<script>alert('id')</script>" not in content
    assert "<img src=x onerror=alert(1)>" not in content


def test_csv_neutralizes_formula_strings(tmp_path: Path) -> None:
    assessment, tasks, findings, events, purple = _inputs()
    findings[0]["evidence"] = "=HYPERLINK(\"https://example.invalid\")"
    result = export_assessment(
        assessment,
        tasks,
        findings,
        events,
        purple,
        output_dir=tmp_path,
        formats=("csv",),
    )
    content = Path(result["files"]["csv"]).read_text(encoding="utf-8")
    assert "'=HYPERLINK" in content
    assert "\n=HYPERLINK" not in content


def test_redacts_sensitive_dictionary_keys_but_keeps_auth_failure_evidence(tmp_path: Path) -> None:
    result = export_assessment(*_inputs(), output_dir=tmp_path, formats=("json",))
    report = json.loads(Path(result["files"]["json"]).read_text(encoding="utf-8"))
    serialized = json.dumps(report, ensure_ascii=False)
    assert "do-not-export" not in serialized
    assert "never-export-this" not in serialized
    assert "authentication failed with status 401; useful evidence remains" in serialized
    assert report["findings"][0]["details"]["Authorization"] == "[REDACTED]"


def test_untrusted_identifier_is_not_used_as_a_path_component(tmp_path: Path) -> None:
    result = export_assessment(*_inputs(), output_dir=tmp_path, formats=("json",))
    bundle = Path(result["bundle_dir"])
    output = Path(result["files"]["json"])
    assert output.parent == bundle
    assert output.name == "assessment.json"
    assert "<script>" not in str(output)
    assert ".." not in output.name


def test_symlink_output_path_is_refused(tmp_path: Path) -> None:
    real = tmp_path / "real"
    real.mkdir()
    link = tmp_path / "link"
    link.symlink_to(real, target_is_directory=True)
    with pytest.raises(ValueError, match="symlink"):
        export_assessment(*_inputs(), output_dir=link, formats=("json",))
    assert list(real.iterdir()) == []


def test_unknown_format_rejected_before_creating_bundle(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="Unknown report format"):
        export_assessment(*_inputs(), output_dir=tmp_path, formats=("yaml",))
    assert list(tmp_path.iterdir()) == []
