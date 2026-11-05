"""Offline assessment report export.

The exporter deliberately treats its inputs as untrusted snapshots.  It does not
perform network access, run tools, or infer that an observation is a compromise.
"""
from __future__ import annotations

import csv
import hashlib
import html
import io
import json
import os
import re
import stat
import unicodedata
from collections import Counter
from collections.abc import Mapping
from datetime import date, datetime, time, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4


_FORMATS = ("json", "md", "html", "csv", "pdf")
_SENSITIVE_TERMS = (
    "secret",
    "password",
    "passwd",
    "token",
    "privatekey",
    "authorization",
    "setcookie",
)
_FORMULA_PREFIXES = "=+-@"
_MANIFEST_NOTE = (
    "SHA-256 values are a tamper-evident snapshot only; they are not an "
    "authenticated or tamper-proof guarantee."
)
_TELEMETRY_FIELDS = {
    "id": "str UUID",
    "observed_at": "timezone-aware UTC ISO timestamp",
    "source": "str",
    "event_type": "str",
    "severity": "info|low|medium|high",
    "details": "dict",
    "rule_id": "str|null",
    "target": "literal IP|null",
    "port": "int|null",
    "task_id": "str|null",
    "assessment_id": "str|null",
}


class _PdfUnavailable(RuntimeError):
    """Internal signal used when an optional PDF renderer cannot be used."""


def _sensitive_key(key: str) -> bool:
    normalized = "".join(character for character in key.casefold() if character.isalnum())
    return any(term in normalized for term in _SENSITIVE_TERMS)


def _jsonable(value: Any, active: set[int] | None = None) -> Any:
    """Convert common model values to JSON-safe values without executing them."""
    if active is None:
        active = set()
    if value is None or isinstance(value, (str, bool, int)):
        return value
    if isinstance(value, float):
        return value if value == value and value not in (float("inf"), float("-inf")) else str(value)
    if isinstance(value, datetime):
        if value.tzinfo is not None and value.utcoffset() is not None:
            return value.astimezone(timezone.utc).isoformat()
        return value.isoformat()
    if isinstance(value, (date, time)):
        return value.isoformat()
    if isinstance(value, Path):
        return str(value)
    if hasattr(value, "value") and not isinstance(value, (bytes, bytearray)):
        enum_value = getattr(value, "value")
        if enum_value is not value:
            return _jsonable(enum_value, active)
    if hasattr(value, "model_dump") and callable(value.model_dump):
        value = value.model_dump(mode="json")
    if isinstance(value, (bytes, bytearray)):
        return "[binary data omitted]"
    identity = id(value)
    if identity in active:
        return "[circular reference omitted]"
    if isinstance(value, Mapping):
        active.add(identity)
        result: dict[str, Any] = {}
        for key, item in value.items():
            key_text = str(key)
            result[key_text] = "[REDACTED]" if _sensitive_key(key_text) else _jsonable(item, active)
        active.remove(identity)
        return result
    if isinstance(value, (list, tuple)):
        active.add(identity)
        result = [_jsonable(item, active) for item in value]
        active.remove(identity)
        return result
    if isinstance(value, (set, frozenset)):
        active.add(identity)
        result = sorted((_jsonable(item, active) for item in value), key=lambda item: repr(item))
        active.remove(identity)
        return result
    return str(value)


def _canonical_json(value: Any) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )


def _pretty_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2, allow_nan=False)


def _as_mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _build_report(
    assessment: Any,
    tasks: Any,
    findings: Any,
    events: Any,
    purple: Any,
    generated_at: str,
    limitations: list[str],
) -> dict[str, Any]:
    safe_assessment = _jsonable(assessment)
    safe_tasks = _jsonable(list(tasks) if isinstance(tasks, (list, tuple)) else [])
    safe_findings = _jsonable(list(findings) if isinstance(findings, (list, tuple)) else [])
    safe_events = _jsonable(list(events) if isinstance(events, (list, tuple)) else [])
    safe_purple = _jsonable(purple)

    assessment_map = _as_mapping(safe_assessment)
    task_items = safe_tasks if isinstance(safe_tasks, list) else []
    finding_items = safe_findings if isinstance(safe_findings, list) else []
    event_items = safe_events if isinstance(safe_events, list) else []
    purple_map = _as_mapping(safe_purple)

    time_data: dict[str, Any] = {"exported_at": generated_at}
    for key in ("created_at", "updated_at", "starts_at", "expires_at"):
        if key in assessment_map:
            time_data[key] = assessment_map[key]
    scope_map = _as_mapping(assessment_map.get("scope"))
    for key in ("starts_at", "expires_at"):
        if key in scope_map:
            time_data[f"scope_{key}"] = scope_map[key]

    task_state_counts = Counter(
        str(item["state"]) for item in task_items if isinstance(item, Mapping) and "state" in item
    )
    state: dict[str, Any] = {"task_count": len(task_items)}
    if task_state_counts:
        state["task_state_counts"] = dict(sorted(task_state_counts.items()))
    if "state" in assessment_map:
        state["assessment_state"] = assessment_map["state"]

    supplied_tools = assessment_map.get("tools")
    if supplied_tools is not None:
        tools: Any = supplied_tools
    else:
        tools = []
        seen_tools: set[str] = set()
        for item in task_items:
            if isinstance(item, Mapping) and item.get("operation") is not None:
                operation = str(item["operation"])
                if operation not in seen_tools:
                    seen_tools.add(operation)
                    tools.append(operation)

    evidence = {
        "task_results": [
            {"id": item.get("id"), "result": item.get("result")}
            for item in task_items
            if isinstance(item, Mapping) and "result" in item
        ],
        "finding_evidence": [
            {"id": item.get("id"), "evidence": item.get("evidence")}
            for item in finding_items
            if isinstance(item, Mapping) and "evidence" in item
        ],
        "event_details": [
            {"id": item.get("id"), "details": item.get("details")}
            for item in event_items
            if isinstance(item, Mapping) and "details" in item
        ],
    }

    status_counts = Counter(
        str(item["status"])
        for item in finding_items
        if isinstance(item, Mapping) and "status" in item
    )
    candidate_status: dict[str, Any] = {"status_counts": dict(sorted(status_counts.items()))}
    if status_counts:
        candidate_status["candidate_count"] = sum(
            count for status, count in status_counts.items() if status.casefold() == "candidate"
        )

    recommendations = [
        item["recommendation"]
        for item in finding_items
        if isinstance(item, Mapping) and item.get("recommendation") not in (None, "")
    ]
    purple_metrics = purple_map.get("metrics", {}) if purple_map else {}
    purple_limitations = purple_map.get("limitations", []) if purple_map else []
    if isinstance(purple_limitations, str):
        purple_limitations = [purple_limitations]

    report_limitations = list(limitations)
    report_limitations.extend(str(item) for item in purple_limitations)
    report_limitations = list(dict.fromkeys(report_limitations))

    return {
        "schema": "secram-pro.assessment-report.v1",
        "generated_at": generated_at,
        "assessment": safe_assessment,
        "scope": scope_map,
        "time": time_data,
        "tools": tools,
        "state": state,
        "tasks": task_items,
        "findings": finding_items,
        "candidate_status": candidate_status,
        "evidence": evidence,
        "recommendations": recommendations,
        "events": event_items,
        "telemetry_contract": {
            "fields": _TELEMETRY_FIELDS,
            "note": "An observation is not confirmed compromise.",
        },
        "purple": safe_purple,
        "purple_metrics": purple_metrics,
        "limitations": report_limitations,
    }


def _markdown(report: Mapping[str, Any]) -> str:
    body = _pretty_json(report).replace("```", "`\\u0060``")
    return (
        "# SecRam-Pro Assessment Report\n\n"
        "Offline, local report generated from the supplied assessment snapshot.\n\n"
        "## Scope, time, tools, and state\n\n"
        "The canonical sanitized snapshot below contains the supplied scope, timing, "
        "tools, task state, evidence, and finding status.\n\n"
        "## Findings, candidate status, evidence, recommendations, and events\n\n"
        "Candidate findings remain candidate observations unless the input explicitly "
        "states another status.\n\n"
        "## Purple metrics and limitations\n\n"
        "Purple-team metrics are limited to the supplied local data.\n\n"
        "```json\n"
        f"{body}\n"
        "```\n"
    )


def _html_report(report: Mapping[str, Any]) -> str:
    # Escaping the complete untrusted serialized snapshot also covers attributes,
    # tags, scripts, and values nested at arbitrary depth.
    escaped = html.escape(_pretty_json(report), quote=True)
    generated = html.escape(str(report.get("generated_at", "")), quote=True)
    return (
        "<!doctype html>\n"
        '<html lang="en"><head><meta charset="utf-8">'
        "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"
        "<title>SecRam-Pro Assessment Report</title>"
        "<style>body{font-family:system-ui,sans-serif;max-width:1100px;margin:2rem auto;padding:0 1rem;line-height:1.45}"
        "pre{white-space:pre-wrap;background:#f5f5f5;padding:1rem;border-radius:.4rem}</style>"
        "</head><body>"
        "<h1>SecRam-Pro Assessment Report</h1>"
        "<p>Offline local snapshot; an observation is not confirmed compromise.</p>"
        f"<p>Generated: <time>{generated}</time></p>"
        f"<pre>{escaped}</pre>"
        "</body></html>\n"
    )


def _flatten(value: Any, path: str = "") -> list[tuple[str, Any]]:
    if isinstance(value, Mapping):
        if not value:
            return [(path, "")]
        rows: list[tuple[str, Any]] = []
        for key, item in value.items():
            child = f"{path}.{key}" if path else str(key)
            rows.extend(_flatten(item, child))
        return rows
    if isinstance(value, list):
        if not value:
            return [(path, "")]
        rows = []
        for index, item in enumerate(value):
            rows.extend(_flatten(item, f"{path}[{index}]"))
        return rows
    return [(path, value)]


def _csv_cell(value: Any) -> str:
    if value is None:
        text = ""
    elif isinstance(value, bool):
        text = "true" if value else "false"
    elif isinstance(value, str):
        text = value
    else:
        text = _canonical_json(value)
    if text.lstrip().startswith(tuple(_FORMULA_PREFIXES)):
        return "'" + text
    return text


def _csv_report(report: Mapping[str, Any]) -> str:
    output = io.StringIO(newline="")
    writer = csv.writer(output, lineterminator="\n")
    writer.writerow(("section", "field", "value"))
    for section, value in report.items():
        for field, item in _flatten(value, str(section)):
            writer.writerow((_csv_cell(section), _csv_cell(field), _csv_cell(item)))
    return output.getvalue()


def _find_dejavu() -> Path | None:
    candidates = (
        Path("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"),
        Path("/usr/local/share/fonts/truetype/dejavu/DejaVuSans.ttf"),
        Path.home() / ".local/share/fonts/truetype/dejavu/DejaVuSans.ttf",
    )
    for candidate in candidates:
        try:
            if candidate.is_file() and not candidate.is_symlink():
                return candidate
        except OSError:
            continue
    return None


def _pdf_capability() -> tuple[bool, Path | None, str | None]:
    try:
        import reportlab  # noqa: F401
    except ImportError:
        return False, None, "PDF unavailable: ReportLab is not installed; no PDF was fabricated."
    font_path = _find_dejavu()
    if font_path is None:
        return (
            True,
            None,
            "PDF uses a built-in fallback font because DejaVuSans was unavailable; "
            "non-ASCII glyph fidelity is limited.",
        )
    return True, font_path, None


def _pdf_bytes(report: Mapping[str, Any], font_path: Path | None) -> bytes:
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle
    from reportlab.lib.units import mm
    from reportlab.pdfbase import pdfmetrics
    from reportlab.pdfbase.ttfonts import TTFont
    from reportlab.platypus import Paragraph, Preformatted, SimpleDocTemplate, Spacer
    from xml.sax.saxutils import escape as xml_escape

    font_name = "SecRamDejaVuSans"
    unicode_supported = font_path is not None
    if font_path is not None:
        try:
            pdfmetrics.getFont(font_name)
        except KeyError:
            pdfmetrics.registerFont(TTFont(font_name, str(font_path)))
    else:
        font_name = "Helvetica"

    text = _pretty_json(report)
    if not unicode_supported:
        text = unicodedata.normalize("NFKD", text).encode("ascii", "replace").decode("ascii")
    style = ParagraphStyle(
        "SecRamReport",
        fontName=font_name,
        fontSize=8,
        leading=10,
        spaceAfter=4,
    )
    heading = ParagraphStyle(
        "SecRamHeading",
        parent=style,
        fontSize=15,
        leading=18,
        spaceAfter=8,
    )
    buffer = io.BytesIO()
    document = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        rightMargin=15 * mm,
        leftMargin=15 * mm,
        topMargin=15 * mm,
        bottomMargin=15 * mm,
        title="SecRam-Pro Assessment Report",
        author="SecRam-Pro offline exporter",
    )
    story = [
        Paragraph("SecRam-Pro Assessment Report", heading),
        Paragraph(
            xml_escape(
                "Offline local snapshot. An observation is not confirmed compromise."
            ),
            style,
        ),
        Spacer(1, 5 * mm),
        Preformatted(text, style, maxLineLength=120),
    ]
    document.build(story)
    return buffer.getvalue()


def _assert_no_symlink_components(path: Path) -> None:
    absolute = path.absolute()
    for component in (absolute, *absolute.parents):
        try:
            if stat.S_ISLNK(os.lstat(component).st_mode):
                raise ValueError(f"Refusing symlink path: {component}")
        except FileNotFoundError:
            continue


def _ensure_directory(path: Path) -> None:
    _assert_no_symlink_components(path)
    if path.exists():
        if not path.is_dir():
            raise ValueError(f"Output path is not a directory: {path}")
        return
    parent = path.parent
    _ensure_directory(parent)
    path.mkdir(mode=0o700)


def _new_bundle(output_dir: Path) -> Path:
    for _ in range(16):
        bundle = output_dir / f"secram-report-{uuid4().hex}"
        _assert_no_symlink_components(bundle)
        try:
            bundle.mkdir(mode=0o700)
            return bundle
        except FileExistsError:
            continue
    raise FileExistsError("Could not allocate a unique report bundle")


def _write_private(path: Path, content: bytes) -> None:
    _assert_no_symlink_components(path)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    descriptor = os.open(path, flags, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            descriptor = -1
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
    finally:
        if descriptor != -1:
            os.close(descriptor)


def _validate_formats(formats: Any) -> list[str]:
    if isinstance(formats, (str, bytes)):
        raise ValueError("formats must be an iterable of format names, not a string")
    try:
        values = list(formats)
    except TypeError as exc:
        raise ValueError("formats must be an iterable of format names") from exc
    result: list[str] = []
    for value in values:
        if not isinstance(value, str):
            raise ValueError(f"Unknown report format: {value!r}")
        normalized = value.casefold().lstrip(".")
        if normalized not in _FORMATS:
            raise ValueError(f"Unknown report format: {value!r}")
        if normalized not in result:
            result.append(normalized)
    return result


def export_assessment(
    assessment: dict,
    tasks: list[dict],
    findings: list[dict],
    events: list[dict],
    purple: dict,
    output_dir: Path,
    formats: tuple = ("json", "md", "html", "csv", "pdf"),
) -> dict[str, Any]:
    """Export a sanitized offline report bundle and return its paths and hashes.

    PDF is optional: if ReportLab is unavailable, the requested PDF is omitted and
    ``unavailable_formats`` plus ``limitations`` state that fact explicitly.
    """
    selected = _validate_formats(formats)
    output = Path(output_dir)
    _assert_no_symlink_components(output)
    _ensure_directory(output)

    generated_at = datetime.now(timezone.utc).isoformat()
    limitations = [
        "This is an offline export of supplied data; it performs no network or tool execution.",
        "An observation is not confirmed compromise.",
        "Candidate finding status and recommendations are copied from supplied input; they are not independently validated.",
        _MANIFEST_NOTE,
    ]
    unavailable: list[str] = []
    pdf_data: bytes | None = None
    font_path: Path | None = None
    if "pdf" in selected:
        capable, font_path, capability_note = _pdf_capability()
        if capability_note:
            limitations.append(capability_note)
        if not capable:
            unavailable.append("pdf")

    report = _build_report(
        assessment,
        tasks,
        findings,
        events,
        purple,
        generated_at,
        limitations,
    )

    if "pdf" in selected and "pdf" not in unavailable:
        try:
            pdf_data = _pdf_bytes(report, font_path)
        except Exception as exc:
            unavailable.append("pdf")
            pdf_data = None
            limitations.append(f"PDF unavailable: local ReportLab rendering failed ({type(exc).__name__}).")
            report = _build_report(
                assessment,
                tasks,
                findings,
                events,
                purple,
                generated_at,
                limitations,
            )

    payloads: dict[str, bytes] = {}
    if "json" in selected:
        payloads["json"] = (_canonical_json(report) + "\n").encode("utf-8")
    if "md" in selected:
        payloads["md"] = _markdown(report).encode("utf-8")
    if "html" in selected:
        payloads["html"] = _html_report(report).encode("utf-8")
    if "csv" in selected:
        payloads["csv"] = _csv_report(report).encode("utf-8")
    if "pdf" in selected and pdf_data is not None:
        payloads["pdf"] = pdf_data

    bundle = _new_bundle(output)
    files: dict[str, str] = {}
    hashes: dict[str, str] = {}
    manifest: dict[str, str] = {}
    suffixes = {"json": "json", "md": "md", "html": "html", "csv": "csv", "pdf": "pdf"}
    for format_name in selected:
        content = payloads.get(format_name)
        if content is None:
            continue
        path = bundle / f"assessment.{suffixes[format_name]}"
        _write_private(path, content)
        digest = hashlib.sha256(content).hexdigest()
        files[format_name] = str(path)
        hashes[format_name] = digest
        manifest[path.name] = digest

    manifest_payload = {
        "schema": "secram-pro.report-manifest.v1",
        "generated_at": generated_at,
        "files": {
            name: {"sha256": digest, "bytes": Path(bundle / name).stat().st_size}
            for name, digest in manifest.items()
        },
        "limitations": list(dict.fromkeys(limitations)),
        "note": _MANIFEST_NOTE,
    }
    manifest_bytes = (_canonical_json(manifest_payload) + "\n").encode("utf-8")
    manifest_path = bundle / "manifest.json"
    _write_private(manifest_path, manifest_bytes)

    final_limitations = list(dict.fromkeys(limitations))
    return {
        "bundle_dir": str(bundle),
        "files": files,
        "hashes": hashes,
        "manifest": manifest,
        "manifest_path": str(manifest_path),
        "manifest_sha256": hashlib.sha256(manifest_bytes).hexdigest(),
        "requested_formats": selected,
        "unavailable_formats": unavailable,
        "limitations": final_limitations,
    }


__all__ = ["export_assessment"]
