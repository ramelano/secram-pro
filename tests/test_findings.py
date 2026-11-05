from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from secram.core.models import Task
from secram.modules.vulnerability.findings import (
    Finding,
    FindingStatus,
    Severity,
    merge_findings,
    normalize_findings,
)


COLLECTED = datetime(2026, 1, 2, 3, 4, 5, tzinfo=timezone.utc)


def make_task(*, assessment_id="assessment-1", task_id="task-1", target="192.0.2.10", port=443):
    return Task(
        id=task_id,
        assessment_id=assessment_id,
        name="web check",
        operation="web.http_headers",
        target=target,
        port=port,
    )


def make_result(*, target="192.0.2.10", port=443, status="complete", candidates=None, collected_at=COLLECTED, operation="web.http_headers", observations=None):
    return {
        "operation": operation,
        "target": target,
        "port": port,
        "collected_at": collected_at,
        "status": status,
        "observations": observations or {},
        "finding_candidates": [] if candidates is None else candidates,
        "limitations": ["configuration observation only"],
    }


def candidate(*, rule_id="http.hsts", severity="low", evidence=None, title="HSTS is absent", recommendation="Enable HSTS", limitations=None):
    return {
        "rule_id": rule_id,
        "title": title,
        "severity": severity,
        "evidence": {"header": "missing"} if evidence is None else evidence,
        "recommendation": recommendation,
        "limitations": [] if limitations is None else limitations,
    }


def test_normalize_adds_provenance_and_keeps_candidate_status():
    task = make_task()
    findings = normalize_findings(
        task,
        make_result(
            observations={"evidence_sha256": "a" * 64, "observation_confirmed": True},
            candidates=[candidate()],
        ),
    )

    assert len(findings) == 1
    finding = findings[0]
    assert finding.status is FindingStatus.CANDIDATE
    assert finding.severity is Severity.LOW
    assert finding.evidence == [
        {
            "header": "missing",
            "evidence_sha256": "a" * 64,
            "source_operation": "web.http_headers",
            "source_task_id": task.id,
        }
    ]
    assert "configuration observation only" in finding.limitations
    assert finding.observed_at == COLLECTED


def test_id_is_deterministic_for_canonical_ipv6():
    first = normalize_findings(
        make_task(target="2001:0db8:0:0:0:0:0:1"),
        make_result(target="2001:db8::1", candidates=[candidate()]),
    )[0]
    second = normalize_findings(
        make_task(task_id="task-2", target="2001:db8::1"),
        make_result(target="2001:0db8::1", candidates=[candidate()]),
    )[0]

    assert first.target == "2001:db8::1"
    assert first.id == second.id


def test_result_identity_mismatch_is_rejected():
    task = make_task()
    with pytest.raises(ValueError):
        normalize_findings(task, make_result(target="192.0.2.11", candidates=[candidate()]))
    with pytest.raises(ValueError):
        normalize_findings(task, make_result(port=8443, candidates=[candidate()]))


def test_malformed_candidate_and_cve_are_rejected_by_forbid():
    malformed = candidate()
    malformed["unexpected"] = True
    with pytest.raises(ValidationError):
        normalize_findings(make_task(), make_result(candidates=[malformed]))

    with pytest.raises(ValidationError):
        normalize_findings(
            make_task(),
            make_result(candidates=[{**candidate(), "cve": "CVE-2099-0001"}]),
        )


def test_timezone_and_status_validation():
    with pytest.raises(ValidationError):
        normalize_findings(
            make_task(),
            make_result(collected_at=datetime(2026, 1, 2, 3, 4, 5), candidates=[]),
        )
    with pytest.raises(ValidationError):
        Finding(
            assessment_id="assessment-1",
            rule_id="http.hsts",
            title="HSTS is absent",
            target="192.0.2.10",
            port=443,
            severity=Severity.LOW,
            status="unknown",
            evidence=[],
            recommendation="Enable HSTS",
            limitations=[],
            observed_at=datetime(2026, 1, 2, 3, 4, 5),
            task_ids=["task-1"],
        )


def test_inconclusive_result_cannot_invent_findings():
    assert normalize_findings(make_task(), make_result(status="inconclusive", candidates=[])) == []
    with pytest.raises(ValueError):
        normalize_findings(
            make_task(),
            make_result(status="inconclusive", candidates=[candidate()]),
        )


def test_merge_deduplicates_evidence_and_preserves_conservative_candidate():
    base = dict(
        assessment_id="assessment-1",
        rule_id="http.hsts",
        title="HSTS is absent",
        target="192.0.2.10",
        port=443,
        severity=Severity.LOW,
        status=FindingStatus.CANDIDATE,
        evidence=[{"header": "missing", "source": "same"}],
        recommendation="Enable HSTS",
        limitations=["z", "a"],
        observed_at=COLLECTED,
        task_ids=["task-2"],
    )
    first = Finding(**base)
    second = Finding(**{**base, "severity": Severity.MEDIUM, "limitations": ["b"], "task_ids": ["task-1"]})

    forward = merge_findings([first, second])
    reverse = merge_findings([second, first])
    assert forward[0].model_dump(mode="json") == reverse[0].model_dump(mode="json")
    merged = forward[0]
    assert merged.status is FindingStatus.CANDIDATE
    assert merged.severity is Severity.MEDIUM
    assert merged.evidence == [{"header": "missing", "source": "same"}]
    assert merged.limitations == ["a", "b", "z"]
    assert merged.task_ids == ["task-1", "task-2"]


def test_merge_does_not_cross_assessments():
    first = normalize_findings(make_task(assessment_id="assessment-1"), make_result(candidates=[candidate()]))[0]
    second = normalize_findings(make_task(assessment_id="assessment-2", task_id="task-2"), make_result(candidates=[candidate()]))[0]

    merged = merge_findings([second, first])
    assert len(merged) == 2
    assert {item.assessment_id for item in merged} == {"assessment-1", "assessment-2"}
