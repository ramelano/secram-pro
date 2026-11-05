from __future__ import annotations

from datetime import datetime, timedelta, timezone
from uuid import uuid4

from secram.modules.purple.correlation import correlate


BASE = datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc)


def task(task_id: str = "task-1", *, state: str = "succeeded", result=None, operation: str = "nmap.tcp_scan") -> dict:
    return {
        "id": task_id,
        "assessment_id": "assessment-1",
        "operation": operation,
        "target": "192.0.2.10",
        "port": 443,
        "started_at": BASE.isoformat().replace("+00:00", "Z"),
        "finished_at": (BASE + timedelta(minutes=1)).isoformat().replace("+00:00", "Z"),
        "state": state,
        "result": result if result is not None else {"scan_status": "complete"},
    }


def event(*, task_id=None, rule_id=None, observed_at=BASE + timedelta(seconds=20), **changes) -> dict:
    value = {
        "id": str(uuid4()),
        "observed_at": observed_at.isoformat().replace("+00:00", "Z"),
        "source": "test-telemetry",
        "event_type": "telemetry",
        "severity": "info",
        "details": {"fixture": True},
        "rule_id": rule_id,
        "target": "192.0.2.10",
        "port": 443,
        "task_id": task_id,
        "assessment_id": "assessment-1",
    }
    value.update(changes)
    return value


def coverage(*task_ids: str, **changes) -> dict:
    value = {
        "complete": True,
        "trusted": True,
        "task_ids": list(task_ids),
        "starts_at": (BASE - timedelta(seconds=1)).isoformat().replace("+00:00", "Z"),
        "ends_at": (BASE + timedelta(minutes=2)).isoformat().replace("+00:00", "Z"),
    }
    value.update(changes)
    return value


def test_explicit_task_rule_and_trusted_coverage_is_detection_and_maps_nmap():
    result = correlate(
        [task()],
        [event(task_id="task-1", rule_id="purple.network.discovery")],
        coverage("task-1"),
    )
    assert result["metrics"]["detection_status"] == "detected"
    assert result["metrics"]["detection_rate"] == 1.0
    detected = [item for item in result["timeline"] if item["classification"] == "detected"]
    assert len(detected) == 1
    task_item = next(item for item in result["timeline"] if item["kind"] == "task")
    assert task_item["attack_techniques"] == [
        {"technique_id": "T1046", "name": "Network Service Discovery"}
    ]


def test_no_alerts_are_unknown_without_coverage_but_not_detected_with_complete_coverage():
    no_coverage = correlate([task()], [])
    assert no_coverage["metrics"]["detection_status"] == "unknown"
    assert no_coverage["metrics"]["detection_rate"] is None

    complete = correlate([task()], [], coverage("task-1"))
    assert complete["metrics"]["detection_status"] == "not_detected"
    assert complete["metrics"]["detection_rate"] == 0.0


def test_temporal_endpoint_match_without_task_id_is_candidate_not_detection():
    result = correlate(
        [task()],
        [event(rule_id="purple.network.discovery", task_id=None)],
        coverage("task-1"),
    )
    assert result["metrics"]["detection_status"] == "unknown"
    assert result["metrics"]["candidate_correlations"] == 1
    assert not any(item["classification"] == "detected" for item in result["timeline"])


def test_observation_without_rule_is_not_detection_and_false_positive_needs_reviewed_negatives():
    result = correlate([task()], [event(task_id="task-1")], coverage("task-1"))
    assert result["metrics"]["observations"] == 1
    assert result["metrics"]["detected_tasks"] == 0
    assert result["metrics"]["false_positive_rate"] is None

    reviewed = correlate(
        [task()],
        [],
        coverage("task-1", reviewed_negative_data={"reviewed": True, "true_denominator": 4, "false_positives": 1}),
    )
    assert reviewed["metrics"]["false_positive_rate"] == 0.25


def test_wrong_assessment_target_and_time_are_ignored():
    wrong_assessment = event(task_id="task-1", rule_id="r", assessment_id="other")
    wrong_target = event(task_id="task-1", rule_id="r", target="192.0.2.11")
    wrong_time = event(task_id="task-1", rule_id="r", observed_at=BASE - timedelta(minutes=1))
    result = correlate([task()], [wrong_assessment, wrong_target, wrong_time], coverage("task-1"))
    assert result["metrics"]["events_considered"] == 0
    assert result["metrics"]["detected_tasks"] == 0
    assert all(item["kind"] == "task" for item in result["timeline"])


def test_failed_cancelled_and_inconclusive_tasks_are_not_denominator_or_link_targets():
    tasks = [
        task("failed", state="failed"),
        task("cancelled", state="cancelled"),
        task("inconclusive", result={"scan_status": "inconclusive"}),
        task("complete"),
    ]
    result = correlate(tasks, [event(task_id="inconclusive", rule_id="r")], coverage("complete"))
    assert result["metrics"]["tasks_executed"] == 1
    assert result["metrics"]["valid_test_denominator"] == 1
    assert result["metrics"]["events_considered"] == 0
    assert result["metrics"]["detection_rate"] == 0.0


def test_active_psutil_polling_does_not_establish_trusted_scan_coverage():
    result = correlate(
        [task(operation="unsupported.operation")],
        [],
        coverage("task-1", source="psutil.poll"),
    )
    task_item = next(item for item in result["timeline"] if item["kind"] == "task")
    assert task_item["attack_techniques"] == []
    assert result["metrics"]["coverage"] == "unknown"
    assert result["metrics"]["detection_status"] == "unknown"
    assert result["metrics"]["detection_rate"] is None
