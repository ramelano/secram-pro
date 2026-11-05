"""Conservative offline correlation of executed tasks and telemetry observations.

This module does not infer compromise.  A detection requires an explicit task
link, a rule identifier, and an explicitly trusted, complete coverage record.
"""
from __future__ import annotations

from datetime import datetime, timezone
from ipaddress import ip_address
from typing import Any
from uuid import UUID


_SEVERITIES = {"info", "low", "medium", "high"}
_BAD_STATES = {"failed", "cancelled", "inconclusive", "partial", "error", "unavailable", "data_unavailable", "unsupported", "notavailable"}
_COMPLETE_STATES = {"complete", "completed", "succeeded", "success"}
_OPERATION_TECHNIQUES: dict[str, list[dict[str, str]]] = {
    "nmap.tcp_scan": [
        {"technique_id": "T1046", "name": "Network Service Discovery"},
    ],
}


def _timestamp(value: Any) -> datetime | None:
    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, str):
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return None
    else:
        return None
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        return None
    return parsed.astimezone(timezone.utc)


def _iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _literal_target(value: Any) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or not value or value != value.strip() or "%" in value:
        return None
    try:
        address = ip_address(value)
    except ValueError:
        return None
    if address.is_multicast or address.is_unspecified or str(address) == "255.255.255.255":
        return None
    return str(address)


def _port(value: Any) -> int | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 65535:
        return None
    return value


def _same_target(left: str | None, right: str | None) -> bool:
    if left is None or right is None:
        return left == right
    return left == right


def _task_window(task: dict[str, Any]) -> tuple[datetime | None, datetime | None]:
    started = _timestamp(task.get("started_at", task.get("start")))
    finished = _timestamp(task.get("finished_at", task.get("finish")))
    return started, finished


def _result_state(result: dict[str, Any]) -> str | None:
    for key in ("scan_status", "status", "state"):
        value = result.get(key)
        if isinstance(value, str):
            return value.lower()
    if result.get("complete") is False:
        return "inconclusive"
    return None


def _normalize_task(raw: Any, limitations: list[str]) -> dict[str, Any] | None:
    if not isinstance(raw, dict):
        limitations.append("Ignored a non-dictionary task.")
        return None
    task_id = raw.get("id")
    assessment_id = raw.get("assessment_id")
    operation = raw.get("operation")
    if not all(isinstance(value, str) and value for value in (task_id, assessment_id, operation)):
        limitations.append("Ignored a task missing id, assessment_id, or operation.")
        return None
    started, finished = _task_window(raw)
    if started is None or finished is None or finished < started:
        limitations.append(f"Excluded task {task_id}: missing or invalid execution timestamps.")
        return None
    target = _literal_target(raw.get("target"))
    if raw.get("target") is not None and target is None:
        limitations.append(f"Excluded task {task_id}: target is not a literal IP.")
        return None
    raw_port = raw.get("port")
    port = _port(raw_port)
    if raw_port is not None and port is None:
        limitations.append(f"Excluded task {task_id}: port is invalid.")
        return None
    state = raw.get("state")
    state = state.value if hasattr(state, "value") else state
    state = state.lower() if isinstance(state, str) else ""
    result = raw.get("result")
    if not isinstance(result, dict):
        limitations.append(f"Excluded task {task_id}: result is not a dictionary.")
        return None
    result_state = _result_state(result)
    if state != "succeeded":
        limitations.append(f"Excluded task {task_id}: state {state or 'unknown'} is not succeeded.")
        return None
    if result_state in _BAD_STATES:
        limitations.append(f"Excluded task {task_id}: result is {result_state}.")
        return None
    return {
        "id": task_id,
        "assessment_id": assessment_id,
        "operation": operation,
        "target": target,
        "port": port,
        "started_at": started,
        "finished_at": finished,
        "state": state,
        "result_state": result_state or "complete",
        "attack_techniques": list(_OPERATION_TECHNIQUES.get(operation, [])),
    }


def _normalize_event(raw: Any, limitations: list[str]) -> dict[str, Any] | None:
    if not isinstance(raw, dict):
        limitations.append("Ignored a non-dictionary telemetry event.")
        return None
    event_id = raw.get("id")
    # UUID validation keeps the shared telemetry contract explicit while allowing
    # task IDs to remain application-defined strings.
    if not isinstance(event_id, str) or not event_id:
        limitations.append("Ignored telemetry without an event id.")
        return None
    try:
        UUID(event_id)
    except (ValueError, AttributeError):
        limitations.append(f"Ignored telemetry {event_id}: id is not a UUID.")
        return None
    observed_at = _timestamp(raw.get("observed_at"))
    source = raw.get("source")
    event_type = raw.get("event_type")
    severity = raw.get("severity")
    if observed_at is None or not isinstance(source, str) or not source:
        limitations.append(f"Ignored telemetry {event_id}: timestamp or source is invalid.")
        return None
    if not isinstance(event_type, str) or not event_type:
        limitations.append(f"Ignored telemetry {event_id}: event_type is invalid.")
        return None
    if severity not in _SEVERITIES:
        limitations.append(f"Ignored telemetry {event_id}: severity is invalid.")
        return None
    details = raw.get("details")
    if not isinstance(details, dict):
        limitations.append(f"Ignored telemetry {event_id}: details is not a dictionary.")
        return None
    rule_id = raw.get("rule_id")
    if rule_id is not None and (not isinstance(rule_id, str) or not rule_id):
        limitations.append(f"Ignored telemetry {event_id}: rule_id is invalid.")
        return None
    target = _literal_target(raw.get("target"))
    if raw.get("target") is not None and target is None:
        limitations.append(f"Ignored telemetry {event_id}: target is not a literal IP.")
        return None
    raw_port = raw.get("port")
    port = _port(raw_port)
    if raw_port is not None and port is None:
        limitations.append(f"Ignored telemetry {event_id}: port is invalid.")
        return None
    task_id = raw.get("task_id")
    assessment_id = raw.get("assessment_id")
    if task_id is not None and (not isinstance(task_id, str) or not task_id):
        limitations.append(f"Ignored telemetry {event_id}: task_id is invalid.")
        return None
    if assessment_id is not None and (not isinstance(assessment_id, str) or not assessment_id):
        limitations.append(f"Ignored telemetry {event_id}: assessment_id is invalid.")
        return None
    return {
        "id": event_id,
        "observed_at": observed_at,
        "source": source,
        "event_type": event_type,
        "severity": severity,
        "details": details,
        "rule_id": rule_id,
        "target": target,
        "port": port,
        "task_id": task_id,
        "assessment_id": assessment_id,
    }


def _coverage_window(coverage: dict[str, Any]) -> tuple[datetime | None, datetime | None]:
    nested = coverage.get("window")
    values = nested if isinstance(nested, dict) else coverage
    start = next((values.get(key) for key in ("starts_at", "started_at", "start")), None)
    finish = next((values.get(key) for key in ("ends_at", "finished_at", "finish", "end")), None)
    return _timestamp(start), _timestamp(finish)


def _coverage_evidence(coverage: dict[str, Any]) -> tuple[set[str], set[str]]:
    task_ids: set[str] = set()
    operations: set[str] = set()
    for value in coverage.get("task_ids", []):
        if isinstance(value, str) and value:
            task_ids.add(value)
    for value in coverage.get("observed_operations", []):
        if isinstance(value, str) and value:
            operations.add(value)
        elif isinstance(value, dict) and isinstance(value.get("operation"), str):
            operations.add(value["operation"])
            if isinstance(value.get("task_id"), str):
                task_ids.add(value["task_id"])
    return task_ids, operations


def _trusted_coverage(coverage: Any, tasks: list[dict[str, Any]], limitations: list[str]) -> tuple[bool, set[str]]:
    if not isinstance(coverage, dict):
        limitations.append("Coverage is unknown: no explicit coverage record was supplied.")
        return False, set()
    source = str(coverage.get("source", "")).lower()
    if "psutil" in source or coverage.get("packet_coverage") is False:
        limitations.append("Active psutil polling does not establish packet or scan coverage.")
        return False, set()
    complete = coverage.get("complete") is True or str(
        coverage.get("status", coverage.get("state", ""))
    ).lower() in _COMPLETE_STATES
    trusted = coverage.get("trusted") is True or coverage.get("evidence_trusted") is True
    nested_evidence = coverage.get("evidence")
    if isinstance(nested_evidence, dict) and nested_evidence.get("trusted") is True:
        trusted = True
    start, finish = _coverage_window(coverage)
    task_ids, operations = _coverage_evidence(coverage)
    if not complete or not trusted or start is None or finish is None or finish < start:
        limitations.append("Coverage is not an explicitly complete, trusted, applicable window.")
        return False, set()
    if not task_ids and not operations:
        limitations.append("Coverage has no trusted task_ids or observed_operations evidence.")
        return False, set()
    applicable: set[str] = set()
    for task in tasks:
        if task["id"] not in task_ids and task["operation"] not in operations:
            continue
        if start <= task["started_at"] and task["finished_at"] <= finish:
            applicable.add(task["id"])
    if not applicable:
        limitations.append("Coverage window does not apply to any completed task.")
        return False, set()
    return True, applicable


def _in_window(event: dict[str, Any], task: dict[str, Any]) -> bool:
    return task["started_at"] <= event["observed_at"] <= task["finished_at"]


def _endpoint_matches(event: dict[str, Any], task: dict[str, Any]) -> bool:
    return (
        event["assessment_id"] == task["assessment_id"]
        and event["target"] is not None
        and _same_target(event["target"], task["target"])
        and (event["port"] is None or event["port"] == task["port"])
        and _in_window(event, task)
    )


def _is_alert(event: dict[str, Any]) -> bool:
    if event["rule_id"] is None:
        return False
    event_type = event["event_type"].lower()
    return event_type.startswith(("alert", "detect", "finding")) or event["rule_id"] is not None


def _negative_rate(coverage: Any) -> float | None:
    if not isinstance(coverage, dict):
        return None
    negative = coverage.get("reviewed_negative_data", coverage.get("negatives"))
    if not isinstance(negative, dict) or negative.get("reviewed") is not True:
        return None
    denominator = negative.get("true_denominator", negative.get("total"))
    false_positives = negative.get("false_positives")
    if (
        isinstance(denominator, bool)
        or not isinstance(denominator, int)
        or denominator <= 0
        or isinstance(false_positives, bool)
        or not isinstance(false_positives, int)
        or not 0 <= false_positives <= denominator
    ):
        return None
    return false_positives / denominator


def correlate(
    tasks: list[dict], events: list[dict], coverage: dict | None = None
) -> dict:
    """Correlate task windows with telemetry without claiming causation.

    ``timeline`` contains only valid completed task windows and valid telemetry
    events that belong to one of those windows.  Endpoint/time matches are
    candidates; only explicit task IDs plus a rule and trusted coverage are
    detections.
    """
    limitations: list[str] = []
    normalized_tasks: list[dict[str, Any]] = []
    seen_task_ids: set[str] = set()
    for raw in tasks:
        task = _normalize_task(raw, limitations)
        if task is None:
            continue
        if task["id"] in seen_task_ids:
            limitations.append(f"Excluded duplicate task {task['id']}.")
            continue
        seen_task_ids.add(task["id"])
        normalized_tasks.append(task)
    normalized_tasks.sort(key=lambda item: (item["started_at"], item["id"]))

    valid_events: list[dict[str, Any]] = []
    for raw in events:
        event = _normalize_event(raw, limitations)
        if event is not None:
            valid_events.append(event)
    trusted, applicable_ids = _trusted_coverage(coverage, normalized_tasks, limitations)

    timeline: list[dict[str, Any]] = []
    for task in normalized_tasks:
        timeline.append(
            {
                "kind": "task",
                "timestamp": _iso(task["started_at"]),
                "task_id": task["id"],
                "assessment_id": task["assessment_id"],
                "operation": task["operation"],
                "target": task["target"],
                "port": task["port"],
                "started_at": _iso(task["started_at"]),
                "finished_at": _iso(task["finished_at"]),
                "state": task["state"],
                "result_status": task["result_state"],
                "attack_techniques": task["attack_techniques"],
                "classification": "executed_test",
            }
        )

    candidate_count = 0
    observation_count = 0
    alert_count = 0
    considered_events = 0
    detected_task_ids: set[str] = set()
    detection_latencies = []
    matched_event_ids: set[str] = set()
    for event in sorted(valid_events, key=lambda item: (item["observed_at"], item["id"])):
        explicit_task = None
        matched_tasks: list[dict[str, Any]] = []
        if event["task_id"] is not None:
            explicit_task = next(
                (task for task in normalized_tasks if task["id"] == event["task_id"]), None
            )
            if explicit_task is None:
                limitations.append(f"Ignored telemetry {event['id']}: task_id is not a valid completed task.")
                continue
            if event["assessment_id"] not in (None, explicit_task["assessment_id"]):
                limitations.append(f"Ignored telemetry {event['id']}: assessment_id does not match task.")
                continue
            if event["target"] is not None and not _same_target(event["target"], explicit_task["target"]):
                limitations.append(f"Ignored telemetry {event['id']}: target does not match task.")
                continue
            if event["port"] is not None and event["port"] != explicit_task["port"]:
                limitations.append(f"Ignored telemetry {event['id']}: port does not match task.")
                continue
            if not _in_window(event, explicit_task):
                limitations.append(f"Ignored telemetry {event['id']}: observed_at is outside task window.")
                continue
            matched_tasks = [explicit_task]
            linkage = "explicit_task_id"
        else:
            if event["assessment_id"] is None:
                limitations.append(f"Ignored telemetry {event['id']}: no assessment_id or task_id.")
                continue
            matched_tasks = [task for task in normalized_tasks if _endpoint_matches(event, task)]
            if not matched_tasks:
                limitations.append(f"Ignored telemetry {event['id']}: no matching assessment, endpoint, and time.")
                continue
            linkage = "endpoint_and_time"
        considered_events += 1
        matched_event_ids.add(event["id"])
        alert = _is_alert(event)
        if alert:
            alert_count += 1
        if event["rule_id"] is None:
            classification = "observation"
            observation_count += 1
        elif explicit_task is not None and trusted and explicit_task["id"] in applicable_ids:
            classification = "detected"
            detected_task_ids.add(explicit_task["id"])
            detection_latencies.append((event["observed_at"] - explicit_task["started_at"]).total_seconds())
        else:
            classification = "candidate"
            candidate_count += 1
        timeline.append(
            {
                "kind": "event",
                "timestamp": _iso(event["observed_at"]),
                "event_id": event["id"],
                "assessment_id": event["assessment_id"],
                "task_id": event["task_id"],
                "matched_task_ids": [task["id"] for task in matched_tasks],
                "source": event["source"],
                "event_type": event["event_type"],
                "severity": event["severity"],
                "rule_id": event["rule_id"],
                "target": event["target"],
                "port": event["port"],
                "details": event["details"],
                "telemetry": {
                    "id": event["id"],
                    "observed_at": _iso(event["observed_at"]),
                    "source": event["source"],
                    "event_type": event["event_type"],
                    "severity": event["severity"],
                    "details": event["details"],
                    "rule_id": event["rule_id"],
                    "target": event["target"],
                    "port": event["port"],
                    "task_id": event["task_id"],
                    "assessment_id": event["assessment_id"],
                },
                "classification": classification,
                "linkage": linkage,
                "alert": alert,
            }
        )

    timeline.sort(key=lambda item: (item["timestamp"], item["kind"], item.get("task_id") or item.get("event_id") or ""))
    denominator = len(applicable_ids) if trusted else 0
    detection_rate = len(detected_task_ids) / denominator if denominator else None
    false_positive_rate = _negative_rate(coverage)
    if detected_task_ids:
        detection_status = "detected"
    elif candidate_count:
        detection_status = "unknown"
    elif trusted and denominator:
        detection_status = "not_detected"
    else:
        detection_status = "unknown"

    metrics = {
        "tasks_total": len(tasks),
        "tasks_executed": len(normalized_tasks),
        "tasks_excluded": len(tasks) - len(normalized_tasks),
        "events_total": len(events),
        "events_considered": considered_events,
        "events_ignored": len(valid_events) - len(matched_event_ids),
        "observations": observation_count,
        "alerts": alert_count,
        "candidate_correlations": candidate_count,
        "detected_tasks": len(detected_task_ids),
        "valid_test_denominator": denominator,
        "coverage": "trusted_complete" if trusted else "unknown",
        "detection_status": detection_status,
        "detection_rate": detection_rate,
        "false_positive_rate": false_positive_rate,
        "mean_verified_detection_latency_seconds": sum(detection_latencies) / len(detection_latencies) if detection_latencies else None,
    }
    if not normalized_tasks:
        limitations.append("No completed, conclusive tasks were available for correlation.")
    if false_positive_rate is None:
        limitations.append("False-positive rate is unknown without explicitly reviewed negative data and a true denominator.")
    if candidate_count:
        limitations.append("Endpoint/time correlations are candidates only; they do not prove causation or compromise.")
    return {"timeline": timeline, "metrics": metrics, "limitations": list(dict.fromkeys(limitations))}


__all__ = ["correlate"]
