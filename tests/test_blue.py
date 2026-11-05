from __future__ import annotations

from pathlib import Path
import time

import pytest

from secram.modules.blue.monitor import BlueMonitor


def wait_for(predicate, timeout: float = 4.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.05)
    return predicate()


def assert_contract(event: dict) -> None:
    assert set(event) == {
        "id",
        "observed_at",
        "source",
        "event_type",
        "severity",
        "details",
        "rule_id",
        "target",
        "port",
        "task_id",
        "assessment_id",
    }
    assert isinstance(event["id"], str) and len(event["id"]) == 36
    assert event["observed_at"].endswith("+00:00")
    assert event["severity"] in {"info", "low", "medium", "high"}
    assert isinstance(event["details"], dict)
    assert event["task_id"] is None
    assert event["assessment_id"] is None


def test_real_psutil_baseline_and_contract() -> None:
    callbacks: list[dict] = []
    monitor = BlueMonitor(callbacks.append, interval=0.5, max_events=32)
    monitor.start()
    try:
        assert wait_for(lambda: monitor.snapshot()["event_count"] >= 3)
        snapshot = monitor.snapshot()
        assert {"host", "process", "network"} <= set(snapshot["sources"])
        assert snapshot["sources"]["host"] in {"active", "limited", "unavailable"}
        assert snapshot["sources"]["process"] in {"active", "limited", "unavailable"}
        assert snapshot["sources"]["network"] in {"active", "limited", "unavailable"}
        for event in callbacks:
            assert_contract(event)
        assert not any(event["event_type"] in {"process.start", "network.ioc.match"} for event in callbacks)
    finally:
        monitor.stop()


def test_auth_log_tails_only_new_appends_and_redacts(tmp_path: Path) -> None:
    auth_log = tmp_path / "auth.log"
    auth_log.write_text("Nov  3 20:00:00 sshd: Failed password=oldsecret from 192.0.2.1 port 22\n")
    callbacks: list[dict] = []
    monitor = BlueMonitor(callbacks.append, interval=0.5, max_events=64)
    monitor.start(auth_log=auth_log)
    try:
        assert wait_for(lambda: monitor.snapshot()["sources"]["auth_log"] == "active")
        assert not any(event["event_type"] == "auth.failure" for event in callbacks)
        with auth_log.open("a", encoding="utf-8") as handle:
            handle.write(
                "2026-11-03T21:02:52+00:00 sshd: Failed password=topsecret "
                "for invalid user demo from 203.0.113.10 port 2222 ssh2\n"
            )
        assert wait_for(lambda: any(event["event_type"] == "auth.failure" for event in callbacks))
        event = next(event for event in callbacks if event["event_type"] == "auth.failure")
        assert event["target"] == "203.0.113.10"
        assert event["port"] == 2222
        assert event["details"]["timestamp_quality"] == "event"
        assert "topsecret" not in event["details"]["rawline"]
        assert "[REDACTED]" in event["details"]["rawline"]
        assert len(event["details"]["rawline"]) <= 512
    finally:
        monitor.stop()


def test_integrity_change_is_observed_not_claimed_compromise(tmp_path: Path) -> None:
    watched = tmp_path / "watched.conf"
    watched.write_bytes(b"before\n")
    callbacks: list[dict] = []
    monitor = BlueMonitor(callbacks.append, interval=0.5, max_events=64)
    monitor.start(integrity_paths=[watched])
    try:
        assert wait_for(lambda: monitor.snapshot()["sources"]["integrity"] == "active")
        watched.write_bytes(b"after\n")
        assert wait_for(
            lambda: any(event["event_type"] == "file.integrity.changed" for event in callbacks)
        )
        event = next(event for event in callbacks if event["event_type"] == "file.integrity.changed")
        assert event["severity"] == "medium"
        assert event["details"]["path"] == str(watched)
        assert event["details"]["previous_sha256"] != event["details"]["current_sha256"]
        assert "not proof" in event["details"]["observation_note"]
    finally:
        monitor.stop()


def test_stop_prevents_late_callbacks() -> None:
    callbacks: list[dict] = []
    monitor = BlueMonitor(callbacks.append, interval=0.5, max_events=32)
    monitor.start()
    assert wait_for(lambda: monitor.snapshot()["event_count"] >= 1)
    monitor.stop()
    count = len(callbacks)
    time.sleep(0.8)
    assert len(callbacks) == count
    assert monitor.snapshot()["running"] is False


def test_event_ring_cap_and_file_error_are_reported(tmp_path: Path) -> None:
    callbacks: list[dict] = []
    missing = tmp_path / "missing.conf"
    monitor = BlueMonitor(callbacks.append, interval=0.5, max_events=1)
    monitor.start(integrity_paths=[missing])
    try:
        assert wait_for(lambda: monitor.snapshot()["event_count"] == 1)
        snapshot = monitor.snapshot()
        assert snapshot["dropped"] > 0
        assert any("integrity unavailable" in item for item in snapshot["limitations"])
    finally:
        monitor.stop()


def test_network_permission_error_is_unavailable(monkeypatch: pytest.MonkeyPatch) -> None:
    import secram.modules.blue.monitor as blue_monitor

    def denied(*args, **kwargs):
        raise PermissionError("test denial")

    monkeypatch.setattr(blue_monitor.psutil, "net_connections", denied)
    monitor = BlueMonitor(lambda event: None, interval=0.5)
    monitor.start()
    try:
        assert wait_for(lambda: monitor.snapshot()["sources"]["network"] == "unavailable")
        assert any("network observation unavailable" in item for item in monitor.snapshot()["limitations"])
    finally:
        monitor.stop()


def test_bounds_and_literal_ioc_validation() -> None:
    with pytest.raises(ValueError):
        BlueMonitor(lambda event: None, interval=0.49)
    with pytest.raises(ValueError):
        BlueMonitor(lambda event: None, interval=60.01)
    monitor = BlueMonitor(lambda event: None, interval=0.5)
    with pytest.raises(ValueError):
        monitor.start(ioc_ips={"example.test"})
