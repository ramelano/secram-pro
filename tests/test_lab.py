from __future__ import annotations

import http.client
import json
import os
from pathlib import Path

import pytest

from secram.lab import manager as manager_module
from secram.lab.manager import LabManager


def test_missing_unshare_fails_honestly_without_fallback(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(manager_module, "_find_unshare", lambda: None)
    manager = LabManager(tmp_path / "lab")
    try:
        result = manager.create()
        assert result["status"] == "notavailable"
        assert result["port"] is None
        assert "unshare" in result["reason"]
        assert not (tmp_path / "lab" / "fixture.sock").exists()
    finally:
        manager.close()


def test_symlinked_ipc_path_is_rejected_without_following(tmp_path: Path) -> None:
    data_dir = tmp_path / "lab"
    data_dir.mkdir(mode=0o700)
    target = tmp_path / "outside"
    target.write_text("do not touch", encoding="utf-8")
    os.symlink(target, data_dir / "fixture.sock")
    manager = LabManager(data_dir)
    try:
        result = manager.create()
        assert result["status"] == "notavailable"
        assert "symlink" in result["reason"]
        assert target.read_text(encoding="utf-8") == "do not touch"
        assert (data_dir / "fixture.sock").is_symlink()
    finally:
        manager.close()


def test_rootless_fixture_http_and_telemetry(tmp_path: Path) -> None:
    manager = LabManager(tmp_path / "lab")
    try:
        created = manager.create()
        if created["status"] == "notavailable":
            pytest.skip(f"rootless unshare integration unavailable: {created.get('reason', 'unknown')}")
        assert created["status"] == "running"
        assert created["target"] == "127.0.0.1"
        assert isinstance(created["port"], int) and created["port"] > 0
        assert Path(created["telemetry_path"]).is_file()

        connection = http.client.HTTPConnection("127.0.0.1", created["port"], timeout=3)
        connection.request("HEAD", "/")
        head = connection.getresponse()
        assert head.status == 200
        assert head.read() == b""
        assert head.getheader("Content-Length") == str(len(
            b"<!doctype html><html><head><title>SecRam educational fixture</title>"
            b"</head><body><h1>SecRam educational HTTP fixture</h1>"
            b"<p>This page intentionally omits common security response headers.</p>"
            b"</body></html>"
        ))
        connection.close()

        connection = http.client.HTTPConnection("127.0.0.1", created["port"], timeout=3)
        connection.request("GET", "/")
        get = connection.getresponse()
        body = get.read()
        assert get.status == 200
        assert b"intentionally omits common security response headers" in body
        assert get.getheader("Content-Security-Policy") is None
        connection.close()

        telemetry_lines = Path(created["telemetry_path"]).read_text(encoding="utf-8").splitlines()
        events = [json.loads(line) for line in telemetry_lines if line.strip()]
        assert len(events) >= 2
        for event in events[-2:]:
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
            assert event["source"] == "lab_sensor"
            assert event["event_type"] == "http.request"
            assert event["severity"] == "info"
            assert event["target"] == "127.0.0.1"
            assert event["port"] == created["port"]
            assert event["rule_id"] is None
            assert event["task_id"] is None
            assert event["assessment_id"] is None
            assert event["details"]["status"] == 200
    finally:
        stopped = manager.stop()
        assert stopped["status"] == "notavailable"
        assert not (tmp_path / "lab" / "fixture.sock").exists()
        assert not (tmp_path / "lab" / "worker.ready").exists()
        process = manager._process
        assert process is None or process.poll() is not None
        manager.close()
