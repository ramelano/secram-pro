from __future__ import annotations

from datetime import datetime
from types import SimpleNamespace

import psutil

from secram.platforms.linux.host import LinuxHostProvider


def test_real_snapshot_shape_and_resources() -> None:
    snapshot = LinuxHostProvider(max_processes=3, max_services=2).collect()

    assert snapshot["operation"] == "host.snapshot"
    assert datetime.fromisoformat(snapshot["collected_at"]).tzinfo is not None
    assert snapshot["status"] in {"ok", "partial"}

    cpu = snapshot["cpu"]
    assert cpu["logical_count"] > 0
    assert cpu["percent"] >= 0
    assert len(cpu["load_avg"]) == 3

    memory = snapshot["memory"]
    assert memory["total"] > 0
    assert memory["available"] >= 0
    assert memory["used"] >= 0
    assert 0 <= memory["percent"] <= 100

    storage = snapshot["storage"]
    assert storage["total"] > 0
    assert storage["used"] >= 0
    assert storage["free"] >= 0
    assert 0 <= storage["percent"] <= 100

    processes = snapshot["processes"]
    assert len(processes["items"]) <= 3
    assert processes["total"] >= processes["observed_count"]
    assert isinstance(processes["truncated"], bool)
    assert isinstance(processes["access_denied"], bool)
    for process in processes["items"]:
        assert set(process) == {"pid", "name", "status"}

    network = snapshot["network"]
    assert isinstance(network["interfaces"], list)
    for interface in network["interfaces"]:
        assert set(interface) == {"interface", "family", "address", "netmask"}

    services = snapshot["services"]
    assert services["status"] in {"ok", "unavailable", "error"}
    assert len(services["items"]) <= 2
    for service in services["items"]:
        assert set(service) == {"name", "load", "active", "sub"}


def test_missing_systemd_is_unavailable_without_fake_services(monkeypatch) -> None:
    monkeypatch.setattr("secram.platforms.linux.host.os.path.isdir", lambda path: False)

    snapshot = LinuxHostProvider().collect()

    assert snapshot["services"] == {
        "status": "unavailable",
        "items": [],
        "detail": "systemd is not running on this host.",
        "total": 0,
        "truncated": False,
    }
    assert snapshot["status"] == "partial"
    assert any("systemd is not running" in item for item in snapshot["limitations"])


def test_process_permission_denial_is_explicit(monkeypatch) -> None:
    def denied_process_iter(*, attrs):
        raise psutil.AccessDenied(pid=123)

    monkeypatch.setattr(
        "secram.platforms.linux.host.psutil.process_iter", denied_process_iter
    )
    monkeypatch.setattr("secram.platforms.linux.host.os.path.isdir", lambda path: False)

    snapshot = LinuxHostProvider().collect()

    assert snapshot["processes"]["items"] == []
    assert snapshot["processes"]["access_denied"] is True
    assert any("permissions" in item for item in snapshot["limitations"])
    assert snapshot["status"] == "partial"


def test_process_and_service_limits_bound_results(monkeypatch) -> None:
    fake_processes = [
        SimpleNamespace(info={"pid": pid, "name": f"proc-{pid}", "status": "running"})
        for pid in (1, 2, 3)
    ]
    monkeypatch.setattr(
        "secram.platforms.linux.host.psutil.process_iter",
        lambda *, attrs: iter(fake_processes),
    )
    monkeypatch.setattr("secram.platforms.linux.host.os.path.isdir", lambda path: True)
    monkeypatch.setattr("secram.platforms.linux.host.shutil.which", lambda name: "/bin/systemctl")

    class Completed:
        returncode = 0

    def fake_run(command, *, stdout, stderr, timeout, check, shell):
        stdout.write(
            b"a.service loaded active running A\n"
            b"b.service loaded inactive dead B\n"
            b"c.service not-found inactive dead C\n"
        )
        return Completed()

    monkeypatch.setattr("secram.platforms.linux.host.subprocess.run", fake_run)

    snapshot = LinuxHostProvider(max_processes=1, max_services=1).collect()

    assert len(snapshot["processes"]["items"]) == 1
    assert snapshot["processes"]["total"] == 3
    assert snapshot["processes"]["truncated"] is True
    assert len(snapshot["services"]["items"]) == 1
    assert snapshot["services"]["total"] == 3
    assert snapshot["services"]["truncated"] is True
    assert snapshot["status"] == "partial"
    assert any("Process list truncated" in item for item in snapshot["limitations"])
    assert any("Service list truncated" in item for item in snapshot["limitations"])


def test_systemctl_permission_error_is_reported(monkeypatch) -> None:
    monkeypatch.setattr("secram.platforms.linux.host.os.path.isdir", lambda path: True)
    monkeypatch.setattr("secram.platforms.linux.host.shutil.which", lambda name: "/bin/systemctl")

    def denied_run(*args, **kwargs):
        raise PermissionError("denied")

    monkeypatch.setattr("secram.platforms.linux.host.subprocess.run", denied_run)

    snapshot = LinuxHostProvider().collect()

    assert snapshot["services"]["status"] == "error"
    assert snapshot["services"]["items"] == []
    assert "permissions" in snapshot["services"]["detail"]
    assert snapshot["status"] == "partial"
