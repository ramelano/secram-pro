import asyncio
import socket
import sys
from datetime import timedelta

import pytest

from secram.core.models import Assessment, Authorization, Scope, utcnow
from secram.tools.adapters.nmap import NmapAdapter
from secram.tools.base import ToolRequest


def _assessment(port: int, *, operations: set[str] | None = None, allowed_ports: set[int] | None = None) -> Assessment:
    return Assessment(
        title="Nmap local integration",
        scope=Scope(
            cidrs=["127.0.0.1/32"],
            allowed_operations=operations or {"nmap.tcp_scan"},
            allowed_ports=allowed_ports if allowed_ports is not None else {port},
            expires_at=utcnow() + timedelta(minutes=10),
        ),
        authorization=Authorization(
            approved_by="local-test-owner",
            evidence_reference="test_nmap.py",
            statement="Temporary loopback listener only",
        ),
    )


def _request(port: int, *, assessment: Assessment | None = None, **kwargs) -> ToolRequest:
    values = {
        "operation": "tcp_scan",
        "timeout": 20,
        "target": "127.0.0.1",
        "parameters": {"ports": [port]},
        "assessment": assessment if assessment is not None else _assessment(port),
    }
    values.update(kwargs)
    return ToolRequest(**values)


def test_real_loopback_tcp_scan_reports_open_and_sets_tested():
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    port = listener.getsockname()[1]
    try:
        adapter = NmapAdapter()
        result = asyncio.run(adapter.run(_request(port)))
        normalized = adapter.normalize(result)
        assert result.returncode == 0
        assert normalized["operation"] == "tcp_scan"
        assert normalized["target"] == "127.0.0.1"
        assert normalized["requested_ports"] == [port]
        assert normalized["scan_status"] == "complete"
        assert adapter.probe().tested is True
        records = normalized["hosts"][0]["ports"]
        assert any(item["port"] == port and item["state"] == "open" for item in records)
        assert all(item["protocol"] == "tcp" for item in records)
        assert all(item["service_verified"] is False for item in records)
        assert normalized["raw_xml_sha256"]
        assert "-oX" in normalized["command"]
    finally:
        listener.close()


@pytest.mark.parametrize(
    "tool_request",
    [
        ToolRequest("tcp_scan", timeout=20, target="127.0.0.1/32", parameters={"ports": [80]}),
        ToolRequest("tcp_scan", timeout=20, target="localhost", parameters={"ports": [80]}),
        ToolRequest("tcp_scan", timeout=20, target="127.0.0.1 ", parameters={"ports": [80]}),
        ToolRequest("tcp_scan", timeout=20, target="127.0.0.1%eth0", parameters={"ports": [80]}),
        ToolRequest("tcp_scan", timeout=20, target="224.0.0.1", parameters={"ports": [80]}),
        ToolRequest("tcp_scan", timeout=20, target="0.0.0.0", parameters={"ports": [80]}),
        ToolRequest("tcp_scan", timeout=20, target="255.255.255.255", parameters={"ports": [80]}),
    ],
)
def test_literal_target_validation(tool_request):
    with pytest.raises((ValueError, RuntimeError)):
        NmapAdapter().validate(tool_request)


def test_missing_assessment_and_wrong_stored_operation_are_denied():
    with pytest.raises(ValueError):
        NmapAdapter().validate(
            ToolRequest("tcp_scan", timeout=20, target="127.0.0.1", parameters={"ports": [80]})
        )
    assessment = _assessment(80, operations={"core.self_check"})
    with pytest.raises(ValueError):
        NmapAdapter().validate(_request(80, assessment=assessment))


def test_unknown_parameters_and_unauthorized_ports_are_denied():
    assessment = _assessment(443)
    with pytest.raises(ValueError):
        NmapAdapter().validate(
            _request(443, assessment=assessment, parameters={"ports": [443], "raw_args": ["--script"]})
        )
    with pytest.raises(ValueError):
        NmapAdapter().validate(_request(80, assessment=_assessment(443)))
    with pytest.raises(ValueError):
        NmapAdapter().validate(_request(443, assessment=assessment, parameters={"ports": [True]}))


def test_timeout_bounds_and_injection_are_denied():
    assessment = _assessment(443)
    with pytest.raises(ValueError):
        NmapAdapter().validate(_request(443, assessment=assessment, timeout=9))
    with pytest.raises(ValueError):
        NmapAdapter().validate(_request(443, assessment=assessment, timeout=float("inf")))
    with pytest.raises(ValueError):
        NmapAdapter().validate(_request(443, assessment=assessment, target="127.0.0.1;id"))


def test_missing_executable_is_clean_failure(monkeypatch):
    monkeypatch.setattr("secram.tools.adapters.nmap.shutil.which", lambda _: None)
    adapter = NmapAdapter()
    assert adapter.probe().installed is False
    with pytest.raises(FileNotFoundError, match="nmap executable"):
        asyncio.run(adapter.run(_request(443, assessment=_assessment(443))))


def test_corrupt_xml_is_rejected_without_being_marked_tested(monkeypatch):
    original = asyncio.create_subprocess_exec

    async def fake_exec(*args, **kwargs):
        return await original(
            sys.executable,
            "-c",
            "import sys; sys.stdout.write('<nmaprun scanner=\\\"nmap\\\"><broken>')",
            **kwargs,
        )

    monkeypatch.setattr(asyncio, "create_subprocess_exec", fake_exec)
    adapter = NmapAdapter()
    with pytest.raises(ValueError, match="Invalid or unsafe Nmap XML"):
        asyncio.run(adapter.run(_request(443, assessment=_assessment(443))))
    assert adapter.probe().tested is False


def test_cancellation_kills_local_child(monkeypatch):
    original = asyncio.create_subprocess_exec
    created = asyncio.Event()
    processes = []

    async def fake_exec(*args, **kwargs):
        process = await original(
            sys.executable,
            "-c",
            "import time; time.sleep(60)",
            **kwargs,
        )
        processes.append(process)
        created.set()
        return process

    async def scenario():
        monkeypatch.setattr(asyncio, "create_subprocess_exec", fake_exec)
        adapter = NmapAdapter()
        task = asyncio.create_task(adapter.run(_request(443, assessment=_assessment(443))))
        await created.wait()
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert processes[0].returncode is not None

    asyncio.run(scenario())
