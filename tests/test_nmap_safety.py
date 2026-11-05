import asyncio
import ipaddress
import sys

import pytest

from secram.tools.adapters.nmap import NmapAdapter


def xml_result(host_body="", host_attributes="", address="127.0.0.1", host_state="up"):
    return (f'<nmaprun scanner="nmap" version="test-fixture"><host {host_attributes}>'
            f'<status state="{host_state}"/><address addr="{address}" addrtype="ipv4"/>'
            f'{host_body}</host><runstats><finished exit="success"/></runstats></nmaprun>').encode()


def parse(raw):
    return NmapAdapter()._parse_xml(raw, target=ipaddress.ip_address("127.0.0.1"),
                                    requested_ports=[443], argv=["test-fixture"])


@pytest.mark.parametrize("raw", [
    xml_result(), xml_result(host_state="down"),
    xml_result('<ports><port protocol="tcp" portid="443"><state state="open"/></port></ports>',
               host_attributes='timedout="true"'),
    b'<nmaprun scanner="nmap"><runstats><finished exit="success"/></runstats></nmaprun>',
])
def test_incomplete_results_are_not_complete(raw):
    assert parse(raw)["scan_status"] == "inconclusive"


def test_closed_port_summary_preserved_without_invention():
    data = parse(xml_result('<ports><extraports state="closed" count="1"/></ports>'))
    assert data["scan_status"] == "complete"
    assert data["hosts"][0]["ports"] == []
    assert data["hosts"][0]["extraports"][0]["count"] == 1


@pytest.mark.parametrize("raw", [
    xml_result(address="192.0.2.1"),
    xml_result('<ports><port protocol="tcp" portid="80"><state state="open"/></port></ports>'),
    xml_result('<ports><port protocol="udp" portid="443"><state state="open"/></port></ports>'),
    b'<!DOCTYPE nmaprun SYSTEM "file:///etc/passwd"><nmaprun scanner="nmap"/>',
    b'<!DOCTYPE nmaprun [<!ENTITY x "secret">]><nmaprun scanner="nmap">&x;</nmaprun>',
])
def test_xml_scope_and_entity_rejection(raw):
    with pytest.raises(ValueError):
        parse(raw)


def test_output_reader_retains_only_limit():
    async def scenario():
        stream = asyncio.StreamReader(); stream.feed_data(b"x" * 1024); stream.feed_eof()
        data, overflow = await NmapAdapter._read_capped(stream, 64)
        assert len(data) == 64 and overflow is True
    asyncio.run(scenario())


def test_timeout_reaps_real_local_child(monkeypatch):
    from datetime import timedelta
    from secram.core.models import Assessment, Authorization, Scope, utcnow
    from secram.tools.base import ToolRequest
    original_exec = asyncio.create_subprocess_exec
    original_timeout = asyncio.timeout
    processes = []
    async def delayed_exec(*args, **kwargs):
        process = await original_exec(sys.executable, "-c", "import time; time.sleep(60)", **kwargs)
        processes.append(process)
        return process
    monkeypatch.setattr(asyncio, "create_subprocess_exec", delayed_exec)
    monkeypatch.setattr(asyncio, "timeout", lambda delay: original_timeout(0.02))
    a = Assessment(title="Local timeout test", scope=Scope(cidrs=["127.0.0.1/32"],
        allowed_operations={"nmap.tcp_scan"}, allowed_ports={443},
        expires_at=utcnow()+timedelta(minutes=5)),
        authorization=Authorization(approved_by="owner", evidence_reference="fixture", statement="local child only"))
    with pytest.raises(TimeoutError):
        asyncio.run(NmapAdapter().run(ToolRequest("tcp_scan", timeout=10, target="127.0.0.1",
                    parameters={"ports":[443]}, assessment=a)))
    assert processes[0].returncode is not None
