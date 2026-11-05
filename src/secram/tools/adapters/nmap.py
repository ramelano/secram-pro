"""Strict, authorized Linux Nmap TCP-scan adapter."""
from __future__ import annotations

import asyncio
import hashlib
import ipaddress
import math
import os
import re
import shutil
import signal
import subprocess
import sys
from dataclasses import replace
from typing import Any

from defusedxml import ElementTree as DefusedET

from secram.core.models import Assessment, Task
from secram.core.policies import PolicyEngine, literal_network_target
from secram.tools.base import ToolAdapter, ToolRequest, ToolResult, ToolStatus


_STDOUT_LIMIT = 2 * 1024 * 1024
_STDERR_LIMIT = 64 * 1024
_OPERATION = "nmap.tcp_scan"


class NmapAdapter(ToolAdapter):
    """Run one narrowly scoped, unprivileged Nmap TCP connect scan."""

    name = "nmap"

    def __init__(self) -> None:
        self._tested = False
        self._probe_status: ToolStatus | None = None
        self._executable: str | None = None
        self._version: str | None = None

    def probe(self) -> ToolStatus:
        """Probe once per adapter instance; later GUI refreshes are non-blocking."""
        if self._probe_status is not None:
            return replace(self._probe_status, tested=self._tested)

        executable = shutil.which("nmap")
        self._executable = executable
        version: str | None = None
        if executable is not None:
            try:
                completed = subprocess.run(
                    [executable, "--version"],
                    capture_output=True,
                    text=True,
                    timeout=2,
                    check=False,
                )
            except (OSError, subprocess.TimeoutExpired):
                completed = None
            if completed is not None:
                text = (completed.stdout or completed.stderr or "").strip()
                if text:
                    version = text.splitlines()[0]

        self._version = version
        self._probe_status = ToolStatus(
            name=self.name,
            installed=executable is not None,
            integrated=True,
            tested=False,
            supported=sys.platform == "linux",
            details="Fixed, unprivileged Linux Nmap TCP connect scan adapter.",
            executable=executable,
            version=version,
        )
        return self._probe_status

    @staticmethod
    def _literal_target(target: object) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
        return literal_network_target(target)

    @staticmethod
    def _ports(parameters: object) -> list[int]:
        if not isinstance(parameters, dict) or set(parameters) != {"ports"}:
            raise ValueError("Parameters must be exactly {'ports': [int, ...]}")
        ports = parameters["ports"]
        if not isinstance(ports, list) or not 1 <= len(ports) <= 32:
            raise ValueError("Ports must be a non-empty list of at most 32 integers")
        if any(not isinstance(port, int) or isinstance(port, bool) for port in ports):
            raise ValueError("Ports must contain integers, not booleans")
        if any(port < 1 or port > 65535 for port in ports):
            raise ValueError("Ports must be between 1 and 65535")
        if len(set(ports)) != len(ports):
            raise ValueError("Ports must be distinct")
        return list(ports)

    def _validated(
        self, request: ToolRequest
    ) -> tuple[ipaddress.IPv4Address | ipaddress.IPv6Address, list[int], Assessment]:
        if sys.platform != "linux":
            raise RuntimeError("Nmap adapter supports Linux only")
        if request.operation != "tcp_scan":
            raise ValueError("Only the tcp_scan operation is supported")
        if isinstance(request.timeout, bool) or not isinstance(request.timeout, (int, float)):
            raise ValueError("Timeout must be a finite number between 10 and 60 seconds")
        if not math.isfinite(float(request.timeout)) or not 10 <= request.timeout <= 60:
            raise ValueError("Timeout must be a finite number between 10 and 60 seconds")

        address = self._literal_target(request.target)
        ports = self._ports(request.parameters)
        assessment = request.assessment
        if not isinstance(assessment, Assessment):
            raise ValueError("An assessment is required for Nmap scans")

        task = Task(
            assessment_id=assessment.id,
            name=_OPERATION,
            operation=_OPERATION,
            target=request.target,
        )
        PolicyEngine().check(assessment, task, target_required=True)
        if not set(ports).issubset(assessment.scope.allowed_ports):
            unauthorized = sorted(set(ports) - assessment.scope.allowed_ports)
            raise ValueError(f"Ports are outside the authorized scope: {unauthorized}")
        return address, ports, assessment

    def validate(self, request: ToolRequest) -> None:
        self._validated(request)

    @staticmethod
    async def _read_capped(stream: asyncio.StreamReader, limit: int) -> tuple[bytes, bool]:
        chunks: list[bytes] = []
        size = 0
        overflow = False
        while True:
            chunk = await stream.read(65536)
            if not chunk:
                break
            remaining = max(0, limit - size)
            if remaining:
                retained = chunk[:remaining]
                chunks.append(retained)
                size += len(retained)
                if len(chunk) > remaining:
                    overflow = True
            else:
                # Continue draining without retaining so Nmap cannot block on a full pipe.
                overflow = True
        return b"".join(chunks), overflow

    @staticmethod
    async def _kill_and_reap(process: asyncio.subprocess.Process) -> None:
        if process.returncode is None:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                try:
                    process.kill()
                except ProcessLookupError:
                    pass
            except PermissionError:
                try:
                    process.kill()
                except ProcessLookupError:
                    pass
        try:
            await asyncio.wait_for(process.wait(), timeout=2)
        except asyncio.TimeoutError:
            try:
                process.kill()
            except ProcessLookupError:
                pass
            await process.wait()

    @staticmethod
    def _safe_confidence(value: str | None) -> int | str | None:
        if value is None:
            return None
        try:
            return int(value)
        except ValueError:
            return value

    @staticmethod
    def _extraports(host: Any) -> list[dict[str, Any]]:
        summaries: list[dict[str, Any]] = []
        for item in host.findall("./ports/extraports"):
            count: int | str | None = item.attrib.get("count")
            if isinstance(count, str):
                try:
                    count = int(count)
                except ValueError:
                    pass
            reasons: list[dict[str, Any]] = []
            for reason in item.findall("./extrareasons"):
                reason_count: int | str | None = reason.attrib.get("count")
                if isinstance(reason_count, str):
                    try:
                        reason_count = int(reason_count)
                    except ValueError:
                        pass
                reasons.append({"reason": reason.attrib.get("reason"), "count": reason_count})
            summaries.append(
                {
                    "state": item.attrib.get("state"),
                    "count": count,
                    "reasons": reasons,
                }
            )
        return summaries

    def _parse_xml(
        self,
        raw_xml: bytes,
        *,
        target: ipaddress.IPv4Address | ipaddress.IPv6Address,
        requested_ports: list[int],
        argv: list[str],
    ) -> dict[str, Any]:
        """Parse only the expected Nmap result shape; never infer missing ports."""
        if not raw_xml:
            raise ValueError("Nmap returned empty XML")

        upper = raw_xml.upper()
        if b"<!ENTITY" in upper:
            raise ValueError("XML entity declarations are not allowed")
        cleaned = re.sub(rb"<!DOCTYPE\s+nmaprun\s*>", b"", raw_xml, count=1, flags=re.IGNORECASE)
        if b"<!DOCTYPE" in cleaned.upper():
            raise ValueError("Only the harmless Nmap nmaprun doctype is allowed")

        try:
            root = DefusedET.fromstring(cleaned)
        except Exception as exc:
            raise ValueError(f"Invalid or unsafe Nmap XML: {exc}") from exc
        if root.tag != "nmaprun" or root.attrib.get("scanner") != "nmap":
            raise ValueError("Unexpected Nmap XML root")

        finished = root.find("./runstats/finished")
        if finished is None or finished.attrib.get("exit") != "success":
            raise ValueError("Nmap did not report a successful finished scan")

        xml_hosts = root.findall(".//host")
        if len(xml_hosts) > 1:
            raise ValueError("Nmap returned more than one host")

        hosts: list[dict[str, Any]] = []
        scan_status = "complete"
        if not xml_hosts:
            scan_status = "inconclusive"
        else:
            host = xml_hosts[0]
            ip_addresses: list[ipaddress.IPv4Address | ipaddress.IPv6Address] = []
            for address_element in host.findall("./address"):
                address_type = address_element.attrib.get("addrtype")
                if address_type not in {"ipv4", "ipv6"}:
                    continue
                try:
                    parsed = ipaddress.ip_address(address_element.attrib["addr"])
                except (KeyError, ValueError) as exc:
                    raise ValueError("Nmap returned an invalid IP address") from exc
                ip_addresses.append(parsed)
                if parsed != target:
                    raise ValueError("Nmap returned an unexpected target IP")
            if target not in ip_addresses:
                raise ValueError("Nmap XML did not identify the requested target")

            status_element = host.find("./status")
            if status_element is None or not status_element.attrib.get("state"):
                raise ValueError("Nmap host status is missing")
            host_state = status_element.attrib["state"]
            host_entry: dict[str, Any] = {"ip": str(target), "state": host_state, "ports": []}
            seen_ports: set[int] = set()
            for port_element in host.findall(".//port"):
                protocol = port_element.attrib.get("protocol")
                try:
                    port = int(port_element.attrib["portid"])
                except (KeyError, ValueError) as exc:
                    raise ValueError("Nmap returned an invalid port") from exc
                if protocol != "tcp":
                    raise ValueError("Nmap returned an unexpected protocol")
                if port not in requested_ports:
                    raise ValueError("Nmap returned an unexpected port")
                if port in seen_ports:
                    raise ValueError("Nmap returned a duplicate port")
                seen_ports.add(port)
                state_element = port_element.find("./state")
                if state_element is None or not state_element.attrib.get("state"):
                    raise ValueError("Nmap port state is missing")
                service_element = port_element.find("./service")
                service = {
                    "name": service_element.attrib.get("name") if service_element is not None else None,
                    "method": service_element.attrib.get("method") if service_element is not None else None,
                    "confidence": (
                        self._safe_confidence(service_element.attrib.get("conf"))
                        if service_element is not None
                        else None
                    ),
                }
                host_entry["ports"].append(
                    {
                        "port": port,
                        "protocol": protocol,
                        "state": state_element.attrib["state"],
                        "reason": state_element.attrib.get("reason"),
                        "service": service,
                        "service_verified": False,
                    }
                )

            summaries = self._extraports(host)
            if summaries:
                # Preserve Nmap's summary without fabricating per-port records.
                host_entry["extraports"] = summaries
            hosts.append(host_entry)
            reason = status_element.attrib.get("reason", "").lower()
            summary_counts = [summary.get("count") for summary in summaries]
            valid_counts = all(type(count) is int and count >= 0 for count in summary_counts)
            covered_ports = len(seen_ports) + sum(summary_counts) if valid_counts else -1
            if ("timeout" in reason or host.attrib.get("timedout") == "true"
                    or host_state != "up" or covered_ports != len(requested_ports)):
                scan_status = "inconclusive"

        tool_version = root.attrib.get("version") or self._version
        return {
            "operation": "tcp_scan",
            "target": str(target),
            "requested_ports": list(requested_ports),
            "hosts": hosts,
            "scan_status": scan_status,
            "tool_version": tool_version,
            "raw_xml_sha256": hashlib.sha256(raw_xml).hexdigest(),
            "command": list(argv),
        }

    async def run(self, request: ToolRequest) -> ToolResult:
        address, ports, _assessment = self._validated(request)
        status = self.probe()
        executable = status.executable
        if executable is None:
            raise FileNotFoundError("nmap executable was not found")

        argv = [executable]
        if address.version == 6:
            argv.append("-6")
        argv.extend(
            [
                "--unprivileged",
                "-sT",
                "-Pn",
                "-n",
                "--disable-arp-ping",
                "-T2",
                "--max-rate",
                "25",
                "--max-retries",
                "1",
                "--host-timeout",
                "25s",
                "-p",
                ",".join(str(port) for port in ports),
                "-oX",
                "-",
                str(address),
            ]
        )

        process = await asyncio.create_subprocess_exec(
            *argv,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            start_new_session=True,
        )
        stdout_task = asyncio.create_task(self._read_capped(process.stdout, _STDOUT_LIMIT))
        stderr_task = asyncio.create_task(self._read_capped(process.stderr, _STDERR_LIMIT))
        try:
            async with asyncio.timeout(float(request.timeout)):
                returncode = await process.wait()
                (stdout_bytes, stdout_overflow), (stderr_bytes, stderr_overflow) = await asyncio.gather(
                    stdout_task, stderr_task
                )
        except BaseException:
            await self._kill_and_reap(process)
            await asyncio.gather(stdout_task, stderr_task, return_exceptions=True)
            raise

        stdout = stdout_bytes.decode("utf-8", errors="replace")
        stderr = stderr_bytes.decode("utf-8", errors="replace")
        if stdout_overflow or stderr_overflow:
            raise RuntimeError("Nmap output exceeded the safety limit")
        if returncode != 0:
            raise RuntimeError(f"Nmap failed with exit code {returncode}: {stderr or stdout}")

        data = self._parse_xml(
            stdout_bytes,
            target=address,
            requested_ports=ports,
            argv=argv,
        )
        self._tested = True
        return ToolResult(
            tool=self.name,
            returncode=returncode,
            stdout=stdout,
            stderr=stderr,
            data=data,
        )

    def normalize(self, result: ToolResult) -> dict[str, Any]:
        return {
            "tool": result.tool,
            "returncode": result.returncode,
            "stdout": result.stdout,
            "stderr": result.stderr,
            **result.data,
        }
