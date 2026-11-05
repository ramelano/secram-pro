"""Read-only Linux host snapshot collection for the Phase 2 host module."""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
from datetime import datetime, timezone
from typing import Any

import psutil


_SYSTEMCTL_COMMAND = [
    "systemctl",
    "list-units",
    "--type=service",
    "--all",
    "--no-pager",
    "--no-legend",
    "--plain",
]
_SYSTEMCTL_TIMEOUT_SECONDS = 3
_MAX_SYSTEMCTL_OUTPUT_BYTES = 1_000_000


class LinuxHostProvider:
    """Collect a bounded, local, read-only Linux host snapshot."""

    def __init__(self, max_processes: int = 200, max_services: int = 200) -> None:
        if isinstance(max_processes, bool) or not isinstance(max_processes, int):
            raise TypeError("max_processes must be an integer")
        if isinstance(max_services, bool) or not isinstance(max_services, int):
            raise TypeError("max_services must be an integer")
        if max_processes < 0 or max_services < 0:
            raise ValueError("collection limits must be non-negative")
        self.max_processes = max_processes
        self.max_services = max_services

    def collect(self) -> dict[str, Any]:
        """Return the current host snapshot without changing local state."""
        limitations: list[str] = []
        snapshot: dict[str, Any] = {
            "operation": "host.snapshot",
            "collected_at": datetime.now(timezone.utc).isoformat(),
            "status": "ok",
            "measurement_context": "OS-visible resources; cgroup limits are not applied. "
                                   "A container snapshot may not represent physical-host resources.",
            "cpu": self._collect_cpu(limitations),
            "memory": self._collect_memory(limitations),
            "storage": self._collect_storage(limitations),
            "processes": self._collect_processes(limitations),
            "network": self._collect_network(limitations),
            "services": self._collect_services(limitations),
            "limitations": limitations,
        }
        if limitations:
            snapshot["status"] = "partial"
        return snapshot

    @staticmethod
    def _add_limitation(limitations: list[str], message: str) -> None:
        if message not in limitations:
            limitations.append(message)

    def _collect_cpu(self, limitations: list[str]) -> dict[str, Any]:
        result: dict[str, Any] = {
            "logical_count": None,
            "percent": None,
            "load_avg": [],
        }
        try:
            result["logical_count"] = psutil.cpu_count(logical=True)
        except Exception as exc:
            self._add_limitation(
                limitations,
                f"CPU logical count unavailable: {type(exc).__name__}.",
            )
        try:
            result["percent"] = psutil.cpu_percent(interval=0.1)
        except Exception as exc:
            self._add_limitation(
                limitations,
                f"CPU utilization unavailable: {type(exc).__name__}.",
            )
        try:
            result["load_avg"] = [float(value) for value in psutil.getloadavg()]
        except Exception as exc:
            self._add_limitation(
                limitations,
                f"CPU load average unavailable: {type(exc).__name__}.",
            )
        return result

    def _collect_memory(self, limitations: list[str]) -> dict[str, Any]:
        result: dict[str, Any] = {
            "total": None,
            "available": None,
            "used": None,
            "percent": None,
        }
        try:
            memory = psutil.virtual_memory()
            for field in ("total", "available", "used", "percent"):
                result[field] = getattr(memory, field)
        except Exception as exc:
            self._add_limitation(
                limitations,
                f"Memory metrics unavailable: {type(exc).__name__}.",
            )
        return result

    def _collect_storage(self, limitations: list[str]) -> dict[str, Any]:
        result: dict[str, Any] = {
            "total": None,
            "used": None,
            "free": None,
            "percent": None,
        }
        try:
            storage = psutil.disk_usage(os.path.abspath(os.sep))
            for field in ("total", "used", "free", "percent"):
                result[field] = getattr(storage, field)
        except Exception as exc:
            self._add_limitation(
                limitations,
                f"Root filesystem metrics unavailable: {type(exc).__name__}.",
            )
        return result

    def _collect_processes(self, limitations: list[str]) -> dict[str, Any]:
        result: dict[str, Any] = {
            "items": [],
            "total": 0,
            "observed_count": 0,
            "truncated": False,
            "access_denied": False,
        }
        try:
            processes = psutil.process_iter(attrs=["pid", "name", "status"])
            for process in processes:
                result["total"] += 1
                try:
                    info = process.info
                    pid = info.get("pid")
                    if pid is None:
                        pid = getattr(process, "pid", None)
                    result["observed_count"] += 1
                    if len(result["items"]) < self.max_processes:
                        result["items"].append(
                            {
                                "pid": pid,
                                "name": self._string_or_none(info.get("name")),
                                "status": self._string_or_none(info.get("status")),
                            }
                        )
                    else:
                        result["truncated"] = True
                except psutil.NoSuchProcess:
                    self._add_limitation(
                        limitations,
                        "Some processes exited during collection.",
                    )
                except psutil.AccessDenied:
                    result["access_denied"] = True
                    self._add_limitation(
                        limitations,
                        "Some process details were unavailable due to permissions.",
                    )
                except (FileNotFoundError, ProcessLookupError):
                    self._add_limitation(
                        limitations,
                        "Some process entries disappeared during collection.",
                    )
                except Exception as exc:
                    self._add_limitation(
                        limitations,
                        f"Some process details were unavailable: {type(exc).__name__}.",
                    )
        except psutil.AccessDenied:
            result["access_denied"] = True
            self._add_limitation(
                limitations,
                "Process inventory was unavailable due to permissions.",
            )
        except psutil.NoSuchProcess:
            self._add_limitation(
                limitations,
                "Process inventory changed while it was being collected.",
            )
        except (FileNotFoundError, ProcessLookupError):
            self._add_limitation(
                limitations,
                "Process inventory was unavailable because procfs was unavailable.",
            )
        except Exception as exc:
            self._add_limitation(
                limitations,
                f"Process inventory unavailable: {type(exc).__name__}.",
            )

        if result["truncated"]:
            self._add_limitation(
                limitations,
                f"Process list truncated at {self.max_processes} items.",
            )
        return result

    def _collect_network(self, limitations: list[str]) -> dict[str, Any]:
        result: dict[str, Any] = {"interfaces": []}
        try:
            addresses_by_interface = psutil.net_if_addrs()
            for interface, addresses in addresses_by_interface.items():
                for address in addresses:
                    value = getattr(address, "address", None)
                    if value is None:
                        continue
                    family = getattr(address, "family", None)
                    family_name = getattr(family, "name", None)
                    if family_name is None:
                        family_name = str(family)
                    result["interfaces"].append(
                        {
                            "interface": str(interface),
                            "family": family_name,
                            "address": str(value),
                            "netmask": getattr(address, "netmask", None),
                        }
                    )
        except psutil.AccessDenied:
            self._add_limitation(
                limitations,
                "Network interface details were unavailable due to permissions.",
            )
        except (FileNotFoundError, ProcessLookupError):
            self._add_limitation(
                limitations,
                "Network interface data was unavailable from the local system.",
            )
        except Exception as exc:
            self._add_limitation(
                limitations,
                f"Network interface data unavailable: {type(exc).__name__}.",
            )
        return result

    def _collect_services(self, limitations: list[str]) -> dict[str, Any]:
        result: dict[str, Any] = {
            "status": "unavailable",
            "items": [],
            "detail": "",
            "total": 0,
            "truncated": False,
        }

        if not os.path.isdir("/run/systemd/system"):
            result["detail"] = "systemd is not running on this host."
            self._add_limitation(
                limitations,
                "Service inventory unavailable because systemd is not running.",
            )
            return result
        if shutil.which("systemctl") is None:
            result["detail"] = "systemctl was not found while systemd is running."
            self._add_limitation(
                limitations,
                "Service inventory unavailable because systemctl was not found.",
            )
            return result

        try:
            with tempfile.TemporaryFile(mode="w+b") as stdout_file, tempfile.TemporaryFile(
                mode="w+b"
            ) as stderr_file:
                completed = subprocess.run(
                    list(_SYSTEMCTL_COMMAND),
                    stdout=stdout_file,
                    stderr=stderr_file,
                    timeout=_SYSTEMCTL_TIMEOUT_SECONDS,
                    check=False,
                    shell=False,
                )
                stdout = self._read_bounded_output(stdout_file)
                stderr = self._read_bounded_output(stderr_file)
        except subprocess.TimeoutExpired:
            result["status"] = "error"
            result["detail"] = "systemctl timed out after 3 seconds."
            self._add_limitation(limitations, result["detail"])
            return result
        except FileNotFoundError:
            result["status"] = "unavailable"
            result["detail"] = "systemctl disappeared before it could be executed."
            self._add_limitation(limitations, result["detail"])
            return result
        except PermissionError:
            result["status"] = "error"
            result["detail"] = "systemctl could not be executed due to permissions."
            self._add_limitation(limitations, result["detail"])
            return result
        except OSError as exc:
            result["status"] = "error"
            result["detail"] = f"systemctl execution failed: {type(exc).__name__}."
            self._add_limitation(limitations, result["detail"])
            return result

        if stdout is None or stderr is None:
            result["status"] = "error"
            result["detail"] = "systemctl output exceeded the bounded collection limit."
            self._add_limitation(limitations, result["detail"])
            return result
        if completed.returncode != 0:
            result["status"] = "error"
            result["detail"] = f"systemctl returned exit code {completed.returncode}."
            self._add_limitation(limitations, result["detail"])
            return result

        malformed = False
        for line in stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            result["total"] += 1
            if len(result["items"]) >= self.max_services:
                result["truncated"] = True
                continue
            fields = line.split()
            if len(fields) < 4:
                malformed = True
                continue
            result["items"].append(
                {
                    "name": fields[0],
                    "load": fields[1],
                    "active": fields[2],
                    "sub": fields[3],
                }
            )

        result["status"] = "ok"
        result["detail"] = f"Collected {len(result['items'])} systemd service units."
        if malformed:
            result["detail"] += " Some output lines were malformed and skipped."
            self._add_limitation(
                limitations,
                "Some systemd service output lines were malformed.",
            )
        if result["truncated"]:
            result["detail"] += f" Output truncated at {self.max_services} items."
            self._add_limitation(
                limitations,
                f"Service list truncated at {self.max_services} items.",
            )
        return result

    @staticmethod
    def _read_bounded_output(handle: Any) -> str | None:
        handle.seek(0)
        data = handle.read(_MAX_SYSTEMCTL_OUTPUT_BYTES + 1)
        if len(data) > _MAX_SYSTEMCTL_OUTPUT_BYTES:
            return None
        if isinstance(data, bytes):
            return data.decode("utf-8", errors="replace")
        return str(data)

    @staticmethod
    def _string_or_none(value: Any) -> str | None:
        if value is None:
            return None
        return str(value)
