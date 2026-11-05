"""Bounded, offline Linux host telemetry for the blue module.

This monitor deliberately reports observations only.  It does not execute
commands, capture command lines or environments, kill processes, or change
firewall state.
"""
from __future__ import annotations

from collections import deque
from datetime import datetime, timezone
import hashlib
import ipaddress
import os
from pathlib import Path
import re
import stat
import threading
import time
from typing import Any, Callable
from uuid import uuid4

import psutil


_MAX_PROCESS_RECORDS = 256
_MAX_NETWORK_RECORDS = 256
_MAX_FILE_SIZE = 4 * 1024 * 1024
_MAX_INTEGRITY_PATHS = 16
_MAX_AUTH_READ = 64 * 1024
_MAX_AUTH_BUFFER = 8 * 1024
_MAX_RAW_LINE = 512
_MAX_LIMITATIONS = 128

_ALLOWED_SEVERITIES = {"info", "low", "medium", "high"}
_STATUS_ACTIVE = "active"
_STATUS_UNAVAILABLE = "unavailable"
_STATUS_LIMITED = "limited"


class BlueMonitor:
    """Observe local host, process, network, auth-log and file state.

    ``on_event`` is called from the monitor's daemon thread.  Events are
    dictionaries using the shared telemetry contract.  The monitor retains a
    bounded copy of events for snapshots and drops the oldest retained event
    when the ring is full.
    """

    def __init__(
        self,
        on_event: Callable[[dict[str, Any]], None],
        interval: float = 1.0,
        max_events: int = 2000,
    ) -> None:
        if not callable(on_event):
            raise TypeError("on_event must be callable")
        if isinstance(interval, bool) or not isinstance(interval, (int, float)):
            raise TypeError("interval must be a number")
        if not 0.5 <= float(interval) <= 60.0:
            raise ValueError("interval must be between 0.5 and 60 seconds")
        if isinstance(max_events, bool) or not isinstance(max_events, int):
            raise TypeError("max_events must be an integer")
        if max_events < 1:
            raise ValueError("max_events must be at least 1")

        self._on_event = on_event
        self._interval = float(interval)
        self._max_events = max_events
        self._events: deque[dict[str, Any]] = deque(maxlen=max_events)
        self._dropped = 0
        self._limitations: list[str] = []
        self._sources: dict[str, str] = {}
        self._lock = threading.RLock()
        self._callback_condition = threading.Condition(self._lock)
        self._callbacks_inflight = 0
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None
        self._running = False

        self._auth_path: Path | None = None
        self._auth_offset = 0
        self._auth_identity: tuple[int, int] | None = None
        self._auth_buffer = b""
        self._integrity_paths: list[Path] = []
        self._integrity_hashes: dict[str, str] = {}
        self._integrity_issues: set[str] = set()
        self._ioc_ips: set[str] = set()
        self._ioc_seen: set[tuple[Any, ...]] = set()
        self._process_known: set[tuple[int, float]] | None = None
        self._network_known: set[tuple[Any, ...]] | None = None
        self._network_process_times: dict[int, float] = {}
        self._first_host_sample = True

    def start(
        self,
        auth_log: Path | None = None,
        integrity_paths: list[Path] | None = None,
        ioc_ips: set[str] | None = None,
    ) -> dict[str, Any]:
        """Start polling local sources and return the initial monitor state."""
        if auth_log is not None and not isinstance(auth_log, Path):
            auth_log = Path(auth_log)
        paths = [Path(path) for path in (integrity_paths or [])]
        if len(paths) > _MAX_INTEGRITY_PATHS:
            paths = paths[:_MAX_INTEGRITY_PATHS]

        normalized_iocs: set[str] = set()
        for value in ioc_ips or set():
            if not isinstance(value, str):
                raise ValueError("ioc_ips must contain literal IP strings")
            try:
                normalized_iocs.add(str(ipaddress.ip_address(value)))
            except ValueError as exc:
                raise ValueError(f"IOC is not a literal IP address: {value!r}") from exc

        with self._callback_condition:
            if self._running:
                result = self._snapshot_locked()
                result.update({"started": False, "reason": "already running"})
                return result
            self._reset_runtime_locked()
            self._auth_path = auth_log
            self._integrity_paths = paths
            self._ioc_ips = normalized_iocs
            self._sources = {
                "host": _STATUS_ACTIVE,
                "process": _STATUS_ACTIVE,
                "network": _STATUS_ACTIVE,
                "auth_log": _STATUS_UNAVAILABLE,
                "integrity": _STATUS_UNAVAILABLE,
                "journalctl": _STATUS_UNAVAILABLE,
            }
            if len(integrity_paths or []) > _MAX_INTEGRITY_PATHS:
                self._add_limitation_locked(
                    f"integrity paths limited to {_MAX_INTEGRITY_PATHS}; extra paths were not observed"
                )
            if auth_log is None:
                self._add_limitation_locked(
                    "auth_log unavailable: pass an explicit local regular-file auth_log path to tail new appends"
                )
                self._add_limitation_locked(
                    "journalctl unavailable: optional bounded journal support is not enabled; no journal data was read"
                )
            else:
                self._prepare_auth_locked(auth_log)
            self._prepare_integrity_locked(paths)
            if not paths:
                self._add_limitation_locked(
                    "integrity unavailable: no regular-file integrity paths were configured"
                )
            elif not self._integrity_hashes:
                self._sources["integrity"] = _STATUS_UNAVAILABLE
            if auth_log is not None and self._sources["auth_log"] != _STATUS_ACTIVE:
                self._sources["journalctl"] = _STATUS_UNAVAILABLE
                self._add_limitation_locked(
                    "journalctl unavailable: optional bounded journal support is not enabled; use auth_log instead"
                )
            self._running = True
            self._stop_event.clear()
            self._thread = threading.Thread(
                target=self._run,
                name="secram-blue-monitor",
                daemon=True,
            )
            self._thread.start()
            result = self._snapshot_locked()
            result.update({"started": True})
            return result

    def stop(self) -> dict[str, Any]:
        """Stop polling and wait until no callback can be delivered later."""
        with self._callback_condition:
            was_running = self._running
            self._running = False
            self._stop_event.set()
            thread = self._thread
        if thread is not None and thread is not threading.current_thread():
            thread.join(timeout=max(2.0, self._interval + 1.0))
        with self._callback_condition:
            # A callback is never started after _running becomes false.  Wait
            # for one already in progress so stop() has a strong lifecycle
            # boundary for callers and tests.
            if thread is not threading.current_thread():
                deadline = time.monotonic() + max(2.0, self._interval + 1.0)
                while self._callbacks_inflight and time.monotonic() < deadline:
                    self._callback_condition.wait(timeout=0.05)
            self._thread = None
            result = self._snapshot_locked()
            result.update({"stopped": was_running})
            return result

    def snapshot(self) -> dict[str, Any]:
        """Return a consistent copy of retained events and source state."""
        with self._callback_condition:
            return self._snapshot_locked()

    def _reset_runtime_locked(self) -> None:
        self._events.clear()
        self._dropped = 0
        self._limitations.clear()
        self._sources.clear()
        self._auth_path = None
        self._auth_offset = 0
        self._auth_identity = None
        self._auth_buffer = b""
        self._integrity_paths = []
        self._integrity_hashes.clear()
        self._integrity_issues.clear()
        self._ioc_ips.clear()
        self._ioc_seen.clear()
        self._process_known = None
        self._network_known = None
        self._network_process_times.clear()
        self._first_host_sample = True

    def _snapshot_locked(self) -> dict[str, Any]:
        events = [dict(event, details=dict(event["details"])) for event in self._events]
        return {
            "running": self._running,
            "interval": self._interval,
            "max_events": self._max_events,
            "events": events,
            "event_count": len(events),
            "dropped": self._dropped,
            "dropped_count": self._dropped,
            "sources": dict(self._sources),
            "limitations": list(self._limitations),
        }

    def _run(self) -> None:
        first = True
        try:
            while not self._stop_event.is_set():
                if not first and self._stop_event.wait(self._interval):
                    break
                first = False
                if self._stop_event.is_set():
                    break
                self._poll_once()
        except Exception as exc:  # defensive boundary for a daemon worker
            self._add_limitation(f"monitor worker stopped after unexpected error: {type(exc).__name__}: {exc}")
        finally:
            with self._callback_condition:
                self._running = False
                self._callback_condition.notify_all()

    def _poll_once(self) -> None:
        if self._stop_event.is_set():
            return
        self._sample_host()
        self._sample_processes()
        self._sample_network()
        self._poll_auth_log()
        self._poll_integrity()

    def _sample_host(self) -> None:
        try:
            cpu = float(psutil.cpu_percent(interval=None))
            memory = psutil.virtual_memory()
            details: dict[str, Any] = {
                "cpu_percent": cpu,
                "memory_percent": float(memory.percent),
                "memory_total": int(memory.total),
                "memory_available": int(memory.available),
            }
            try:
                load = os.getloadavg()
                details["load_average"] = [float(value) for value in load[:3]]
            except (AttributeError, OSError):
                details["load_average"] = None
            with self._callback_condition:
                self._sources["host"] = _STATUS_ACTIVE
                first = self._first_host_sample
                self._first_host_sample = False
            # Keep host telemetry useful without producing a high-rate event
            # stream; one real sample per monitor run is sufficient baseline.
            if first:
                self._emit("host", "host.sample", "info", details)
        except PermissionError as exc:
            self._set_source_status("host", _STATUS_UNAVAILABLE)
            self._add_limitation(
                f"host observation unavailable: permission denied ({exc}); grant local psutil read access"
            )
        except Exception as exc:
            self._set_source_status("host", _STATUS_LIMITED)
            self._add_limitation(f"host observation limited: {type(exc).__name__}: {exc}")

    def _sample_processes(self) -> None:
        records: list[dict[str, Any]] = []
        identities: set[tuple[int, float]] = set()
        limited = False
        try:
            iterator = psutil.process_iter(["pid", "create_time", "name"])
            for index, process in enumerate(iterator):
                if index >= _MAX_PROCESS_RECORDS:
                    limited = True
                    break
                try:
                    info = process.info or {}
                    pid = int(info.get("pid", process.pid))
                    create_time = info.get("create_time")
                    if create_time is None:
                        create_time = process.create_time()
                    create_time = float(create_time)
                    name = str(info.get("name") or "")[:128]
                    identity = (pid, create_time)
                    identities.add(identity)
                    records.append(
                        {"pid": pid, "create_time": create_time, "name": name}
                    )
                except (psutil.NoSuchProcess, psutil.ZombieProcess):
                    limited = True
                except psutil.AccessDenied:
                    limited = True
            status = _STATUS_LIMITED if limited else _STATUS_ACTIVE
            with self._callback_condition:
                prior = self._process_known
                self._process_known = set(identities)
                self._network_process_times = {
                    record["pid"]: record["create_time"] for record in records
                }
                self._sources["process"] = status
            if limited:
                self._add_limitation(
                    "process observation limited: some processes were inaccessible or the 256-record bound was reached"
                )
            if prior is None:
                self._emit(
                    "process",
                    "process.sample",
                    "info",
                    {
                        "baseline": True,
                        "count": len(records),
                        "truncated": len(records) >= _MAX_PROCESS_RECORDS,
                        "processes": records,
                        "observation_note": "PID and create_time identify observations; no command line or environment was captured",
                    },
                )
            else:
                new_records = [
                    record
                    for record in records
                    if (record["pid"], record["create_time"]) not in prior
                ]
                for record in new_records[:32]:
                    self._emit(
                        "process",
                        "process.start",
                        "low",
                        {
                            **record,
                            "observation_note": "Observed process identity; this is not proof of compromise",
                        },
                        rule_id="blue.process.new",
                    )
                if len(new_records) > 32:
                    self._add_limitation(
                        "process observations limited: more than 32 new process identities occurred in one interval"
                    )
        except PermissionError as exc:
            self._set_source_status("process", _STATUS_UNAVAILABLE)
            self._add_limitation(
                f"process observation unavailable: permission denied ({exc}); grant local process metadata access"
            )
        except Exception as exc:
            self._set_source_status("process", _STATUS_LIMITED)
            self._add_limitation(f"process observation limited: {type(exc).__name__}: {exc}")

    def _sample_network(self) -> None:
        connections: list[dict[str, Any]] = []
        identities: set[tuple[Any, ...]] = set()
        try:
            raw_connections = psutil.net_connections(kind="inet")
            for index, connection in enumerate(raw_connections):
                if index >= _MAX_NETWORK_RECORDS:
                    break
                local_ip, local_port = self._address_parts(getattr(connection, "laddr", None))
                remote_ip, remote_port = self._address_parts(getattr(connection, "raddr", None))
                pid_value = getattr(connection, "pid", None)
                pid = int(pid_value) if isinstance(pid_value, int) else None
                create_time = self._network_process_times.get(pid) if pid is not None else None
                status = str(getattr(connection, "status", ""))[:32]
                identity = (pid, create_time, local_ip, local_port, remote_ip, remote_port, status)
                identities.add(identity)
                connections.append(
                    {
                        "pid": pid,
                        "process_create_time": create_time,
                        "local_ip": local_ip,
                        "local_port": local_port,
                        "remote_ip": remote_ip,
                        "remote_port": remote_port,
                        "status": status,
                    }
                )
            with self._callback_condition:
                prior = self._network_known
                self._network_known = set(identities)
                self._ioc_seen.intersection_update(identities)
                self._sources["network"] = (
                    _STATUS_LIMITED if len(connections) >= _MAX_NETWORK_RECORDS else _STATUS_ACTIVE
                )
            if len(connections) >= _MAX_NETWORK_RECORDS:
                self._add_limitation(
                    "network observation limited: the 256-connection bound was reached"
                )
            if prior is None:
                self._emit(
                    "network",
                    "network.sample",
                    "info",
                    {
                        "baseline": True,
                        "count": len(connections),
                        "truncated": len(connections) >= _MAX_NETWORK_RECORDS,
                        "connections": connections,
                        "observation_note": "Connection state is observational; no traffic was generated",
                    },
                )
            for connection in connections:
                remote_ip = connection["remote_ip"]
                if remote_ip is None or remote_ip not in self._ioc_ips:
                    continue
                key = (
                    connection["pid"],
                    connection["process_create_time"],
                    connection["local_ip"],
                    connection["local_port"],
                    connection["remote_ip"],
                    connection["remote_port"],
                    connection["status"],
                )
                with self._callback_condition:
                    already_seen = key in self._ioc_seen
                    if not already_seen:
                        self._ioc_seen.add(key)
                if not already_seen:
                    self._emit(
                        "network",
                        "network.ioc.match",
                        "medium",
                        {
                            **connection,
                            "indicator": remote_ip,
                            "observation_note": "Exact observed IP equality; this is not proof of compromise",
                        },
                        rule_id="blue.network.ioc",
                        target=remote_ip,
                        port=connection["remote_port"],
                    )
        except PermissionError as exc:
            self._set_source_status("network", _STATUS_UNAVAILABLE)
            self._add_limitation(
                f"network observation unavailable: permission denied ({exc}); grant net-connection read access or run with the required local permissions"
            )
        except Exception as exc:
            self._set_source_status("network", _STATUS_LIMITED)
            self._add_limitation(f"network observation limited: {type(exc).__name__}: {exc}")

    def _poll_auth_log(self) -> None:
        path = self._auth_path
        if path is None:
            return
        try:
            if path.is_symlink():
                self._set_source_status("auth_log", _STATUS_UNAVAILABLE)
                self._add_limitation(
                    f"auth_log unavailable for {path}: symlinks are not followed; provide a regular local file"
                )
                return
            info = path.stat()
            if not stat.S_ISREG(info.st_mode):
                self._set_source_status("auth_log", _STATUS_UNAVAILABLE)
                self._add_limitation(
                    f"auth_log unavailable for {path}: path is not a regular file"
                )
                return
            identity = (int(info.st_dev), int(info.st_ino))
            if self._auth_identity != identity or info.st_size < self._auth_offset:
                self._auth_identity = identity
                self._auth_offset = int(info.st_size)
                self._auth_buffer = b""
                self._set_source_status("auth_log", _STATUS_LIMITED)
                self._add_limitation(
                    f"auth_log reset/rotation observed for {path}; current contents were not replayed as alerts"
                )
                return
            if info.st_size == self._auth_offset:
                self._set_source_status("auth_log", _STATUS_ACTIVE)
                return
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            with os.fdopen(fd, "rb") as handle:
                opened = os.fstat(handle.fileno())
                if not stat.S_ISREG(opened.st_mode):
                    raise OSError("auth log changed to a non-regular file")
                if (opened.st_dev, opened.st_ino) != identity:
                    raise OSError("auth log identity changed during read; no data ingested")
                handle.seek(self._auth_offset)
                chunk = handle.read(_MAX_AUTH_READ)
                new_offset = handle.tell()
            if info.st_size - self._auth_offset > _MAX_AUTH_READ:
                self._add_limitation(
                    f"auth_log read limited for {path}: more than {_MAX_AUTH_READ} appended bytes arrived in one interval; excess bytes were not replayed"
                )
            self._auth_offset = new_offset
            self._auth_identity = identity
            lines = (self._auth_buffer + chunk).split(b"\n")
            self._auth_buffer = lines.pop() if lines else b""
            if len(self._auth_buffer) > _MAX_AUTH_BUFFER:
                self._auth_buffer = b""
                self._add_limitation(
                    f"auth_log line buffer limited for {path}: an unterminated line exceeded {_MAX_AUTH_BUFFER} bytes"
                )
            for raw in lines:
                self._handle_auth_line(raw)
            self._set_source_status("auth_log", _STATUS_ACTIVE)
        except PermissionError as exc:
            self._set_source_status("auth_log", _STATUS_UNAVAILABLE)
            self._add_limitation(
                f"auth_log unavailable for {path}: permission denied ({exc}); grant read access to the local log"
            )
        except FileNotFoundError as exc:
            self._set_source_status("auth_log", _STATUS_UNAVAILABLE)
            self._add_limitation(
                f"auth_log unavailable for {path}: file disappeared ({exc}); select an existing local regular file"
            )
        except OSError as exc:
            self._set_source_status("auth_log", _STATUS_LIMITED)
            self._add_limitation(
                f"auth_log read limited for {path}: {exc}; verify the path and local read permissions"
            )

    def _handle_auth_line(self, raw: bytes) -> None:
        line = raw.decode("utf-8", errors="replace").rstrip("\r")
        if not _AUTH_FAILURE_RE.search(line):
            return
        observed = _utc_iso()
        event_timestamp = self._parse_event_timestamp(line, observed)
        target = self._find_literal_ip(line)
        port = self._find_port(line)
        details: dict[str, Any] = {
            "rawline": self._redact_line(line),
            "timestamp_quality": "event" if event_timestamp else "ingested",
            "observation_note": "Observed authentication failure log entry; this is not proof of compromise",
        }
        if event_timestamp:
            details["event_timestamp"] = event_timestamp
        self._emit(
            "auth_log",
            "auth.failure",
            "low",
            details,
            rule_id="blue.auth.failure",
            target=target,
            port=port,
            observed_at=observed,
        )

    def _prepare_auth_locked(self, path: Path) -> None:
        try:
            if path.is_symlink():
                self._add_limitation_locked(
                    f"auth_log unavailable for {path}: symlinks are not followed; provide a regular local file"
                )
                return
            info = path.stat()
            if not stat.S_ISREG(info.st_mode):
                self._add_limitation_locked(
                    f"auth_log unavailable for {path}: path is not a regular file"
                )
                return
            # Baseline at EOF is intentional: pre-existing lines never become
            # fabricated startup alerts.
            self._auth_identity = (int(info.st_dev), int(info.st_ino))
            self._auth_offset = int(info.st_size)
            self._sources["auth_log"] = _STATUS_ACTIVE
        except PermissionError as exc:
            self._add_limitation_locked(
                f"auth_log unavailable for {path}: permission denied ({exc}); grant read access to the local log"
            )
        except FileNotFoundError as exc:
            self._add_limitation_locked(
                f"auth_log unavailable for {path}: file does not exist ({exc}); select an existing local regular file"
            )
        except OSError as exc:
            self._add_limitation_locked(
                f"auth_log unavailable for {path}: {exc}; verify the path and local read permissions"
            )

    def _prepare_integrity_locked(self, paths: list[Path]) -> None:
        valid = 0
        for path in paths:
            key = str(path)
            digest, error = self._hash_regular_file(path)
            if digest is None:
                self._integrity_issues.add(key)
                self._add_limitation_locked(error or f"integrity unavailable for {path}")
                continue
            self._integrity_hashes[key] = digest
            valid += 1
        if valid:
            self._sources["integrity"] = (
                _STATUS_LIMITED if self._integrity_issues else _STATUS_ACTIVE
            )

    def _poll_integrity(self) -> None:
        if not self._integrity_paths:
            return
        limited = False
        for path in self._integrity_paths:
            key = str(path)
            digest, error = self._hash_regular_file(path)
            if digest is None:
                limited = True
                self._set_source_status("integrity", _STATUS_LIMITED)
                issue_key = f"{key}:{error}"
                with self._callback_condition:
                    new_issue = issue_key not in self._integrity_issues
                    if new_issue:
                        self._integrity_issues.add(issue_key)
                if new_issue:
                    self._add_limitation(error or f"integrity unavailable for {path}")
                continue
            with self._callback_condition:
                previous = self._integrity_hashes.get(key)
                self._integrity_hashes[key] = digest
            if previous is not None and previous != digest:
                self._emit(
                    "integrity",
                    "file.integrity.changed",
                    "medium",
                    {
                        "path": key[:512],
                        "previous_sha256": previous,
                        "current_sha256": digest,
                        "observation_note": "Observed SHA-256 change in a bounded regular file; this is not proof of malicious modification",
                    },
                    rule_id="blue.file.integrity",
                )
        self._set_source_status("integrity", _STATUS_LIMITED if limited else _STATUS_ACTIVE)

    def _hash_regular_file(self, path: Path) -> tuple[str | None, str | None]:
        if path.is_symlink():
            return None, f"integrity unavailable for {path}: symlinks are not followed"
        fd: int | None = None
        try:
            flags = os.O_RDONLY
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            fd = os.open(str(path), flags)
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode):
                return None, f"integrity unavailable for {path}: path is not a regular file"
            if info.st_size > _MAX_FILE_SIZE:
                return None, (
                    f"integrity unavailable for {path}: file is {info.st_size} bytes, above the {_MAX_FILE_SIZE}-byte limit"
                )
            digest = hashlib.sha256()
            total = 0
            while True:
                chunk = os.read(fd, min(1024 * 1024, _MAX_FILE_SIZE - total + 1))
                if not chunk:
                    break
                total += len(chunk)
                if total > _MAX_FILE_SIZE:
                    return None, f"integrity unavailable for {path}: file exceeded the {_MAX_FILE_SIZE}-byte read limit"
                digest.update(chunk)
            return digest.hexdigest(), None
        except PermissionError as exc:
            return None, f"integrity unavailable for {path}: permission denied ({exc}); grant read access"
        except FileNotFoundError as exc:
            return None, f"integrity unavailable for {path}: file does not exist ({exc}); verify the path"
        except OSError as exc:
            return None, f"integrity unavailable for {path}: {exc}; verify it is a readable regular file"
        finally:
            if fd is not None:
                try:
                    os.close(fd)
                except OSError:
                    pass

    def _emit(
        self,
        source: str,
        event_type: str,
        severity: str,
        details: dict[str, Any],
        *,
        rule_id: str | None = None,
        target: str | None = None,
        port: int | None = None,
        observed_at: str | None = None,
    ) -> None:
        if severity not in _ALLOWED_SEVERITIES:
            raise ValueError(f"invalid telemetry severity: {severity}")
        if target is not None:
            try:
                target = str(ipaddress.ip_address(target))
            except ValueError as exc:
                raise ValueError("telemetry target must be a literal IP") from exc
        if port is not None and not 1 <= int(port) <= 65535:
            port = None
        event = {
            "id": str(uuid4()),
            "observed_at": observed_at or _utc_iso(),
            "source": source,
            "event_type": event_type,
            "severity": severity,
            "details": details,
            "rule_id": rule_id,
            "target": target,
            "port": int(port) if port is not None else None,
            "task_id": None,
            "assessment_id": None,
        }
        with self._callback_condition:
            if not self._running or self._stop_event.is_set():
                return
            if len(self._events) >= self._max_events:
                self._dropped += 1
            self._events.append(event)
            self._callbacks_inflight += 1
        try:
            self._on_event(event)
        except Exception as exc:
            self._add_limitation(
                f"event callback failed for {source}/{event_type}: {type(exc).__name__}: {exc}"
            )
        finally:
            with self._callback_condition:
                self._callbacks_inflight -= 1
                self._callback_condition.notify_all()

    def _set_source_status(self, source: str, status: str) -> None:
        if status not in {_STATUS_ACTIVE, _STATUS_UNAVAILABLE, _STATUS_LIMITED}:
            raise ValueError("invalid source status")
        with self._callback_condition:
            self._sources[source] = status

    def _add_limitation(self, message: str) -> None:
        with self._callback_condition:
            self._add_limitation_locked(message)

    def _add_limitation_locked(self, message: str) -> None:
        message = str(message)[:1000]
        if message not in self._limitations and len(self._limitations) < _MAX_LIMITATIONS:
            self._limitations.append(message)

    @staticmethod
    def _address_parts(address: Any) -> tuple[str | None, int | None]:
        if not address:
            return None, None
        if hasattr(address, "ip"):
            ip_value = getattr(address, "ip", None)
            port = getattr(address, "port", None)
        elif isinstance(address, tuple) and len(address) >= 2:
            ip_value, port = address[0], address[1]
        else:
            return None, None
        try:
            ip_value = str(ipaddress.ip_address(str(ip_value)))
        except ValueError:
            ip_value = None
        try:
            port = int(port) if port is not None else None
        except (TypeError, ValueError):
            port = None
        if port is not None and not 1 <= port <= 65535:
            port = None
        return ip_value, port

    @staticmethod
    def _find_literal_ip(line: str) -> str | None:
        for match in re.finditer(r"(?<![A-Za-z0-9_.:])(?:[0-9A-Fa-f]{1,4}:){2,}[0-9A-Fa-f:.]+|(?<![A-Za-z0-9_])(?:\d{1,3}\.){3}\d{1,3}(?![A-Za-z0-9_])", line):
            try:
                return str(ipaddress.ip_address(match.group(0)))
            except ValueError:
                continue
        return None

    @staticmethod
    def _find_port(line: str) -> int | None:
        match = re.search(r"\bport\s+(\d{1,5})\b", line, re.IGNORECASE)
        if not match:
            return None
        value = int(match.group(1))
        return value if 1 <= value <= 65535 else None

    @staticmethod
    def _redact_line(line: str) -> str:
        redacted = re.sub(
            r"(?i)\b(password|passwd|passphrase|token|secret|api[_-]?key|authorization|cookie)\b(\s*[:=]\s*)([^\s,;]+)",
            r"\1\2[REDACTED]",
            line,
        )
        redacted = re.sub(r"(?i)\bBearer\s+[^\s,;]+", "Bearer [REDACTED]", redacted)
        redacted = " ".join(redacted.replace("\x00", "").split())
        return redacted[:_MAX_RAW_LINE]

    @staticmethod
    def _parse_event_timestamp(line: str, observed_at: str) -> str | None:
        iso_match = re.search(
            r"\b(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\b",
            line,
        )
        if iso_match:
            value = iso_match.group(1).replace("Z", "+00:00")
            try:
                parsed = datetime.fromisoformat(value)
                if parsed.tzinfo is None or parsed.utcoffset() is None:
                    parsed = parsed.replace(tzinfo=timezone.utc)
                return parsed.astimezone(timezone.utc).isoformat()
            except ValueError:
                pass
        syslog = re.match(
            r"^\s*(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+(\d{1,2})\s+(\d{2}:\d{2}:\d{2})\b",
            line,
        )
        if not syslog:
            return None
        try:
            year = datetime.fromisoformat(observed_at).year
            parsed = datetime.strptime(
                f"{year} {syslog.group(1)} {syslog.group(2)} {syslog.group(3)}",
                "%Y %b %d %H:%M:%S",
            ).replace(tzinfo=timezone.utc)
            return parsed.isoformat()
        except ValueError:
            return None


def _utc_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


_AUTH_FAILURE_RE = re.compile(
    r"(?i)(failed\s+(?:password|login|publickey)|authentication\s+failure|auth(?:entication)?\s+fail(?:ed|ure)|login\s+failure)"
)


__all__ = ["BlueMonitor"]
