"""Rootless, fixed-scope educational HTTP lab manager.

The lab is deliberately small: one Python HTTP fixture in a rootless user and
network namespace, reached through a loopback-only gateway.  It is not a
container runtime and is not a boundary for untrusted exploit code.
"""
from __future__ import annotations

import json
import os
import shutil
import signal
import socket
import socketserver
import stat
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit
from uuid import uuid4


SOCKET_NAME = "fixture.sock"
READY_NAME = "worker.ready"
TELEMETRY_NAME = "telemetry.jsonl"
READY_DEADLINE_SECONDS = 5.0
PROCESS_TERM_TIMEOUT_SECONDS = 1.5
MAX_DIAGNOSTICS = 2048
MAX_REQUEST_TARGET = 2048
MAX_RESPONSE_BYTES = 64 * 1024

ISOLATION_NOTE = (
    "Rootless unshare -Urn user+network namespace with a loopback-only child; "
    "the kernel and filesystem are shared, so this is not safe for untrusted "
    "exploits and is not equivalent to Podman or KVM. The 127.0.0.1 gateway "
    "deliberately crosses the namespace boundary."
)


def _find_unshare() -> str | None:
    """Return only a standard, executable unshare path; never accept user input."""
    for candidate in ("/usr/bin/unshare", "/bin/unshare"):
        path = Path(candidate)
        try:
            if path.is_file() and os.access(path, os.X_OK):
                return candidate
        except OSError:
            continue
    return None


def _bounded_text(value: bytes | str | None, limit: int = MAX_DIAGNOSTICS) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        value = value.decode("utf-8", "replace")
    return value[:limit].strip()


def _response_status(response: bytes) -> int | None:
    try:
        first_line = response.split(b"\r\n", 1)[0].decode("ascii", "strict")
        parts = first_line.split(" ", 2)
        if len(parts) >= 2 and parts[0].startswith("HTTP/"):
            status = int(parts[1])
            return status if 100 <= status <= 599 else None
    except (ValueError, UnicodeDecodeError):
        pass
    return None


class _GatewayServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = False
    daemon_threads = True
    block_on_close = False


class _GatewayHandler(BaseHTTPRequestHandler):
    """Forward only GET/HEAD requests to the one owned Unix-socket fixture."""

    protocol_version = "HTTP/1.0"
    server_version = "SecRam-Lab-Gateway"
    sys_version = ""

    def setup(self) -> None:
        self.request.settimeout(3.0)
        super().setup()

    def handle(self) -> None:
        try:
            super().handle()
        except (ConnectionResetError, BrokenPipeError):
            # A TCP-connect port probe can close without sending HTTP.
            self.close_connection = True

    def log_message(self, _format: str, *_args: object) -> None:
        # The lab's durable evidence is the bounded telemetry JSONL, not stderr.
        return

    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        self._forward("GET")

    def do_HEAD(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        self._forward("HEAD")

    def do_POST(self) -> None:  # noqa: N802 - explicitly no upload surface
        self._reject_method("POST")

    def do_PUT(self) -> None:  # noqa: N802 - explicitly no upload surface
        self._reject_method("PUT")

    def do_PATCH(self) -> None:  # noqa: N802 - explicitly no upload surface
        self._reject_method("PATCH")

    def do_DELETE(self) -> None:  # noqa: N802 - explicitly no destructive surface
        self._reject_method("DELETE")

    def _reject_method(self, method: str) -> None:
        self.close_connection = True
        self._simple_response(405)
        self._record(method, 405)

    def _simple_response(self, status: int) -> None:
        try:
            self.send_response(status)
            self.send_header("Content-Length", "0")
            self.send_header("Connection", "close")
            self.end_headers()
        except (BrokenPipeError, ConnectionResetError):
            pass

    def _forward(self, method: str) -> None:
        self.close_connection = True
        target = self.path
        status = 502
        if (
            not target
            or len(target) > MAX_REQUEST_TARGET
            or not target.startswith("/")
            or "\r" in target
            or "\n" in target
            or any(ord(char) > 127 for char in target)
        ):
            self._simple_response(400)
            self._record(method, 400)
            return

        request_target = target.encode("ascii")
        request = (
            method.encode("ascii")
            + b" "
            + request_target
            + b" HTTP/1.0\r\n"
            + b"Host: 127.0.0.1\r\n"
            + b"Connection: close\r\n\r\n"
        )
        response = bytearray()
        try:
            fixture_path = self.server.fixture_socket  # type: ignore[attr-defined]
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as upstream:
                upstream.settimeout(2.0)
                upstream.connect(str(fixture_path))
                upstream.sendall(request)
                while True:
                    chunk = upstream.recv(8192)
                    if not chunk:
                        break
                    if len(response) + len(chunk) > MAX_RESPONSE_BYTES:
                        raise RuntimeError("fixture response exceeded cap")
                    response.extend(chunk)
            status = _response_status(bytes(response)) or 502
            if response:
                self.wfile.write(response)
                self.wfile.flush()
            else:
                self._simple_response(502)
        except (
            OSError,
            RuntimeError,
            socket.timeout,
            BrokenPipeError,
            ConnectionResetError,
        ):
            self._simple_response(503)
            status = 503
        finally:
            self._record(method, status)

    def _record(self, method: str, status: int) -> None:
        manager = self.server.manager  # type: ignore[attr-defined]
        manager._record_http_event(method, self.path[:MAX_REQUEST_TARGET], status)


class LabManager:
    """Own exactly one fixed educational HTTP fixture and its gateway."""

    def __init__(self, data_dir: Path):
        self._data_dir = Path(data_dir).absolute()
        self._ensure_private_data_dir()
        self._socket_path = self._child_path(SOCKET_NAME)
        self._ready_path = self._child_path(READY_NAME)
        self._telemetry_path = self._child_path(TELEMETRY_NAME)
        self._lab_id = str(uuid4())
        self._process: subprocess.Popen[bytes] | None = None
        self._gateway: _GatewayServer | None = None
        self._gateway_thread: threading.Thread | None = None
        self._gateway_port: int | None = None
        self._lock = threading.RLock()
        self._telemetry_lock = threading.Lock()
        self._last_reason: str | None = None
        self._closed = False

    def _ensure_private_data_dir(self) -> None:
        try:
            try:
                info = self._data_dir.lstat()
            except FileNotFoundError:
                self._data_dir.mkdir(parents=True, mode=0o700, exist_ok=False)
                info = self._data_dir.lstat()
            if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
                raise ValueError("Lab data_dir must be a real directory, not a symlink")
            if info.st_uid != os.getuid():
                raise ValueError("Lab data_dir must be owned by the current user")
            os.chmod(self._data_dir, 0o700)
            info = self._data_dir.lstat()
            if info.st_mode & 0o077:
                raise ValueError("Lab data_dir must have mode 0700")
        except OSError as exc:
            raise ValueError(f"Lab data_dir is unavailable: {exc}") from exc

    def _child_path(self, name: str) -> Path:
        if name not in {SOCKET_NAME, READY_NAME, TELEMETRY_NAME}:
            raise ValueError("Unexpected lab path")
        path = self._data_dir / name
        if path.parent != self._data_dir or path.name != name:
            raise ValueError("Lab path traversal rejected")
        return path

    def _base_status(self, state: str, *, reason: str | None = None) -> dict[str, Any]:
        result: dict[str, Any] = {
            "status": state,
            "lab_id": self._lab_id,
            "target": "127.0.0.1",
            "port": self._gateway_port if state == "running" else None,
            "telemetry_path": str(self._telemetry_path),
            "isolation": ISOLATION_NOTE,
        }
        if reason:
            result["reason"] = reason
        return result

    def _path_kind(self, path: Path) -> int | None:
        try:
            return path.lstat().st_mode
        except FileNotFoundError:
            return None
        except OSError as exc:
            raise RuntimeError(f"Cannot inspect owned lab path {path.name}: {exc}") from exc

    def _prepare_ipc_paths(self) -> None:
        # These are the only paths this manager ever removes. Symlinks are never followed.
        for path, expected in (
            (self._socket_path, "socket"),
            (self._ready_path, "regular"),
        ):
            mode = self._path_kind(path)
            if mode is None:
                continue
            if stat.S_ISLNK(mode):
                raise RuntimeError(f"Refusing symlinked lab IPC path: {path.name}")
            if expected == "socket" and not stat.S_ISSOCK(mode):
                raise RuntimeError(f"Unexpected existing lab socket path: {path.name}")
            if expected == "regular" and not stat.S_ISREG(mode):
                raise RuntimeError(f"Unexpected existing lab readiness path: {path.name}")
            os.unlink(path)

    def _ensure_telemetry_file(self) -> None:
        mode = self._path_kind(self._telemetry_path)
        if mode is not None:
            if stat.S_ISLNK(mode) or not stat.S_ISREG(mode):
                raise RuntimeError("Telemetry path must be a regular, non-symlink file")
            os.chmod(self._telemetry_path, 0o600)
            return
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
        fd = os.open(self._telemetry_path, flags, 0o600)
        os.close(fd)

    def _read_diagnostics(self, process: subprocess.Popen[bytes]) -> str:
        try:
            _stdout, stderr = process.communicate(timeout=0.5)
        except (subprocess.TimeoutExpired, OSError):
            return ""
        return _bounded_text(stderr)

    def _terminate_process(self) -> str:
        process = self._process
        if process is None:
            return ""
        diagnostics = ""
        try:
            if process.poll() is None:
                try:
                    if os.getpgid(process.pid) == process.pid:
                        os.killpg(process.pid, signal.SIGTERM)
                    else:
                        process.terminate()
                except (OSError, ProcessLookupError):
                    pass
                try:
                    process.wait(timeout=PROCESS_TERM_TIMEOUT_SECONDS)
                except subprocess.TimeoutExpired:
                    try:
                        if os.getpgid(process.pid) == process.pid:
                            os.killpg(process.pid, signal.SIGKILL)
                        else:
                            process.kill()
                    except (OSError, ProcessLookupError):
                        pass
                    try:
                        process.wait(timeout=PROCESS_TERM_TIMEOUT_SECONDS)
                    except subprocess.TimeoutExpired:
                        pass
            diagnostics = self._read_diagnostics(process)
        finally:
            self._process = None
        return diagnostics

    def _cleanup_ipc_paths(self) -> None:
        for path, is_socket in ((self._socket_path, True), (self._ready_path, False)):
            try:
                mode = path.lstat().st_mode
            except FileNotFoundError:
                continue
            except OSError:
                continue
            if stat.S_ISLNK(mode):
                continue
            if (is_socket and stat.S_ISSOCK(mode)) or (not is_socket and stat.S_ISREG(mode)):
                try:
                    os.unlink(path)
                except OSError:
                    pass

    def _wait_ready(self) -> tuple[bool, str]:
        deadline = time.monotonic() + READY_DEADLINE_SECONDS
        process = self._process
        if process is None:
            return False, "worker process was not started"
        while time.monotonic() < deadline:
            if process.poll() is not None:
                diagnostics = self._read_diagnostics(process)
                reason = f"worker exited with status {process.returncode}"
                if diagnostics:
                    reason += f": {diagnostics}"
                return False, reason[:MAX_DIAGNOSTICS]
            try:
                ready_mode = self._ready_path.lstat().st_mode
                socket_mode = self._socket_path.lstat().st_mode
                if (
                    stat.S_ISREG(ready_mode)
                    and not stat.S_ISLNK(ready_mode)
                    and stat.S_ISSOCK(socket_mode)
                    and not stat.S_ISLNK(socket_mode)
                    and self._ready_path.read_bytes()[:32] == b"ready\n"
                ):
                    return True, ""
            except FileNotFoundError:
                pass
            except OSError as exc:
                return False, f"worker readiness check failed: {exc}"[:MAX_DIAGNOSTICS]
            time.sleep(0.03)
        diagnostics = self._terminate_process()
        reason = f"worker readiness timeout after {READY_DEADLINE_SECONDS:.1f}s"
        if diagnostics:
            reason += f": {diagnostics}"
        return False, reason[:MAX_DIAGNOSTICS]

    def _shutdown_gateway(self) -> None:
        gateway = self._gateway
        thread = self._gateway_thread
        self._gateway = None
        self._gateway_thread = None
        self._gateway_port = None
        if gateway is not None:
            try:
                if thread is not None and thread.is_alive():
                    gateway.shutdown()
            except (OSError, RuntimeError):
                pass
            try:
                gateway.server_close()
            except OSError:
                pass
        if thread is not None:
            thread.join(timeout=PROCESS_TERM_TIMEOUT_SECONDS)

    def _unavailable(self, reason: str) -> dict[str, Any]:
        self._last_reason = reason[:MAX_DIAGNOSTICS]
        return self._base_status("notavailable", reason=self._last_reason)

    def create(self) -> dict[str, Any]:
        with self._lock:
            if self._closed:
                raise RuntimeError("LabManager is closed")
            if self._process is not None and self._process.poll() is None and self._gateway is not None:
                return self._base_status("running")
            if self._process is not None:
                self._shutdown_gateway()
                diagnostics = self._terminate_process()
                self._cleanup_ipc_paths()
                if diagnostics:
                    self._last_reason = diagnostics
            try:
                self._prepare_ipc_paths()
                self._ensure_telemetry_file()
            except (OSError, RuntimeError) as exc:
                return self._unavailable(str(exc))

            unshare = _find_unshare()
            if unshare is None:
                return self._unavailable(
                    "unshare command is unavailable; rootless user+network isolation is not available"
                )
            command = [
                unshare,
                "-Urn",
                "--",
                sys.executable,
                "-m",
                "secram.lab.worker",
                "--data-dir",
                str(self._data_dir),
            ]
            try:
                self._process = subprocess.Popen(
                    command,
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.PIPE,
                    close_fds=True,
                    start_new_session=True,
                )
            except OSError as exc:
                return self._unavailable(f"cannot start rootless unshare: {exc}")

            ready, reason = self._wait_ready()
            if not ready:
                diagnostics = self._terminate_process()
                if diagnostics and diagnostics not in reason:
                    reason = f"{reason}: {diagnostics}"
                self._cleanup_ipc_paths()
                return self._unavailable(reason)

            try:
                gateway = _GatewayServer(("127.0.0.1", 0), _GatewayHandler)
                if gateway.server_address[0] != "127.0.0.1":
                    gateway.server_close()
                    raise RuntimeError("gateway did not bind to 127.0.0.1")
                gateway.fixture_socket = self._socket_path  # type: ignore[attr-defined]
                gateway.manager = self  # type: ignore[attr-defined]
                self._gateway = gateway
                self._gateway_port = int(gateway.server_address[1])
                self._gateway_thread = threading.Thread(
                    target=gateway.serve_forever,
                    kwargs={"poll_interval": 0.05},
                    name=f"secram-lab-{self._lab_id[:8]}",
                    daemon=True,
                )
                self._gateway_thread.start()
            except (OSError, RuntimeError) as exc:
                self._shutdown_gateway()
                self._terminate_process()
                self._cleanup_ipc_paths()
                return self._unavailable(f"cannot create loopback gateway: {exc}")
            self._last_reason = None
            return self._base_status("running")

    def _record_http_event(self, method: str, path: str, status: int) -> None:
        event = {
            "id": str(uuid4()),
            "observed_at": datetime.now(timezone.utc).isoformat(),
            "source": "lab_sensor",
            "event_type": "http.request",
            "severity": "info",
            "details": {"method": method, "path": path[:MAX_REQUEST_TARGET], "status": int(status)},
            "rule_id": None,
            "target": "127.0.0.1",
            "port": self._gateway_port,
            "task_id": None,
            "assessment_id": None,
        }
        line = (json.dumps(event, separators=(",", ":"), sort_keys=True) + "\n").encode("utf-8")
        with self._telemetry_lock:
            try:
                flags = os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW
                fd = os.open(self._telemetry_path, flags, 0o600)
                try:
                    os.fchmod(fd, 0o600)
                    view = memoryview(line)
                    while view:
                        view = view[os.write(fd, view) :]
                finally:
                    os.close(fd)
            except OSError:
                # A telemetry write must never turn a real fixture response into a fake one.
                return

    def status(self) -> dict[str, Any]:
        with self._lock:
            if self._process is not None and self._process.poll() is None and self._gateway is not None:
                return self._base_status("running")
            if self._process is not None:
                self._shutdown_gateway()
                diagnostics = self._terminate_process()
                self._cleanup_ipc_paths()
                reason = self._last_reason or "lab worker is no longer running"
                if diagnostics:
                    reason = f"{reason}: {diagnostics}"
                return self._unavailable(reason)
            return self._base_status("notavailable", reason=self._last_reason)

    def stop(self) -> dict[str, Any]:
        with self._lock:
            self._shutdown_gateway()
            diagnostics = self._terminate_process()
            self._cleanup_ipc_paths()
            self._last_reason = "stopped"
            if diagnostics:
                self._last_reason = f"stopped; worker diagnostics: {diagnostics}"
            return self._base_status("notavailable", reason=self._last_reason)

    def close(self) -> None:
        with self._lock:
            if not self._closed:
                self.stop()
                self._closed = True


__all__ = ["LabManager"]
