"""Fixed educational HTTP fixture for :mod:`secram.lab.manager`.

This worker intentionally exposes only a root HTML page over an owned Unix
socket. It has no upload, authentication, database, exploit, or arbitrary
command/image surface.
"""
from __future__ import annotations

import argparse
import os
import socketserver
import stat
import subprocess
import sys
from http.server import BaseHTTPRequestHandler
from pathlib import Path
from urllib.parse import urlsplit

SOCKET_NAME = "fixture.sock"
READY_NAME = "worker.ready"
MAX_DIAGNOSTIC = 2048

ROOT_HTML = (
    b"<!doctype html><html><head><title>SecRam educational fixture</title>"
    b"</head><body><h1>SecRam educational HTTP fixture</h1>"
    b"<p>This page intentionally omits common security response headers.</p>"
    b"</body></html>"
)


def _private_directory(path: Path) -> None:
    if not path.is_absolute():
        raise RuntimeError("worker data directory must be absolute")
    try:
        info = path.lstat()
    except OSError as exc:
        raise RuntimeError(f"worker data directory unavailable: {exc}") from exc
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        raise RuntimeError("worker data directory must be a real directory")
    if info.st_mode & 0o077:
        raise RuntimeError("worker data directory must have mode 0700")


def _fixed_path(directory: Path, name: str) -> Path:
    path = directory / name
    if path.parent != directory or path.name != name:
        raise RuntimeError("worker path traversal rejected")
    try:
        info = path.lstat()
    except FileNotFoundError:
        return path
    except OSError as exc:
        raise RuntimeError(f"cannot inspect worker path {name}: {exc}") from exc
    if stat.S_ISLNK(info.st_mode):
        raise RuntimeError(f"refusing symlinked worker path {name}")
    raise RuntimeError(f"worker path already exists: {name}")


def _ip_binary() -> str:
    for candidate in ("/usr/sbin/ip", "/sbin/ip", "/usr/bin/ip", "/bin/ip"):
        path = Path(candidate)
        try:
            if path.is_file() and os.access(path, os.X_OK):
                return candidate
        except OSError:
            continue
    raise RuntimeError("fixed ip command is unavailable")


def _bring_up_loopback() -> None:
    command = [_ip_binary(), "link", "set", "lo", "up"]
    try:
        completed = subprocess.run(
            command,
            check=True,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            timeout=5.0,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        details = str(exc)[:MAX_DIAGNOSTIC]
        if isinstance(exc, subprocess.CalledProcessError):
            details = (exc.stderr or b"").decode("utf-8", "replace")[:MAX_DIAGNOSTIC].strip() or details
        raise RuntimeError(f"cannot bring up loopback: {details}") from exc
    if completed.returncode != 0:
        raise RuntimeError("fixed loopback command failed")


class _FixtureHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.0"
    server_version = "SecRam-Lab-Fixture"
    sys_version = ""

    def log_message(self, _format: str, *_args: object) -> None:
        return

    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        self._serve_root(include_body=True)

    def do_HEAD(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        self._serve_root(include_body=False)

    def _serve_root(self, *, include_body: bool) -> None:
        self.close_connection = True
        try:
            path = urlsplit(self.path).path
        except ValueError:
            path = ""
        if path != "/":
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.send_header("Connection", "close")
            self.end_headers()
            return
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(ROOT_HTML)))
        self.send_header("Connection", "close")
        # Deliberately absent: CSP, HSTS, X-Content-Type-Options and X-Frame-Options.
        self.end_headers()
        if include_body:
            self.wfile.write(ROOT_HTML)

    def _method_not_allowed(self) -> None:
        self.close_connection = True
        self.send_response(405)
        self.send_header("Allow", "GET, HEAD")
        self.send_header("Content-Length", "0")
        self.send_header("Connection", "close")
        self.end_headers()

    do_POST = lambda self: self._method_not_allowed()  # noqa: N816,E731
    do_PUT = lambda self: self._method_not_allowed()  # noqa: N816,E731
    do_PATCH = lambda self: self._method_not_allowed()  # noqa: N816,E731
    do_DELETE = lambda self: self._method_not_allowed()  # noqa: N816,E731


class _FixtureServer(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True
    block_on_close = False

    def server_bind(self) -> None:
        if os.path.lexists(self.server_address):
            raise RuntimeError("fixture socket path unexpectedly exists")
        super().server_bind()
        os.chmod(self.server_address, 0o600)


def _write_ready(path: Path) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
    fd = os.open(path, flags, 0o600)
    try:
        os.write(fd, b"ready\n")
    finally:
        os.close(fd)


def _remove_owned(path: Path, *, socket_path: bool) -> None:
    try:
        info = path.lstat()
    except FileNotFoundError:
        return
    except OSError:
        return
    if stat.S_ISLNK(info.st_mode):
        return
    if (socket_path and stat.S_ISSOCK(info.st_mode)) or (
        not socket_path and stat.S_ISREG(info.st_mode)
    ):
        try:
            path.unlink()
        except OSError:
            pass


def run(data_dir: Path) -> int:
    _private_directory(data_dir)
    socket_path = _fixed_path(data_dir, SOCKET_NAME)
    ready_path = _fixed_path(data_dir, READY_NAME)
    _bring_up_loopback()
    server: _FixtureServer | None = None
    ready_written = False
    try:
        server = _FixtureServer(str(socket_path), _FixtureHandler)
        _write_ready(ready_path)
        ready_written = True
        server.serve_forever(poll_interval=0.1)
        return 0
    finally:
        if server is not None:
            server.server_close()
        if ready_written:
            _remove_owned(ready_path, socket_path=False)
        _remove_owned(socket_path, socket_path=True)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--data-dir", required=True)
    args = parser.parse_args(argv)
    try:
        return run(Path(args.data_dir))
    except BaseException as exc:  # bounded startup diagnostic; manager owns lifecycle
        message = f"{type(exc).__name__}: {str(exc)[:MAX_DIAGNOSTIC]}"
        print(message[:MAX_DIAGNOSTIC], file=sys.stderr, flush=True)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
