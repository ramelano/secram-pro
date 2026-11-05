from __future__ import annotations

import asyncio
import hashlib
import ipaddress
import json
import socket
import ssl
from datetime import timedelta

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from secram.core.models import Assessment, Authorization, Scope, Task, utcnow
from secram.core.policies import PolicyDenied
from secram.modules.vulnerability.checks import WebChecks


TARGET = "127.0.0.1"


def _assessment(port: int, operation: str) -> Assessment:
    return Assessment(
        title="Local web checks",
        scope=Scope(
            cidrs=["127.0.0.1/32"],
            allowed_operations={operation},
            allowed_ports={port},
            expires_at=utcnow() + timedelta(minutes=5),
        ),
        authorization=Authorization(
            approved_by="local-test-owner",
            evidence_reference="test_web_checks.py",
            statement="Temporary loopback fixture only",
        ),
    )


def _task(assessment: Assessment, operation: str, port: int, *, params: dict) -> Task:
    return Task(
        assessment_id=assessment.id,
        name="local web check",
        operation=operation,
        target=TARGET,
        port=port,
        params=params,
    )


async def _start_server(payload: bytes | None = None, *, tls: ssl.SSLContext | None = None):
    seen: list[bytes] = []

    async def handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            try:
                request = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 1)
            except (asyncio.TimeoutError, asyncio.IncompleteReadError, asyncio.LimitOverrunError):
                request = b""
            seen.append(request)
            if payload is not None:
                writer.write(payload)
                await writer.drain()
        finally:
            writer.close()
            try:
                await asyncio.wait_for(writer.wait_closed(), 1)
            except (asyncio.TimeoutError, OSError):
                pass

    server = await asyncio.start_server(handler, TARGET, 0, ssl=tls, family=socket.AF_INET)
    return server, server.sockets[0].getsockname()[1], seen


def _certificate_files(tmp_path, *, not_before=None, not_after=None):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = utcnow()
    not_before = not_before or now - timedelta(days=1)
    not_after = not_after or now + timedelta(days=1)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, TARGET)])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before.replace(tzinfo=None))
        .not_valid_after(not_after.replace(tzinfo=None))
        .add_extension(
            x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address(TARGET))]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    cert_path = tmp_path / "server-cert.pem"
    key_path = tmp_path / "server-key.pem"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
    )
    return cert, cert_path, key_path


def _server_tls_context(cert_path, key_path) -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile=cert_path, keyfile=key_path)
    return context


def test_real_http_root_head_and_bounded_security_headers():
    async def scenario():
        payload = (
            b"HTTP/1.1 200 OK\r\n"
            b"Content-Type: text/html; charset=utf-8\r\n"
            b"Content-Security-Policy: default-src 'self'\r\n"
            b"X-Frame-Options: DENY\r\n"
            b"X-Content-Type-Options: nosniff\r\n"
            b"Referrer-Policy: no-referrer\r\n"
            b"Set-Cookie: session=secret-token\r\n"
            b"Authorization: Bearer secret-token\r\n"
            b"Content-Length: 12\r\n\r\n"
            b"body-secret"
        )
        server, port, seen = await _start_server(payload)
        try:
            assessment = _assessment(port, "web.http_headers")
            task = _task(assessment, "web.http_headers", port, params={"scheme": "http"})
            result = await WebChecks().run(task, assessment)
        finally:
            server.close()
            await server.wait_closed()
        assert result["status"] == "complete"
        assert result["operation"] == "web.http_headers"
        assert result["target"] == TARGET
        assert result["port"] == port
        assert result["observations"]["response"]["status_code"] == 200
        assert result["observations"]["response"]["security_headers"]["content-security-policy"]
        assert result["observations"]["response"]["sensitive_header_names_omitted"] == [
            "authorization",
            "set-cookie",
        ]
        request = seen[0]
        assert request.startswith(b"HEAD / HTTP/1.1\r\n")
        assert f"Host: {TARGET}:{port}\r\n".encode() in request
        assert b"Connection: close\r\n" in request
        serialized = json.dumps(result, sort_keys=True)
        assert "secret-token" not in serialized
        assert "body-secret" not in serialized
        assert result["evidence_sha256"] == hashlib.sha256(
            json.dumps(
                {
                    "observations": result["observations"],
                    "finding_candidates": result["finding_candidates"],
                },
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
            ).encode()
        ).hexdigest()

    asyncio.run(scenario())


def test_redirect_is_not_followed():
    async def scenario():
        payload = b"HTTP/1.1 302 Found\r\nLocation: /private\r\nContent-Type: text/html\r\n\r\n"
        server, port, seen = await _start_server(payload)
        try:
            assessment = _assessment(port, "web.http_headers")
            task = _task(assessment, "web.http_headers", port, params={"scheme": "http"})
            result = await WebChecks().run(task, assessment)
        finally:
            server.close()
            await server.wait_closed()
        assert result["status"] == "complete"
        assert result["observations"]["response"]["status_code"] == 302
        assert len(seen) == 1
        assert any("not followed" in item for item in result["limitations"])
        assert all("private" not in json.dumps(candidate) for candidate in result["finding_candidates"])

    asyncio.run(scenario())


def test_json_content_type_does_not_create_html_csp_or_frame_findings():
    async def scenario():
        payload = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{}"
        server, port, _ = await _start_server(payload)
        try:
            assessment = _assessment(port, "web.http_headers")
            task = _task(assessment, "web.http_headers", port, params={"scheme": "http"})
            result = await WebChecks().run(task, assessment)
        finally:
            server.close()
            await server.wait_closed()
        rules = {candidate["rule_id"] for candidate in result["finding_candidates"]}
        assert "web.missing_content_security_policy" not in rules
        assert "web.missing_frame_policy" not in rules
        assert {"web.missing_nosniff", "web.missing_referrer_policy"} <= rules
        assert all(candidate["severity"] == "info" for candidate in result["finding_candidates"])

    asyncio.run(scenario())


def test_https_verification_failure_is_inconclusive_without_header_findings(tmp_path):
    async def scenario():
        _, cert_path, key_path = _certificate_files(tmp_path)
        server, port, seen = await _start_server(
            b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n",
            tls=_server_tls_context(cert_path, key_path),
        )
        try:
            assessment = _assessment(port, "web.http_headers")
            task = _task(assessment, "web.http_headers", port, params={"scheme": "https"})
            result = await WebChecks().run(task, assessment)
        finally:
            server.close()
            await server.wait_closed()
        assert result["status"] == "inconclusive"
        assert result["finding_candidates"] == []
        assert any("no unverified HTTP retry" in item for item in result["limitations"])
        assert all(request == b"" for request in seen)

    asyncio.run(scenario())


def test_real_tls_self_signed_certificate_observations_and_no_http(tmp_path):
    async def scenario():
        cert, cert_path, key_path = _certificate_files(tmp_path)
        server, port, seen = await _start_server(tls=_server_tls_context(cert_path, key_path))
        try:
            assessment = _assessment(port, "web.tls_check")
            task = _task(assessment, "web.tls_check", port, params={})
            result = await WebChecks().run(task, assessment)
        finally:
            server.close()
            await server.wait_closed()
        observations = result["observations"]
        certificate = observations["certificate"]
        assert result["status"] == "complete"
        assert observations["verification"]["status"] == "untrusted"
        assert certificate["sha256"] == hashlib.sha256(cert.public_bytes(serialization.Encoding.DER)).hexdigest()
        assert certificate["key_algorithm"] == "RSA"
        assert certificate["key_size"] == 2048
        assert certificate["not_valid_after"].endswith("+00:00")
        assert observations["negotiated"]["protocol"].startswith("TLS")
        assert observations["negotiated"]["cipher"]
        assert any(candidate["rule_id"] == "tls.untrusted_certificate" for candidate in result["finding_candidates"])
        assert all(candidate["evidence"]["observation_confirmed"] is True for candidate in result["finding_candidates"])
        assert all(request == b"" for request in seen)

    asyncio.run(scenario())


def test_scope_and_timeout_errors_are_explicit(monkeypatch):
    async def scenario():
        assessment = _assessment(443, "web.tls_check")
        outside = _task(assessment, "web.tls_check", 443, params={})
        outside.target = "192.0.2.1"
        with pytest.raises(PolicyDenied):
            WebChecks().validate(outside, assessment)

        async def timeout_connect(*args, **kwargs):
            raise asyncio.TimeoutError

        monkeypatch.setattr(WebChecks, "_connect", staticmethod(timeout_connect))
        task = _task(assessment, "web.tls_check", 443, params={})
        result = await WebChecks().run(task, assessment)
        assert result["status"] == "inconclusive"
        assert result["finding_candidates"] == []
        assert any("timed out" in item for item in result["limitations"])

    asyncio.run(scenario())


def test_header_cap_produces_no_inferred_findings():
    async def scenario():
        oversized = b"HTTP/1.1 200 OK\r\nX-Filler: " + (b"x" * 70000) + b"\r\n\r\n"
        server, port, _ = await _start_server(oversized)
        try:
            assessment = _assessment(port, "web.http_headers")
            task = _task(assessment, "web.http_headers", port, params={"scheme": "http"})
            result = await WebChecks().run(task, assessment)
        finally:
            server.close()
            await server.wait_closed()
        assert result["status"] == "inconclusive"
        assert result["finding_candidates"] == []
        assert result["observations"]["response"]["headers_capped"] is True
        assert result["observations"]["response"]["header_limit_bytes"] == 64 * 1024

    asyncio.run(scenario())
