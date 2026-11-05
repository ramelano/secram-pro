"""Local-only real HTTP/TLS configuration validation, not exploit simulation."""
from __future__ import annotations

import argparse
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import ipaddress
import json
from pathlib import Path
import ssl
import tempfile
from threading import Thread

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from secram.services.application import ApplicationService


class TestPage(BaseHTTPRequestHandler):
    def do_HEAD(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Set-Cookie", "session=test-token-must-not-be-retained")
        self.end_headers()

    def log_message(self, *args):
        pass


@contextmanager
def serve(context=None):
    server = ThreadingHTTPServer(("127.0.0.1", 0), TestPage)
    if context is not None:
        server.socket = context.wrap_socket(server.socket, server_side=True)
    thread = Thread(target=server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
    thread.start()
    try:
        yield server.server_port
    finally:
        server.shutdown(); server.server_close(); thread.join(timeout=2)


def expired_context(directory):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "SecRam local test")])
    now = datetime.now(timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now-timedelta(days=2)).not_valid_after(now-timedelta(days=1))
            .add_extension(x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]), False)
            .sign(key, hashes.SHA256()))
    cert_path = directory / "public-test-cert.pem"
    key_path = directory / "private-test-key.pem"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    key_path.chmod(0o600)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert_path, key_path)
    return context


def main():
    parser = argparse.ArgumentParser(description="Yerel HTTP/TLS Phase 3 doğrulaması")
    parser.add_argument("--output", type=Path, default=Path("phase3-validation-output"))
    args = parser.parse_args(); args.output.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="secram-web-test-") as temp:
        directory = Path(temp)
        context = expired_context(directory)
        with serve() as http_port, serve(context) as tls_port:
            service = ApplicationService(directory / "data")
            try:
                assessment = service.create_assessment("Gerçek yerel HTTP/TLS kontrolü", ["127.0.0.1/32"],
                    "Yerel test sahibi", "Geçici HTML/TLS servisleri; dış hedef yok",
                    allowed_operations={"web.http_headers","web.tls_check"}, allowed_ports={http_port,tls_port})
                http = service.submit_operation(assessment.id,"HTTP","web.http_headers",target="127.0.0.1",
                                                port=http_port,params={"scheme":"http"})
                tls = service.submit_operation(assessment.id,"TLS","web.tls_check",target="127.0.0.1",port=tls_port)
                service.wait_idle()
                tasks = [service.repository.get_task(task.id) for task in (http,tls)]
                if any(task.state.value != "succeeded" for task in tasks):
                    raise RuntimeError([task.error for task in tasks])
                findings = service.list_findings(assessment.id)
                if not any(f.rule_id == "tls.certificate_expired" for f in findings):
                    raise RuntimeError("Real expired certificate observation was not recorded")
                if any(f.status.value != "candidate" for f in findings):
                    raise RuntimeError("Observation was incorrectly promoted to verified vulnerability")
                output = {"validation":"real local-only HTTP/TLS", "http_port":http_port,"tls_port":tls_port,
                          "tasks":[task.model_dump(mode="json") for task in tasks],
                          "findings":[finding.model_dump(mode="json") for finding in findings]}
                serialized = json.dumps(output,ensure_ascii=False,indent=2)
                if "test-token-must-not-be-retained" in serialized:
                    raise RuntimeError("Sensitive header retention regression")
                (args.output / "http-tls-validation.json").write_text(serialized+"\n",encoding="utf-8")
                print(json.dumps({"http_state":tasks[0].state.value,"tls_state":tasks[1].state.value,
                    "candidate_count":len(findings),"rules":[f.rule_id for f in findings],"output":str(args.output)},ensure_ascii=False))
            finally:
                service.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
