"""Real local-only Phase 2 validation; never accepts an external target."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import socket
import tempfile

from secram.services.application import ApplicationService


def main() -> int:
    parser = argparse.ArgumentParser(description="Yerel Host/Nmap Phase 2 doğrulaması")
    parser.add_argument("--output", type=Path, default=Path("validation-output"))
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="secram-validation-") as directory:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
            listener.bind(("127.0.0.1", 0))
            listener.listen(4)
            port = listener.getsockname()[1]
            service = ApplicationService(Path(directory))
            try:
                assessment = service.create_assessment(
                    "Gerçek yerel Phase 2 doğrulaması", ["127.0.0.1/32"], "Sandbox yerel test sahibi",
                    "Geçici loopback TCP dinleyicisi; dış hedef yok",
                    allowed_operations={"host.snapshot", "nmap.tcp_scan"}, allowed_ports={port},
                )
                host_task = service.submit_operation(assessment.id, "Host anlık bilgi", "host.snapshot")
                nmap_task = service.submit_operation(assessment.id, "Yerel TCP testi", "nmap.tcp_scan",
                                                     target="127.0.0.1", params={"ports": [port]})
                service.wait_idle()
                host = service.repository.get_task(host_task.id)
                scan = service.repository.get_task(nmap_task.id)
                if host.state.value != "succeeded" or scan.state.value != "succeeded":
                    raise RuntimeError(f"Validation failed: {host.error}; {scan.error}")
                ports = scan.result.get("hosts", [{}])[0].get("ports", [])
                if not any(record["port"] == port and record["state"] == "open" for record in ports):
                    raise RuntimeError("Local listener was not verified open")
                xml = scan.result["stdout"]
                digest = hashlib.sha256(xml.encode("utf-8")).hexdigest()
                if digest != scan.result["raw_xml_sha256"]:
                    raise RuntimeError("Evidence hash mismatch")
                (args.output / "nmap-loopback.xml").write_text(xml, encoding="utf-8")
                (args.output / "nmap-task.json").write_text(scan.model_dump_json(indent=2), encoding="utf-8")
                # Public summary avoids publishing the detailed local process/interface inventory.
                summary = {
                    "validation": "real local-only Phase 2",
                    "target": "127.0.0.1", "authorized_port": port,
                    "host": {
                        "task_state": host.state.value, "snapshot_status": host.result["status"],
                        "collected_at": host.result["collected_at"],
                        "cpu": host.result["cpu"], "memory": host.result["memory"],
                        "storage": host.result["storage"],
                        "process_count": len(host.result["processes"]["items"]),
                        "interface_address_count": len(host.result["network"]["interfaces"]),
                        "services_status": host.result["services"]["status"],
                        "limitations": host.result["limitations"],
                        "measurement_context": host.result["measurement_context"],
                    },
                    "nmap": {"task_state": scan.state.value, "tool_version": scan.result["tool_version"],
                             "scan_status": scan.result["scan_status"], "observed_ports": ports,
                             "raw_xml_sha256": digest, "command": scan.result["command"]},
                    "audit_records": service.counts()["audit"],
                }
                (args.output / "validation-summary.json").write_text(
                    json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
                print(json.dumps({"host_state": host.state.value, "host_status": host.result["status"],
                                  "services": host.result["services"]["status"],
                                  "nmap_state": scan.state.value, "open_port": port,
                                  "sha256": digest, "output": str(args.output)}, ensure_ascii=False))
            finally:
                service.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
