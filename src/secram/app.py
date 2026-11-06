from __future__ import annotations

import argparse
import ipaddress
import json
from pathlib import Path
import shutil
import sys

from secram.services.application import ApplicationService


def _print(value):
    print(json.dumps(value,ensure_ascii=False,indent=2,default=str))


def _profile(service, path):
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 65536:
        raise ValueError("Profil, symlink olmayan ve en fazla 64 KiB boyutunda yerel JSON dosyası olmalı")
    data=json.loads(path.read_text(encoding="utf-8"))
    allowed={"title","cidrs","approved_by","evidence_reference","expires_hours","allowed_operations","ports","target","web_services"}
    if not isinstance(data,dict) or set(data)-allowed:
        raise ValueError("Profil yalnız belgelenmiş kapsam/izin/protokol alanlarını kabul eder")
    required={"title","cidrs","approved_by","evidence_reference","allowed_operations","ports","target"}
    if required-set(data): raise ValueError("Eksik profil alanları: "+", ".join(sorted(required-set(data))))
    assessment=service.create_assessment(data["title"],data["cidrs"],data["approved_by"],data["evidence_reference"],
        expires_hours=data.get("expires_hours",1),allowed_operations=set(data["allowed_operations"]),allowed_ports=set(data["ports"]))
    task=service.submit_operation(assessment.id,"CLI otonom profil","orchestrator.run",target=data["target"],
        params={"ports":data["ports"],"web_services":data.get("web_services",{})})
    service.wait_idle(260)
    completed=service.repository.get_task(task.id)
    _print(completed.model_dump(mode="json"))
    return 0 if completed.state.value=="succeeded" and completed.result.get("status")=="complete" else 1


def _scan_ports(text: str) -> list[int]:
    parts = [part.strip() for part in text.split(",") if part.strip()]
    if not 1 <= len(parts) <= 32 or any(not part.isascii() or not part.isdecimal() for part in parts):
        raise ValueError("--scan-ports 1–32 adet virgülle ayrılmış sayı olmalı")
    ports = [int(part) for part in parts]
    if len(set(ports)) != len(ports) or any(not 1 <= port <= 65535 for port in ports):
        raise ValueError("Tarama portları 1–65535 arasında ve farklı olmalı")
    return ports


def _scan_summary(result: object) -> str:
    if not isinstance(result, dict):
        return "Sonuç özeti alınamadı."
    hosts = result.get("hosts") or []
    ports = hosts[0].get("ports", []) if hosts and isinstance(hosts[0], dict) else []
    opened = [str(item.get("port")) for item in ports if item.get("state") == "open"]
    closed = [str(item.get("port")) for item in ports if item.get("state") != "open"]
    return f"Açık: {', '.join(opened) or 'yok'} | Kapalı/filtreli: {', '.join(closed) or 'yok'}"


def _quick_scan(service, target: str, ports_text: str, output: Path | None, authorized: bool) -> int:
    if not authorized:
        raise ValueError("Tarama için --authorized açık yetki beyanı gerekir")
    try:
        address = ipaddress.ip_address(target)
    except ValueError as exc:
        raise ValueError("--scan-target yalnızca literal IPv4/IPv6 adresi kabul eder") from exc
    if address.is_unspecified or address.is_multicast or address.is_reserved:
        raise ValueError("Bu IP adresi tarama hedefi olarak kabul edilmez")
    ports = _scan_ports(ports_text)
    assessment = service.create_assessment(
        "Terminal hızlı TCP taraması", [f"{address}/{'128' if address.version == 6 else '32'}"],
        "CLI kullanıcısı", "CLI --authorized kullanıcı beyanı", expires_hours=1,
        allowed_operations={"nmap.tcp_scan"}, allowed_ports=set(ports),
    )
    task = service.submit_operation(assessment.id, "Terminal hızlı Nmap TCP", "nmap.tcp_scan",
                                    target=str(address), params={"ports": ports})
    service.wait_idle(70)
    completed = service.repository.get_task(task.id)
    saved = service.save_task_result(task.id, output) if output else service.save_task_result(task.id)
    result = completed.model_dump(mode="json")
    result["result_file"] = str(saved)
    result["summary"] = _scan_summary(result.get("result"))
    _print(result)
    return 0 if completed.state.value == "succeeded" else 1


def main() -> int:
    parser=argparse.ArgumentParser(description="SecRam-Pro v0.4.0 — çevrimdışı, kapsam kontrollü Linux değerlendirme")
    parser.add_argument("--data-dir",type=Path,help="Ayrı kullanıcı veri dizini")
    parser.add_argument("--smoke-test",action="store_true",help="Qt arayüzünü açıp kısa süre sonra kapatır")
    checks=parser.add_mutually_exclusive_group()
    checks.add_argument("--self-check",action="store_true",help="Yerel çekirdek kontrolü; tarama yok")
    checks.add_argument("--host-snapshot",action="store_true",help="Gerçek salt okunur yerel Host verisi")
    checks.add_argument("--doctor",action="store_true",help="Yerel bağımlılık/durum bilgisi; tarama yok")
    checks.add_argument("--lab-demo",action="store_true",help="Yalnız kendi geçici rootless HTTP Lab'ında gerçek otonom test")
    checks.add_argument("--run-assessment",type=Path,help="Açık yetki/kapsam içeren yerel JSON profil")
    checks.add_argument("--scan-target",help="Tek literal IP için hızlı TCP taraması")
    checks.add_argument("--show-network",action="store_true",help="Yerel IP/CIDR/gateway bilgisini gösterir; tarama yapmaz")
    checks.add_argument("--import-osv",type=Path,help="Yerel OSV JSON verisini içe aktar")
    checks.add_argument("--list-assessments",action="store_true",help="Kayıtlı değerlendirmeleri JSON listeler")
    checks.add_argument("--export",metavar="ASSESSMENT_ID",help="Değerlendirmeyi beş formatta dışa aktar")
    parser.add_argument("--output-dir",type=Path,help="--export için yerel rapor dizini")
    parser.add_argument("--scan-ports",help="--scan-target için örn. 22,80,443")
    parser.add_argument("--scan-output",type=Path,help="Tarama JSON sonucunun yazılacağı dosya")
    parser.add_argument("--authorized",action="store_true",help="Bu hedef için açık yetki beyanı")
    args=parser.parse_args()
    if sys.platform!="linux": parser.error("Bu sürüm yalnız Linux destekler")
    service=None
    try:
        service=ApplicationService(args.data_dir)
        if args.doctor:
            _print({"version":"0.4.0","platform":sys.platform,"python":sys.version,"tools":service.list_tools(),
                    "lab_commands":{"unshare":shutil.which("unshare"),"ip":shutil.which("ip")},
                    "rootless_namespace_verified":False,"advisory_data":service.advisory_status(),
                    "data_dir":str(service.data_dir),"security_assessment":False})
            return 0
        if args.show_network:
            _print(service.discover_network())
            return 0
        if args.list_assessments:
            _print([a.model_dump(mode="json") for a in service.list_assessments()]); return 0
        if args.import_osv:
            result=service.import_advisories(args.import_osv); _print(result)
            return 0 if result["accepted"] else 1
        if args.export:
            result=service.export_report(args.export,args.output_dir); _print(result)
            return 0 if not result["unavailable_formats"] else 1
        if args.scan_target is not None:
            if not args.scan_ports:
                parser.error("--scan-target ile birlikte --scan-ports zorunludur")
            return _quick_scan(service, args.scan_target, args.scan_ports, args.scan_output, args.authorized)
        if args.run_assessment: return _profile(service,args.run_assessment)
        if args.lab_demo:
            lab=service.create_lab()
            if lab["status"]!="running": _print(lab); return 1
            assessment=service.create_assessment("CLI kontrollü Lab",["127.0.0.1/32"],"Yerel Lab sahibi",
                "CLI --lab-demo: yalnız uygulamanın kendi rootless loopback HTTP servisi",expires_hours=1,
                allowed_operations={"orchestrator.run","nmap.tcp_scan","web.http_headers","blue.monitor"},allowed_ports={lab["port"]})
            task=service.submit_operation(assessment.id,"Gerçek otonom Lab demosu","orchestrator.run",target="127.0.0.1",
                params={"ports":[lab["port"]],"web_services":{str(lab["port"]):"http"}})
            service.wait_idle(260); completed=service.repository.get_task(task.id)
            _print(completed.model_dump(mode="json"))
            return 0 if completed.state.value=="succeeded" and completed.result.get("status")=="complete" else 1
        if args.self_check or args.host_snapshot:
            operation="host.snapshot" if args.host_snapshot else "core.self_check"
            assessment=service.create_assessment("Yerel Host/çekirdek kontrolü",["127.0.0.1/32"],"Yerel kullanıcı",
                "CLI yerel salt okunur kontrol: ağ taraması yok",allowed_operations={operation})
            task=service.submit_operation(assessment.id,operation,operation); service.wait_idle()
            completed=service.repository.get_task(task.id); _print(completed.model_dump(mode="json"))
            return 0 if completed.state.value=="succeeded" else 1
        from PySide6.QtCore import QTimer
        from PySide6.QtWidgets import QApplication
        from secram.ui.main_window import MainWindow
        app=QApplication([sys.argv[0]]); app.setApplicationName("SecRam-Pro")
        window=MainWindow(service); window.show()
        if args.smoke_test: QTimer.singleShot(300,app.quit)
        return app.exec()
    except (OSError,ValueError,RuntimeError,KeyError,TypeError) as exc:
        print(f"SecRam-Pro: {exc}",file=sys.stderr); return 1
    finally:
        if service is not None: service.close()


if __name__=="__main__":
    raise SystemExit(main())
