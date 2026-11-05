"""Only the application's owned loopback lab; no external target parameter."""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import resource
import shutil
import tempfile
import time

from secram.services.application import ApplicationService


def main():
    parser=argparse.ArgumentParser(description="Owned rootless Lab release evidence")
    parser.add_argument("--output",type=Path,default=Path("docs/release-evidence"))
    args=parser.parse_args(); args.output.mkdir(parents=True,exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="secram-release-") as temporary:
        app=ApplicationService(Path(temporary)/"data")
        try:
            lab=app.create_lab()
            if lab["status"]!="running": raise RuntimeError(lab.get("reason","Rootless lab unavailable"))
            assessment=app.create_assessment("Gerçek kontrollü release Lab",["127.0.0.1/32"],"Yerel Lab sahibi",
                "Only owned temporary rootless fixture",expires_hours=1,
                allowed_operations={"orchestrator.run","nmap.tcp_scan","web.http_headers","blue.monitor"},allowed_ports={lab["port"]})
            started=time.monotonic()
            task=app.submit_operation(assessment.id,"Release proof","orchestrator.run",target="127.0.0.1",
                params={"ports":[lab["port"]],"web_services":{str(lab["port"]):"http"}})
            app.wait_idle(90)
            duration=time.monotonic()-started
            finished=app.repository.get_task(task.id)
            if finished.state.value!="succeeded" or finished.result.get("status")!="complete":
                raise RuntimeError(f"Real workflow failed: {finished.error or finished.result}")
            children=[app.repository.get_task(identity) for identity in finished.result["child_task_ids"]]
            scan=next(c for c in children if c.operation=="nmap.tcp_scan")
            xml=scan.result.get("raw_xml")
            if isinstance(xml,str): (args.output/"nmap.xml").write_text(xml,encoding="utf-8")
            report=finished.result["report"]
            if report["unavailable_formats"]: raise RuntimeError("Report unavailable: "+str(report["unavailable_formats"]))
            pdf=Path(report["files"]["pdf"])
            if not pdf.read_bytes().startswith(b"%PDF"): raise RuntimeError("Invalid real PDF")
            shutil.copy2(pdf,args.output/"example-lab-report.pdf")
            events=app.list_events(assessment.id)
            if not any(e["source"]=="lab_sensor" and e["details"]["method"]=="HEAD" for e in events):
                raise RuntimeError("Actual lab HEAD telemetry was not observed")
            summary={"version":"0.4.0","real_network_interaction":True,"external_targets":False,
                "target":"127.0.0.1","port":lab["port"],"workflow_state":finished.state.value,
                "workflow_status":finished.result["status"],"duration_seconds":duration,
                "process_highwater_rss_kib":resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
                "resource_scope":"This Python process lifetime highwater; not children/host or per-operation peak",
                "operations":[{"operation":c.operation,"state":c.state.value} for c in children],
                "nmap_xml_sha256":scan.result.get("raw_xml_sha256"),"nmap_status":scan.result.get("scan_status"),
                "candidate_findings":len(app.list_findings(assessment.id)),"event_sources":dict(Counter(e["source"] for e in events)),
                "purple_metrics":finished.result["purple"]["metrics"],"report_formats":sorted(report["files"]),
                "report_hashes":report["hashes"],"example_pdf_sha256":hashlib.sha256(pdf.read_bytes()).hexdigest(),
                "lab_isolation":lab["isolation"],"production_ready":False,
                "budget":{"initial_planning_credits":3100,"minimum_reserve_credits":int(3100*0.20),"actual_used_credits":None}}
            (args.output/"validation-summary.json").write_text(json.dumps(summary,ensure_ascii=False,indent=2)+"\n",encoding="utf-8")
            print(json.dumps(summary,ensure_ascii=False,indent=2))
        finally: app.close()
    return 0


if __name__=="__main__": raise SystemExit(main())
