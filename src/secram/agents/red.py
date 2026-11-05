"""Deterministic safe Red planning, not an LLM or unrestricted attack agent."""
from secram.core.policies import literal_network_target


class RedAgent:
    @staticmethod
    def validate(task, assessment):
        literal_network_target(task.target)
        if task.port is not None or set(task.params) - {"ports", "web_services"}:
            raise ValueError("Autonomous profile accepts only ports and explicit web service hints")
        ports = task.params.get("ports")
        if not isinstance(ports, list) or not 1 <= len(ports) <= 32 or len(ports) != len(set(ports)):
            raise ValueError("Provide 1–32 unique literal TCP ports")
        if any(type(p) is not int or p not in assessment.scope.allowed_ports for p in ports):
            raise ValueError("Every port must be explicitly authorized")
        if "nmap.tcp_scan" not in assessment.scope.allowed_operations:
            raise ValueError("Autonomous network assessment requires separate Nmap authorization")
        hints = task.params.get("web_services", {})
        if not isinstance(hints, dict) or any(not isinstance(p, str) or not p.isascii() or not p.isdigit()
            or int(p) not in ports or value not in {"http", "https", "tls"} for p, value in hints.items()):
            raise ValueError("Web hints must map requested decimal ports to http/https/tls")

    @staticmethod
    def next_steps(target, scan_result, operations, hints):
        actions, decisions = [], []
        if scan_result.get("scan_status") != "complete":
            return [], [{"reason": "Nmap result inconclusive: no automatic follow-up"}]
        open_ports = sorted({p["port"] for h in scan_result.get("hosts", []) for p in h.get("ports", [])
                             if p.get("state") == "open" and p.get("protocol") == "tcp"})
        for port in open_ports[:8]:
            scheme = hints.get(str(port))
            reason = "explicit protocol hint" if scheme else "standard-port heuristic, not verified service identity"
            if scheme is None:
                scheme = "http" if port in {80, 8000, 8080, 8888} else "https" if port in {443, 8443} else None
            if scheme in {"http", "https"} and "web.http_headers" in operations:
                actions.append({"operation": "web.http_headers", "target": target, "port": port,
                                "params": {"scheme": scheme}})
            if scheme in {"https", "tls"} and "web.tls_check" in operations:
                actions.append({"operation": "web.tls_check", "target": target, "port": port, "params": {}})
            decisions.append({"port": port, "protocol_hint": scheme, "reason": reason if scheme else "unknown service: no blind HTTP/TLS probe"})
        if len(open_ports) > 8:
            decisions.append({"reason": "Follow-up limited to first eight open ports; remaining ports require another explicit assessment"})
        if not open_ports:
            decisions.append({"reason": "No open port observation; unnecessary web checks skipped"})
        return actions, decisions
