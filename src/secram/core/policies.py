"""Literal-IP scope gate. DNS, redirects and scanning are not Phase 1 features."""
from ipaddress import ip_address, ip_network

from secram.core.models import Assessment, Task, utcnow


class PolicyDenied(ValueError):
    pass


def literal_network_target(target: object):
    if not isinstance(target, str) or not target or target != target.strip() or "%" in target:
        raise PolicyDenied("One literal IP without whitespace or zone ID is required")
    try:
        address = ip_address(target)
    except ValueError as exc:
        raise PolicyDenied("Hostname, CIDR and ambiguous targets are not accepted") from exc
    if address.is_multicast or address.is_unspecified or str(address) == "255.255.255.255":
        raise PolicyDenied("Multicast, unspecified and limited-broadcast targets are forbidden")
    return address


class PolicyEngine:
    def check(self, assessment: Assessment, task: Task, *, target_required: bool) -> None:
        scope = assessment.scope
        now = utcnow()
        if task.assessment_id != assessment.id:
            raise PolicyDenied("Assessment identity mismatch")
        if not (scope.starts_at <= now < scope.expires_at):
            raise PolicyDenied("Authorization is not currently valid")
        if task.operation not in scope.allowed_operations:
            raise PolicyDenied("Operation is outside the authorized scope")
        if target_required and not task.target:
            raise PolicyDenied("A literal IP target is required")
        if task.target is not None:
            try:
                # IPv6 scope IDs and hostnames are deliberately unsupported here.
                if "%" in task.target or task.target != task.target.strip():
                    raise ValueError("Invalid literal target")
                address = ip_address(task.target)
            except ValueError as exc:
                raise PolicyDenied("Only unambiguous literal IP targets are accepted") from exc
            networks = [ip_network(cidr) for cidr in scope.cidrs]
            if not any(address.version == net.version and address in net for net in networks):
                raise PolicyDenied("Target is outside the authorized scope")
        if task.port is not None:
            if task.target is None:
                raise PolicyDenied("A port requires an explicit target")
            if task.port not in scope.allowed_ports:
                raise PolicyDenied("Port is outside the authorized scope")
