"""Asset inventory generation from scan results."""
from __future__ import annotations

from collections import Counter
from typing import Any, Dict

SEVERITY_WEIGHT = {"critical": 10, "high": 6, "medium": 3, "low": 1, "info": 0}
SENSITIVE_SERVICES = {"telnet", "ftp", "smb", "rdp", "redis", "mongodb", "elasticsearch"}


def build_asset_inventory(report: Dict[str, Any]) -> Dict[str, Any]:
    hosts = report.get("hosts", {}) or {}
    findings = report.get("findings", []) or []
    by_host: Dict[str, list] = {}
    for finding in findings:
        by_host.setdefault(str(finding.get("host", "unknown")), []).append(finding)

    assets = []
    service_totals: Counter[str] = Counter()
    for host, data in sorted(hosts.items()):
        open_ports_raw = data.get("open_ports", {}) or {}
        port_values = open_ports_raw.keys() if isinstance(open_ports_raw, dict) else open_ports_raw
        open_ports = sorted({int(p) for p in port_values})
        services_raw = data.get("services", {}) or {}
        services = []
        for port, detail in services_raw.items():
            name = str((detail or {}).get("service", "unknown"))
            services.append({"port": int(port), "service": name})
            service_totals[name] += 1
        host_findings = by_host.get(host, [])
        severities = Counter(str(f.get("severity", "info")).lower() for f in host_findings)
        finding_risk = sum(SEVERITY_WEIGHT.get(str(f.get("severity", "info")).lower(), 0) for f in host_findings)
        sensitive = sorted({s["service"] for s in services if s["service"] in SENSITIVE_SERVICES})
        exposure_score = min(100, finding_risk * 5 + len(open_ports) * 2 + len(sensitive) * 8)
        assets.append({
            "host": host,
            "open_ports": open_ports,
            "services": services,
            "finding_count": len(host_findings),
            "severity_breakdown": dict(severities),
            "sensitive_services": sensitive,
            "exposure_score": exposure_score,
        })

    return {
        "summary": {
            "asset_count": len(assets),
            "total_open_ports": sum(len(a["open_ports"]) for a in assets),
            "assets_with_findings": sum(1 for a in assets if a["finding_count"]),
            "assets_with_sensitive_services": sum(1 for a in assets if a["sensitive_services"]),
            "service_counts": dict(service_totals.most_common()),
        },
        "assets": sorted(assets, key=lambda a: (-a["exposure_score"], a["host"])),
    }
