"""Baseline and drift analysis for Hobbit-NG reports.

This module is intentionally passive: it compares already-collected reports and
never performs network activity.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Dict, Iterable

SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def finding_fingerprint(finding: Dict[str, Any]) -> str:
    """Return a stable identifier for a finding across scans."""
    parts = (
        str(finding.get("host", "")).strip().lower(),
        str(finding.get("port", "")).strip(),
        str(finding.get("module", "")).strip().lower(),
        str(finding.get("title", "")).strip().lower(),
    )
    raw = "|".join(parts).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()[:20]


def _finding_map(findings: Iterable[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    result: Dict[str, Dict[str, Any]] = {}
    for finding in findings or []:
        copy = dict(finding)
        copy.setdefault("fingerprint", finding_fingerprint(copy))
        result[copy["fingerprint"]] = copy
    return result


def _ports(host_data: Dict[str, Any]) -> set[int]:
    raw = host_data.get("open_ports", {}) if host_data else {}
    values = raw.keys() if isinstance(raw, dict) else raw
    out: set[int] = set()
    for value in values or []:
        try:
            out.add(int(value))
        except (TypeError, ValueError):
            continue
    return out


def compare_reports(baseline: Dict[str, Any], current: Dict[str, Any]) -> Dict[str, Any]:
    """Compare two Hobbit-NG reports and return actionable security drift."""
    base_findings = _finding_map(baseline.get("findings", []))
    cur_findings = _finding_map(current.get("findings", []))

    new_ids = sorted(set(cur_findings) - set(base_findings))
    resolved_ids = sorted(set(base_findings) - set(cur_findings))
    persistent_ids = sorted(set(cur_findings) & set(base_findings))

    base_hosts = baseline.get("hosts", {}) or {}
    cur_hosts = current.get("hosts", {}) or {}
    new_hosts = sorted(set(cur_hosts) - set(base_hosts))
    removed_hosts = sorted(set(base_hosts) - set(cur_hosts))

    port_changes = []
    for host in sorted(set(base_hosts) | set(cur_hosts)):
        before, after = _ports(base_hosts.get(host, {})), _ports(cur_hosts.get(host, {}))
        opened, closed = sorted(after - before), sorted(before - after)
        if opened or closed:
            port_changes.append({"host": host, "opened": opened, "closed": closed})

    base_risk = float((baseline.get("summary") or {}).get("risk_score", 0) or 0)
    cur_risk = float((current.get("summary") or {}).get("risk_score", 0) or 0)
    new_findings = [cur_findings[i] for i in new_ids]
    highest_new = max(
        (SEVERITY_ORDER.get(str(f.get("severity", "info")).lower(), 0) for f in new_findings),
        default=0,
    )
    high_or_critical = sum(
        1 for f in new_findings if str(f.get("severity", "info")).lower() in {"high", "critical"}
    )

    return {
        "summary": {
            "new_findings": len(new_ids),
            "resolved_findings": len(resolved_ids),
            "persistent_findings": len(persistent_ids),
            "new_hosts": len(new_hosts),
            "removed_hosts": len(removed_hosts),
            "hosts_with_port_changes": len(port_changes),
            "new_high_or_critical": high_or_critical,
            "highest_new_severity": next((k for k, v in SEVERITY_ORDER.items() if v == highest_new), "info"),
            "risk_score_before": base_risk,
            "risk_score_after": cur_risk,
            "risk_score_delta": round(cur_risk - base_risk, 2),
            "security_regression": bool(new_ids or new_hosts or any(p["opened"] for p in port_changes)),
        },
        "new_findings": new_findings,
        "resolved_findings": [base_findings[i] for i in resolved_ids],
        "new_hosts": new_hosts,
        "removed_hosts": removed_hosts,
        "port_changes": port_changes,
    }


def load_report(path: str | Path) -> Dict[str, Any]:
    with Path(path).open("r", encoding="utf-8") as handle:
        data = json.load(handle)
    if not isinstance(data, dict):
        raise ValueError("Report must be a JSON object")
    return data


def save_report(report: Dict[str, Any], path: str | Path) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(report, indent=2, default=str), encoding="utf-8")
