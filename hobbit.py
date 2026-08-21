#!/usr/bin/env python3
import argparse
import asyncio
import html
import json
from datetime import datetime, timezone
from pathlib import Path

from src.ai_engine.ml_engine import AIEngine
from src.compliance.engine import ComplianceEngine
from src.core.baseline import compare_reports, load_report, save_report
from src.core.engine import AIEnhancedEngine
from src.core.support import maybe_prompt_support, support_info
from src.deception.engine import DeceptionEngine
from src.graph_analysis.analyzer import AttackGraphAnalyzer
from src.modules.portscan_async import AsyncPortScanner
from src.modules.purple_team import AdversarySimulation
from src.modules.recon_async import AsyncReconModule
from src.modules.service_detect_async import AsyncServiceDetect
from src.modules.vulnscan import VulnScanModule
from src.modules.webscan import WebScanModule
from src.modules.zero_trust import ZeroTrustAssessor
from src.remediation.engine import RemediationEngine
from src.supply_chain.scanner import SupplyChainScanner
from src.threat_intel.engine import ThreatIntelEngine

VERSION = "3.2.0"


def setup_modules(engine):
    classes = {
        "ai_engine": AIEngine,
        "threat_intel": ThreatIntelEngine,
        "graph_analysis": AttackGraphAnalyzer,
        "supply_chain": SupplyChainScanner,
        "deception": DeceptionEngine,
        "remediation": RemediationEngine,
        "compliance": ComplianceEngine,
        "purple_team": AdversarySimulation,
        "zero_trust": ZeroTrustAssessor,
        "recon": AsyncReconModule,
        "portscan": AsyncPortScanner,
        "service_detect": AsyncServiceDetect,
        "vulnscan": VulnScanModule,
        "webscan": WebScanModule,
    }
    for name, cls in classes.items():
        engine.register_module(name, cls)
    return engine


def parser():
    p = argparse.ArgumentParser(description="Hobbit-NG authorized security assessment framework")
    p.add_argument("-t", "--target", help="Comma-separated target hosts/CIDRs")
    p.add_argument("-c", "--config", default="config/default.yaml")
    p.add_argument("-m", "--modules", help="Comma-separated modules")
    p.add_argument("--full-scan", action="store_true")
    p.add_argument("--ack-authorized", action="store_true", help="Required for active network scanning; confirms you have permission")
    p.add_argument("--scan-depth", choices=["quick", "standard", "deep", "comprehensive"], default="standard")
    p.add_argument("-o", "--output", default="report.json")
    p.add_argument("-f", "--format", choices=["json", "html"], default="json")
    p.add_argument("--baseline", help="Compare this scan with a previous Hobbit-NG JSON report")
    p.add_argument("--save-baseline", help="Save the completed report as a future baseline")
    p.add_argument("--inventory-output", help="Write the generated asset inventory to a separate JSON file")
    p.add_argument("--fail-on-regression", action="store_true", help="Exit with code 2 if baseline comparison finds new hosts, ports, or findings")
    p.add_argument("--compare-reports", nargs=2, metavar=("BASELINE", "CURRENT"), help="Offline report comparison; performs no network activity")
    p.add_argument("--support", action="store_true", help="Show optional project-support information and configured Stripe donation link")
    p.add_argument("--no-support-prompt", action="store_true", help="Never show the optional post-scan support prompt")
    p.add_argument("--supply-chain", action="store_true")
    p.add_argument("--sbom")
    p.add_argument("--container-image")
    p.add_argument("--purple-team", action="store_true")
    p.add_argument("--chain", default="apt29")
    p.add_argument("--zero-trust", action="store_true")
    p.add_argument("--deception", choices=["deploy", "check", "cleanup"])
    p.add_argument("--environment", default="corporate")
    p.add_argument("--remediate", action="store_true")
    p.add_argument("--compliance")
    return p


def generate_html_report(report, path):
    rows = []
    for finding in report.get("findings", [])[:100]:
        rows.append(
            "<tr>"
            f"<td>{html.escape(str(finding.get('severity', '')))}</td>"
            f"<td>{html.escape(str(finding.get('title', '')))}</td>"
            f"<td>{html.escape(str(finding.get('host', '')))}</td>"
            f"<td>{html.escape(str(finding.get('port', '')))}</td>"
            "</tr>"
        )
    summary = report["summary"]
    drift = report.get("drift", {}).get("summary", {})
    drift_html = ""
    if drift:
        drift_html = (
            "<h2>Security Drift</h2>"
            f"<p>New findings: <b>{int(drift.get('new_findings', 0))}</b> &nbsp; "
            f"New hosts: <b>{int(drift.get('new_hosts', 0))}</b> &nbsp; "
            f"Hosts with port changes: <b>{int(drift.get('hosts_with_port_changes', 0))}</b> &nbsp; "
            f"Risk delta: <b>{float(drift.get('risk_score_delta', 0)):+.1f}</b></p>"
        )
    inventory = report.get("asset_inventory", {}).get("summary", {})
    doc = f"""<!doctype html><html><head><meta charset='utf-8'><title>Hobbit-NG Report</title>
<style>body{{font-family:system-ui;max-width:1100px;margin:40px auto;padding:0 20px}}table{{border-collapse:collapse;width:100%}}td,th{{padding:8px;border-bottom:1px solid #ddd;text-align:left}}.metric{{display:inline-block;margin-right:28px}}</style></head>
<body><h1>Hobbit-NG Security Assessment</h1><p>Authorized assessment report.</p>
<div class='metric'><b>{summary['total_findings']}</b><br>Total findings</div>
<div class='metric'><b>{summary['severity_breakdown']['high']}</b><br>High</div>
<div class='metric'><b>{summary['risk_score']:.1f}</b><br>Risk score</div>
<div class='metric'><b>{int(inventory.get('asset_count', 0))}</b><br>Assets</div>
<div class='metric'><b>{int(inventory.get('total_open_ports', 0))}</b><br>Open ports</div>
{drift_html}
<h2>Findings</h2><table><tr><th>Severity</th><th>Title</th><th>Host</th><th>Port</th></tr>{''.join(rows)}</table>
</body></html>"""
    Path(path).write_text(doc, encoding="utf-8")


def _write_json(data, path):
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")


def _print_support(config):
    info = support_info(config)
    print(info["message"])
    if info["configured"]:
        print(f"Stripe donation link: {info['donation_url']}")
    else:
        print(
            f"Donation link is not configured. Set {info['donation_url_env']} to a live Stripe Payment Link. "
            "All Hobbit-NG features remain free."
        )


def main():
    args = parser().parse_args()
    if args.compare_reports:
        baseline, current = (load_report(p) for p in args.compare_reports)
        drift = compare_reports(baseline, current)
        print(json.dumps(drift, indent=2, default=str))
        raise SystemExit(2 if args.fail_on_regression and drift["summary"]["security_regression"] else 0)

    engine = setup_modules(AIEnhancedEngine(args.config, authorized=args.ack_authorized))
    targets = [x.strip() for x in (args.target or "").split(",") if x.strip()]
    print(f"Hobbit-NG v{VERSION} | Scan ID {engine.scan_metadata['scan_id']} | {datetime.now(timezone.utc).isoformat()}")

    if args.support:
        _print_support(engine.config)
        return
    if args.supply_chain:
        scanner = SupplyChainScanner(engine.config, engine.logger)
        result = scanner.scan_sbom(args.sbom) if args.sbom else scanner.scan_container_image(args.container_image or "")
        print(json.dumps(result, indent=2))
        return
    if args.purple_team:
        if not targets:
            raise SystemExit("Purple-team planning requires --target")
        simulator = AdversarySimulation(engine.config, engine.logger)
        print(json.dumps([simulator.simulate_attack_chain(t, args.chain) for t in targets], indent=2))
        return
    if args.zero_trust:
        if not targets:
            raise SystemExit("Zero Trust assessment requires --target")
        print(json.dumps(ZeroTrustAssessor(engine.config, engine.logger).assess(targets), indent=2))
        return
    if args.deception:
        deception = DeceptionEngine(engine.config, engine.logger)
        out = (
            deception.deploy_honeypots(args.environment) + deception.deploy_honeytokens(args.environment)
            if args.deception == "deploy"
            else deception.check_alerts()
            if args.deception == "check"
            else deception.cleanup()
        )
        print(json.dumps(out, indent=2))
        return
    if not targets:
        raise SystemExit("Active scan requires --target")

    modules = (
        list(engine.modules)
        if args.full_scan
        else [m.strip() for m in args.modules.split(",")]
        if args.modules
        else ["recon", "portscan", "service_detect", "vulnscan", "webscan"]
    )
    active = [m for m in modules if m in {"recon", "portscan", "service_detect", "vulnscan", "webscan"}]
    report = asyncio.run(engine.run_scan(targets, active, args.scan_depth))

    if args.remediate:
        rem = RemediationEngine(engine.config, engine.logger)
        actions = rem.generate_remediation_plan(engine.findings)
        report["remediation_plan"] = rem.generate_remediation_report(actions, [])
    if args.compliance:
        comp = ComplianceEngine(engine.config, engine.logger)
        comp.frameworks = [args.compliance]
        report["compliance"] = comp.generate_audit_report(engine.findings)
    if args.baseline:
        report["drift"] = compare_reports(load_report(args.baseline), report)
    if args.inventory_output:
        _write_json(report["asset_inventory"], args.inventory_output)
    if args.format == "json":
        save_report(report, args.output)
    else:
        generate_html_report(report, args.output)
    if args.save_baseline:
        save_report(report, args.save_baseline)

    print(
        f"Scan complete: {args.output} | findings={report['summary']['total_findings']} | "
        f"risk={report['summary']['risk_score']:.1f}/100 | assets={report['summary']['host_count']}"
    )
    if report.get("drift"):
        drift = report["drift"]["summary"]
        print(
            f"Drift: new_findings={drift['new_findings']} | new_hosts={drift['new_hosts']} | "
            f"port_changes={drift['hosts_with_port_changes']} | risk_delta={drift['risk_score_delta']:+.1f}"
        )
        if args.fail_on_regression and drift["security_regression"]:
            raise SystemExit(2)

    maybe_prompt_support(engine.config, skip_prompt=args.no_support_prompt)


if __name__ == "__main__":
    main()
