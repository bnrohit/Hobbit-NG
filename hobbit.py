#!/usr/bin/env python3
import argparse
import asyncio
import html
import json
from datetime import datetime, timezone
from pathlib import Path
from src.core.engine import AIEnhancedEngine
from src.ai_engine.ml_engine import AIEngine
from src.threat_intel.engine import ThreatIntelEngine
from src.graph_analysis.analyzer import AttackGraphAnalyzer
from src.supply_chain.scanner import SupplyChainScanner
from src.deception.engine import DeceptionEngine
from src.remediation.engine import RemediationEngine
from src.compliance.engine import ComplianceEngine
from src.modules.purple_team import AdversarySimulation
from src.modules.zero_trust import ZeroTrustAssessor
from src.modules.recon_async import AsyncReconModule
from src.modules.portscan_async import AsyncPortScanner
from src.modules.service_detect_async import AsyncServiceDetect
from src.modules.vulnscan import VulnScanModule
from src.modules.webscan import WebScanModule

VERSION="3.0.0"

def setup_modules(engine):
    for name,cls in {"ai_engine":AIEngine,"threat_intel":ThreatIntelEngine,"graph_analysis":AttackGraphAnalyzer,"supply_chain":SupplyChainScanner,"deception":DeceptionEngine,"remediation":RemediationEngine,"compliance":ComplianceEngine,"purple_team":AdversarySimulation,"zero_trust":ZeroTrustAssessor,"recon":AsyncReconModule,"portscan":AsyncPortScanner,"service_detect":AsyncServiceDetect,"vulnscan":VulnScanModule,"webscan":WebScanModule}.items(): engine.register_module(name,cls)
    return engine

def parser():
    p=argparse.ArgumentParser(description="Hobbit-NG authorized security assessment framework")
    p.add_argument("-t","--target",help="Comma-separated target hosts/CIDRs")
    p.add_argument("-c","--config",default="config/default.yaml")
    p.add_argument("-m","--modules",help="Comma-separated modules")
    p.add_argument("--full-scan",action="store_true")
    p.add_argument("--ack-authorized",action="store_true",help="Required for active network scanning; confirms you have permission")
    p.add_argument("--scan-depth",choices=["quick","standard","deep","comprehensive"],default="standard")
    p.add_argument("-o","--output",default="report.json")
    p.add_argument("-f","--format",choices=["json","html"],default="json")
    p.add_argument("--supply-chain",action="store_true"); p.add_argument("--sbom"); p.add_argument("--container-image")
    p.add_argument("--purple-team",action="store_true"); p.add_argument("--chain",default="apt29")
    p.add_argument("--zero-trust",action="store_true")
    p.add_argument("--deception",choices=["deploy","check","cleanup"]); p.add_argument("--environment",default="corporate")
    p.add_argument("--remediate",action="store_true"); p.add_argument("--compliance")
    return p

def generate_html_report(report,path):
    rows=[]
    for f in report.get("findings",[])[:100]:
        rows.append(f"<tr><td>{html.escape(str(f.get('severity','')))}</td><td>{html.escape(str(f.get('title','')))}</td><td>{html.escape(str(f.get('host','')))}</td><td>{html.escape(str(f.get('port','')))}</td></tr>")
    s=report["summary"]
    doc=f"""<!doctype html><html><head><meta charset='utf-8'><title>Hobbit-NG Report</title><style>body{{font-family:system-ui;max-width:1100px;margin:40px auto;padding:0 20px}}table{{border-collapse:collapse;width:100%}}td,th{{padding:8px;border-bottom:1px solid #ddd;text-align:left}}.metric{{display:inline-block;margin-right:28px}}</style></head><body><h1>Hobbit-NG Security Assessment</h1><p>Authorized assessment report.</p><div class='metric'><b>{s['total_findings']}</b><br>Total findings</div><div class='metric'><b>{s['severity_breakdown']['high']}</b><br>High</div><div class='metric'><b>{s['risk_score']:.1f}</b><br>Risk score</div><h2>Findings</h2><table><tr><th>Severity</th><th>Title</th><th>Host</th><th>Port</th></tr>{''.join(rows)}</table></body></html>"""
    Path(path).write_text(doc,encoding="utf-8")

def main():
    args=parser().parse_args(); engine=setup_modules(AIEnhancedEngine(args.config,authorized=args.ack_authorized)); targets=[x.strip() for x in (args.target or "").split(',') if x.strip()]
    print(f"Hobbit-NG v{VERSION} | Scan ID {engine.scan_metadata['scan_id']} | {datetime.now(timezone.utc).isoformat()}")
    if args.supply_chain:
        sc=SupplyChainScanner(engine.config,engine.logger); result=sc.scan_sbom(args.sbom) if args.sbom else sc.scan_container_image(args.container_image or "")
        print(json.dumps(result,indent=2)); return
    if args.purple_team:
        if not targets: raise SystemExit("Purple-team planning requires --target")
        sim=AdversarySimulation(engine.config,engine.logger); print(json.dumps([sim.simulate_attack_chain(t,args.chain) for t in targets],indent=2)); return
    if args.zero_trust:
        if not targets: raise SystemExit("Zero Trust assessment requires --target")
        print(json.dumps(ZeroTrustAssessor(engine.config,engine.logger).assess(targets),indent=2)); return
    if args.deception:
        d=DeceptionEngine(engine.config,engine.logger)
        out=d.deploy_honeypots(args.environment)+d.deploy_honeytokens(args.environment) if args.deception=="deploy" else d.check_alerts() if args.deception=="check" else d.cleanup()
        print(json.dumps(out,indent=2)); return
    if not targets: raise SystemExit("Active scan requires --target")
    modules=list(engine.modules) if args.full_scan else ([m.strip() for m in args.modules.split(',')] if args.modules else ["recon","portscan","service_detect","vulnscan","webscan"] )
    active=[m for m in modules if m in {"recon","portscan","service_detect","vulnscan","webscan"}]
    report=asyncio.run(engine.run_scan(targets,active,args.scan_depth))
    if args.remediate:
        rem=RemediationEngine(engine.config,engine.logger); actions=rem.generate_remediation_plan(engine.findings); report["remediation_plan"]=rem.generate_remediation_report(actions,[])
    if args.compliance:
        comp=ComplianceEngine(engine.config,engine.logger); comp.frameworks=[args.compliance]; report["compliance"]=comp.generate_audit_report(engine.findings)
    if args.format=="json": Path(args.output).write_text(json.dumps(report,indent=2,default=str),encoding="utf-8")
    else: generate_html_report(report,args.output)
    print(f"Scan complete: {args.output} | findings={report['summary']['total_findings']} | risk={report['summary']['risk_score']:.1f}/100")

if __name__=="__main__": main()
