from __future__ import annotations

import asyncio
import ipaddress
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

import yaml

from src.core.baseline import finding_fingerprint
from src.core.inventory import build_asset_inventory
from src.core.policy import TargetPolicy
from src.modules.portscan_async import AsyncPortScanner
from src.modules.recon_async import AsyncReconModule
from src.modules.service_detect_async import AsyncServiceDetect
from src.modules.vulnscan import VulnScanModule
from src.modules.webscan import WebScanModule
from src.utils.logger import setup_logger


class Severity:
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class AIEnhancedEngine:
    def __init__(self, config_path="config/default.yaml", authorized=False):
        self.config = self._load_config(config_path)
        self.authorized = authorized
        self.logger = setup_logger(self.config.get("logging", {}).get("level", "INFO"))
        self.modules = {}
        self.findings = []
        self.hosts = {}
        self.scan_errors = []
        self.scan_metadata = {
            "scan_id": str(uuid.uuid4()),
            "start_time": self._now(),
            "status": "initialized",
        }

    @staticmethod
    def _now():
        return datetime.now(timezone.utc).isoformat()

    def _load_config(self, path):
        p = Path(path)
        if not p.exists():
            return {}
        with p.open("r", encoding="utf-8") as handle:
            return yaml.safe_load(handle) or {}

    def register_module(self, name, module_class):
        self.modules[name] = module_class

    def _ports_for_depth(self, depth):
        scan = self.config.get("scanning", {})
        if depth == "quick":
            return scan.get("fast_ports", [22, 80, 443])
        if depth == "standard":
            return scan.get("top_ports", [22, 80, 443, 445, 3389])
        spec = str(scan.get("deep_ports", "1-1024"))
        ports = []
        for part in spec.split(","):
            part = part.strip()
            if "-" in part:
                a, b = map(int, part.split("-", 1))
                ports.extend(range(max(1, a), min(65535, b) + 1))
            elif part:
                ports.append(int(part))
        return sorted({p for p in ports if 1 <= p <= 65535})

    async def _expand_target(self, target):
        try:
            net = ipaddress.ip_network(target, strict=False)
        except ValueError:
            return [target]
        if net.num_addresses == 1:
            return [str(net.network_address)]
        recon = AsyncReconModule(self.config, self.logger)
        return await recon.discover_hosts(target)

    @staticmethod
    def _deduplicate_findings(findings):
        by_id = {}
        for finding in findings:
            item = dict(finding)
            item.setdefault("fingerprint", finding_fingerprint(item))
            by_id[item["fingerprint"]] = item
        return list(by_id.values())

    async def _scan_host(self, host, modules, ports, scanner, detector, vuln, web, host_sem):
        async with host_sem:
            try:
                open_ports = await scanner.scan_host(host, ports) if "portscan" in modules else {}
                services = (
                    await detector.detect(host, open_ports)
                    if "service_detect" in modules and open_ports
                    else {}
                )
                findings = []
                if "vulnscan" in modules:
                    findings.extend(vuln.scan(host, open_ports, services))
                if "webscan" in modules:
                    findings.extend(await web.scan(host, open_ports))
                return host, {"open_ports": open_ports, "services": services}, findings, None
            except Exception as exc:
                self.logger.warning("Host scan failed for %s: %s", host, exc)
                return host, {"open_ports": {}, "services": {}}, [], str(exc)

    async def run_scan(self, targets, modules, depth="standard"):
        if not self.authorized:
            raise PermissionError("Active scanning requires explicit authorization acknowledgement")
        if not targets:
            raise ValueError("At least one target is required")

        policy = TargetPolicy(self.config)
        for target in targets:
            policy.validate(target)

        started = time.monotonic()
        self.scan_metadata.update(
            {
                "status": "running",
                "targets": list(targets),
                "target_count": len(targets),
                "modules": list(modules),
                "scan_depth": depth,
            }
        )
        ports = self._ports_for_depth(depth)
        scanner = AsyncPortScanner(self.config, self.logger)
        detector = AsyncServiceDetect(self.config, self.logger)
        vuln = VulnScanModule(self.config, self.logger)
        web = WebScanModule(self.config, self.logger)

        expanded = await asyncio.gather(*(self._expand_target(target) for target in targets))
        hosts = list(dict.fromkeys(host for group in expanded for host in group))
        max_total = int(self.config.get("scanning", {}).get("max_total_hosts", 8192))
        if len(hosts) > max_total:
            raise ValueError(f"Scan expands to {len(hosts)} live/explicit hosts; configured total limit is {max_total}")

        host_sem = asyncio.Semaphore(
            max(1, int(self.config.get("scanning", {}).get("max_hosts_parallel", 64)))
        )
        results = await asyncio.gather(
            *(
                self._scan_host(host, modules, ports, scanner, detector, vuln, web, host_sem)
                for host in hosts
            )
        )

        all_findings = []
        self.hosts = {}
        self.scan_errors = []
        for host, host_data, findings, error in results:
            self.hosts[host] = host_data
            all_findings.extend(findings)
            if error:
                self.scan_errors.append({"host": host, "error": error})
        self.findings = self._deduplicate_findings(all_findings)

        self.scan_metadata.update(
            {
                "status": "completed",
                "end_time": self._now(),
                "duration_seconds": round(time.monotonic() - started, 3),
                "host_count": len(hosts),
                "error_count": len(self.scan_errors),
            }
        )
        return self._generate_final_report()

    def _generate_final_report(self):
        sev = {s: 0 for s in ["critical", "high", "medium", "low", "info"]}
        for finding in self.findings:
            key = str(finding.get("severity", "info")).lower()
            sev[key] = sev.get(key, 0) + 1
        weights = {"critical": 10, "high": 6, "medium": 3, "low": 1, "info": 0}
        weighted = sum(sev.get(k, 0) * value for k, value in weights.items())
        risk = min(100.0, (weighted / max(1, len(self.findings))) * 10)
        report = {
            "scan_id": self.scan_metadata["scan_id"],
            "metadata": self.scan_metadata,
            "summary": {
                "total_findings": len(self.findings),
                "severity_breakdown": sev,
                "risk_score": risk,
                "host_count": len(self.hosts),
                "error_count": len(self.scan_errors),
            },
            "findings": self.findings,
            "hosts": self.hosts,
            "scan_errors": self.scan_errors,
            "attack_paths": [],
            "compliance": {},
            "ai_analysis": {},
        }
        report["asset_inventory"] = build_asset_inventory(report)
        return report
