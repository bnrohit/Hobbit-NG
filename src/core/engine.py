import asyncio
import ipaddress
import uuid
from datetime import datetime, timezone
from pathlib import Path
import yaml
from src.utils.logger import setup_logger
from src.modules.recon_async import AsyncReconModule
from src.modules.portscan_async import AsyncPortScanner
from src.modules.service_detect_async import AsyncServiceDetect
from src.modules.vulnscan import VulnScanModule
from src.modules.webscan import WebScanModule

class Severity:
    CRITICAL="critical"; HIGH="high"; MEDIUM="medium"; LOW="low"; INFO="info"

class AIEnhancedEngine:
    def __init__(self, config_path="config/default.yaml", authorized=False):
        self.config=self._load_config(config_path)
        self.authorized=authorized
        self.logger=setup_logger(self.config.get("logging",{}).get("level","INFO"))
        self.modules={}
        self.findings=[]
        self.hosts={}
        self.scan_metadata={"scan_id":str(uuid.uuid4()),"start_time":self._now(),"status":"initialized"}

    @staticmethod
    def _now(): return datetime.now(timezone.utc).isoformat()

    def _load_config(self,path):
        p=Path(path)
        if not p.exists(): return {}
        with p.open("r",encoding="utf-8") as f: return yaml.safe_load(f) or {}

    def register_module(self,name,module_class): self.modules[name]=module_class

    def _ports_for_depth(self,depth):
        scan=self.config.get("scanning",{})
        if depth=="quick": return scan.get("fast_ports",[22,80,443])
        if depth=="standard": return scan.get("top_ports",[22,80,443,445,3389])
        spec=str(scan.get("deep_ports","1-1024"))
        ports=[]
        for part in spec.split(','):
            part=part.strip()
            if '-' in part:
                a,b=map(int,part.split('-',1)); ports.extend(range(max(1,a),min(65535,b)+1))
            elif part: ports.append(int(part))
        return sorted(set(ports))

    async def _expand_target(self,target):
        try:
            net=ipaddress.ip_network(target, strict=False)
        except ValueError:
            return [target]
        if net.num_addresses==1: return [str(net.network_address)]
        recon=AsyncReconModule(self.config,self.logger)
        return await recon.discover_hosts(target)

    async def run_scan(self,targets,modules,depth="standard"):
        if not self.authorized:
            raise PermissionError("Active scanning requires explicit authorization acknowledgement")
        if not targets:
            raise ValueError("At least one target is required")
        self.scan_metadata["status"]="running"
        ports=self._ports_for_depth(depth)
        scanner=AsyncPortScanner(self.config,self.logger)
        detector=AsyncServiceDetect(self.config,self.logger)
        vuln=VulnScanModule(self.config,self.logger)
        web=WebScanModule(self.config,self.logger)
        hosts=[]
        for target in targets: hosts.extend(await self._expand_target(target))
        hosts=list(dict.fromkeys(hosts))
        for host in hosts:
            open_ports = await scanner.scan_host(host, ports) if "portscan" in modules else {}
            services = await detector.detect(host, open_ports) if "service_detect" in modules and open_ports else {}
            self.hosts[host]={"open_ports":open_ports,"services":services}
            if "vulnscan" in modules: self.findings.extend(vuln.scan(host,open_ports,services))
            if "webscan" in modules: self.findings.extend(await web.scan(host,open_ports))
        self.scan_metadata.update({"status":"completed","end_time":self._now(),"host_count":len(hosts)})
        return self._generate_final_report()

    def _generate_final_report(self):
        sev={s:0 for s in ["critical","high","medium","low","info"]}
        for f in self.findings: sev[f.get("severity","info")]=sev.get(f.get("severity","info"),0)+1
        weights={"critical":10,"high":6,"medium":3,"low":1,"info":0}
        weighted=sum(sev[k]*v for k,v in weights.items())
        risk=min(100.0,(weighted/max(1,len(self.findings)))*10)
        return {"scan_id":self.scan_metadata["scan_id"],"metadata":self.scan_metadata,"summary":{"total_findings":len(self.findings),"severity_breakdown":sev,"risk_score":risk},"findings":self.findings,"hosts":self.hosts,"attack_paths":[],"compliance":{},"ai_analysis":{}}
