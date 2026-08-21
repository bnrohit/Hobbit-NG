class VulnScanModule:
    def __init__(self, config, logger):
        self.config = config
        self.logger = logger

    def scan(self, host, open_ports, services=None):
        findings = []
        rules = {
            23: ("Telnet service exposed", "medium", "Use SSH or another encrypted management protocol."),
            21: ("FTP service exposed", "low", "Prefer SFTP/FTPS and disable plaintext authentication where possible."),
            445: ("SMB service reachable", "info", "Confirm SMB exposure is intended and restrict it to required network zones."),
            3389: ("RDP service reachable", "info", "Restrict RDP to management paths and require MFA/NLA where supported."),
            6379: ("Redis service reachable", "medium", "Restrict Redis to trusted application networks and require supported authentication/TLS controls."),
            9200: ("Elasticsearch service reachable", "medium", "Restrict Elasticsearch to trusted management/application networks and enforce authentication/TLS."),
            27017: ("MongoDB service reachable", "medium", "Restrict MongoDB to trusted application networks and enforce authentication/TLS."),
        }
        for port in open_ports:
            if port in rules:
                title, severity, remediation = rules[port]
                findings.append({
                    "title": title,
                    "severity": severity,
                    "host": host,
                    "port": port,
                    "module": "vulnscan",
                    "cvss_score": 0.0,
                    "confidence": "high",
                    "evidence": f"TCP/{port} accepted a connection during the authorized exposure check.",
                    "remediation": remediation,
                })
        return findings
