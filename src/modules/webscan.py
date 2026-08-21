import asyncio
import ssl

class WebScanModule:
    def __init__(self, config, logger):
        self.config = config
        self.logger = logger

    async def scan(self, host, ports):
        findings=[]
        for port in ports:
            if port in {80,8080}:
                findings.append({"title":"Plain HTTP service reachable","severity":"low","host":host,"port":port,"module":"webscan","cvss_score":0.0,"remediation":"Prefer HTTPS for administrative or sensitive web applications."})
            elif port in {443,8443}:
                cert = await self._tls_certificate(host, port)
                if cert is None:
                    findings.append({"title":"TLS handshake could not be validated","severity":"low","host":host,"port":port,"module":"webscan","cvss_score":0.0,"remediation":"Review certificate chain, hostname, protocol, and cipher configuration."})
        return findings

    async def _tls_certificate(self, host, port):
        ctx=ssl.create_default_context()
        try:
            reader, writer = await asyncio.wait_for(asyncio.open_connection(host,port,ssl=ctx,server_hostname=host),timeout=3)
            cert=writer.get_extra_info("peercert")
            writer.close(); await writer.wait_closed()
            return cert
        except (OSError, ssl.SSLError, asyncio.TimeoutError):
            return None
