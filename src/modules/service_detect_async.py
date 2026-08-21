import asyncio

class AsyncServiceDetect:
    PORT_MAP = {21:"ftp",22:"ssh",23:"telnet",25:"smtp",53:"dns",80:"http",110:"pop3",143:"imap",443:"https",445:"smb",3306:"mysql",3389:"rdp",5432:"postgresql",6379:"redis",8080:"http-alt",8443:"https-alt",9200:"elasticsearch",27017:"mongodb"}

    def __init__(self, config, logger):
        self.config = config
        self.logger = logger
        self.semaphore = asyncio.Semaphore(int(config.get("scanning", {}).get("max_concurrent_tasks", 256)))

    async def detect(self, host, open_ports):
        ports = list(open_ports)
        banners = await asyncio.gather(*(self._grab_banner(host, p) for p in ports))
        return {p: {"service": self.PORT_MAP.get(p, "unknown"), "banner": b or ""} for p,b in zip(ports,banners)}

    async def _grab_banner(self, host, port):
        async with self.semaphore:
            try:
                reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=2)
                if port in {21,22,23,25,110,143}:
                    data = await asyncio.wait_for(reader.read(512), timeout=1)
                else:
                    data = b""
                writer.close(); await writer.wait_closed()
                return data.decode("utf-8", errors="ignore").strip()[:512]
            except (OSError, asyncio.TimeoutError):
                return ""
