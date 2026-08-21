import asyncio

class AsyncPortScanner:
    def __init__(self, config, logger):
        self.config = config
        self.logger = logger
        limit = int(config.get("scanning", {}).get("max_concurrent_tasks", 256))
        self.semaphore = asyncio.Semaphore(max(1, min(limit, 1024)))

    async def scan_host(self, host, ports):
        ports = [int(p) for p in ports if 1 <= int(p) <= 65535]
        results = await asyncio.gather(*(self._scan_port(host, p) for p in ports))
        return {p: "open" for p, is_open in zip(ports, results) if is_open}

    async def _scan_port(self, host, port):
        timeout = float(self.config.get("scanning", {}).get("timeout", 2))
        async with self.semaphore:
            try:
                _, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=timeout)
                writer.close()
                await writer.wait_closed()
                return True
            except (OSError, asyncio.TimeoutError):
                return False
