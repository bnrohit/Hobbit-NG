import asyncio
import ipaddress

class AsyncReconModule:
    def __init__(self, config, logger):
        self.config = config
        self.logger = logger

    async def discover_hosts(self, network_cidr):
        net = ipaddress.ip_network(network_cidr, strict=False)
        max_hosts = int(self.config.get("scanning", {}).get("max_hosts_per_target", 4096))
        count = max(0, net.num_addresses - (2 if net.version == 4 and net.prefixlen <= 30 else 0))
        if count > max_hosts:
            raise ValueError(f"Target expands to {count} hosts; configured limit is {max_hosts}")
        hosts = [str(ip) for ip in net.hosts()] if net.num_addresses > 1 else [str(net.network_address)]
        sem = asyncio.Semaphore(int(self.config.get("scanning", {}).get("max_hosts_parallel", 64)))
        results = await asyncio.gather(*(self._tcp_probe(ip, sem) for ip in hosts))
        return [ip for ip, alive in zip(hosts, results) if alive]

    async def _tcp_probe(self, ip, sem):
        async with sem:
            for port in (443,80,22,445):
                try:
                    _, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout=0.6)
                    writer.close(); await writer.wait_closed()
                    return True
                except (OSError, asyncio.TimeoutError):
                    pass
            return False
