"""Target scope policy for authorized assessment jobs."""
from __future__ import annotations

import fnmatch
import ipaddress
from typing import Any, Dict, Iterable


class TargetPolicy:
    def __init__(self, config: Dict[str, Any]):
        policy = (config or {}).get("target_policy", {}) or {}
        self.enforce_allowlist = bool(policy.get("enforce_allowlist", False))
        self.allowed_networks = self._networks(policy.get("allowed_networks", []))
        self.denied_networks = self._networks(policy.get("denied_networks", []))
        self.allowed_hostnames = [str(x).lower() for x in policy.get("allowed_hostnames", [])]
        self.denied_hostnames = [str(x).lower() for x in policy.get("denied_hostnames", [])]

    @staticmethod
    def _networks(values: Iterable[str]):
        result = []
        for value in values or []:
            result.append(ipaddress.ip_network(str(value), strict=False))
        return result

    @staticmethod
    def _matches_hostname(hostname: str, patterns: Iterable[str]) -> bool:
        name = hostname.rstrip(".").lower()
        return any(fnmatch.fnmatchcase(name, pattern.rstrip(".").lower()) for pattern in patterns)

    @staticmethod
    def _network_within(candidate, configured) -> bool:
        return candidate.version == configured.version and candidate.subnet_of(configured)

    def validate(self, target: str) -> None:
        """Raise ValueError if target violates configured scope policy."""
        try:
            candidate = ipaddress.ip_network(target, strict=False)
        except ValueError:
            if self._matches_hostname(target, self.denied_hostnames):
                raise ValueError(f"Target {target!r} is denied by target_policy")
            if self.enforce_allowlist and not self._matches_hostname(target, self.allowed_hostnames):
                raise ValueError(f"Target {target!r} is not in target_policy allowlist")
            return

        if any(self._network_within(candidate, denied) for denied in self.denied_networks):
            raise ValueError(f"Target {target!r} is denied by target_policy")
        if self.enforce_allowlist and not any(
            self._network_within(candidate, allowed) for allowed in self.allowed_networks
        ):
            raise ValueError(f"Target {target!r} is not in target_policy allowlist")
