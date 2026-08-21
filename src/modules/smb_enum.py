class SMBEnumModule:
    """Reserved for explicitly configured, read-only SMB posture checks."""
    def __init__(self, config, logger): self.config, self.logger = config, logger
    def scan(self, host): return []
