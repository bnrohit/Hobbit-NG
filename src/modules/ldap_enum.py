class LDAPEnumModule:
    """Reserved for explicitly configured, read-only LDAP posture checks."""
    def __init__(self, config, logger): self.config, self.logger = config, logger
    def scan(self, host): return []
