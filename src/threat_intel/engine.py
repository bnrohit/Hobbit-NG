class ThreatIntelEngine:
    def __init__(self, config, logger): self.config,self.logger=config,logger
    def lookup_ioc(self,ioc): return {"ioc":ioc,"reputation":"unknown","status":"provider-not-configured"}
