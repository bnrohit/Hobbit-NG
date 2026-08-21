class AIEngine:
    def __init__(self, config, logger): self.config, self.logger = config, logger
    def analyze_findings(self, findings):
        seen=set(); out=[]
        for f in findings:
            key=(f.get("host"),f.get("port"),f.get("title"))
            if key not in seen: seen.add(key); out.append(f)
        return out
