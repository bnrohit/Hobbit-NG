from src.core.baseline import finding_fingerprint


class AIEngine:
    """Deterministic finding correlation baseline.

    The class keeps the historical name for API compatibility. It does not claim
    ML behavior when no model is configured.
    """

    def __init__(self, config, logger):
        self.config, self.logger = config, logger

    def analyze_findings(self, findings):
        correlated = {}
        for finding in findings:
            item = dict(finding)
            item.setdefault("fingerprint", finding_fingerprint(item))
            correlated[item["fingerprint"]] = item
        return list(correlated.values())
