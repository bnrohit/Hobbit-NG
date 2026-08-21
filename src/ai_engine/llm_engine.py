import os

class LLMEngine:
    def __init__(self, config, logger):
        llm=config.get("ai",{}).get("llm",{})
        self.api_key=os.getenv(llm.get("api_key_env","OPENAI_API_KEY"),"")
        self.model=llm.get("model","gpt-5-mini")
        self.logger=logger

    def generate_executive_summary(self, findings, risk_score):
        if not self.api_key: return "LLM not configured; set the configured API-key environment variable."
        return f"Automated LLM narrative is disabled in the baseline build. Findings: {len(findings)}; risk score: {risk_score:.1f}."
