import json
from pathlib import Path

class ReportGenerator:
    def __init__(self,results,logger): self.results,self.logger=results,logger
    def generate(self,output_file,format_type="json"):
        if format_type!="json": raise ValueError("Baseline ReportGenerator supports JSON only")
        Path(output_file).write_text(json.dumps(self.results,indent=2,default=str),encoding="utf-8")
