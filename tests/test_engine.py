import pytest
from src.core.engine import AIEnhancedEngine

def test_report_empty():
    e=AIEnhancedEngine("config/default.yaml",authorized=True)
    r=e._generate_final_report()
    assert r["summary"]["total_findings"]==0
    assert r["summary"]["risk_score"]==0

def test_scan_requires_authorization():
    e=AIEnhancedEngine("config/default.yaml",authorized=False)
    with pytest.raises(PermissionError):
        import asyncio
        asyncio.run(e.run_scan(["127.0.0.1"],["portscan"],"quick"))

def test_deep_port_parser_is_bounded():
    e=AIEnhancedEngine("config/default.yaml",authorized=True)
    ports=e._ports_for_depth("deep")
    assert 1 in ports and 1024 in ports
    assert all(1 <= p <= 65535 for p in ports)
