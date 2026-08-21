from src.core.inventory import build_asset_inventory


def test_inventory_prioritizes_exposed_assets():
    report = {
        "hosts": {
            "10.0.0.5": {
                "open_ports": {22: "open", 6379: "open"},
                "services": {22: {"service": "ssh"}, 6379: {"service": "redis"}},
            },
            "10.0.0.6": {"open_ports": {443: "open"}, "services": {443: {"service": "https"}}},
        },
        "findings": [
            {"host": "10.0.0.5", "severity": "medium", "title": "Redis service reachable"}
        ],
    }
    inventory = build_asset_inventory(report)
    assert inventory["summary"]["asset_count"] == 2
    assert inventory["summary"]["total_open_ports"] == 3
    assert inventory["assets"][0]["host"] == "10.0.0.5"
    assert "redis" in inventory["assets"][0]["sensitive_services"]
