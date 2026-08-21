from src.core.baseline import compare_reports, finding_fingerprint


def _report(hosts, findings, risk=0):
    return {
        "summary": {"risk_score": risk},
        "hosts": hosts,
        "findings": findings,
    }


def test_fingerprint_is_stable():
    finding = {"host": "10.0.0.5", "port": 23, "module": "vulnscan", "title": "Telnet service exposed"}
    assert finding_fingerprint(finding) == finding_fingerprint(dict(finding))


def test_compare_reports_detects_security_drift():
    baseline = _report(
        {"10.0.0.5": {"open_ports": {22: "open"}}},
        [],
        risk=0,
    )
    current = _report(
        {
            "10.0.0.5": {"open_ports": {22: "open", 23: "open"}},
            "10.0.0.6": {"open_ports": {443: "open"}},
        },
        [{"host": "10.0.0.5", "port": 23, "module": "vulnscan", "title": "Telnet service exposed", "severity": "medium"}],
        risk=30,
    )
    drift = compare_reports(baseline, current)
    assert drift["summary"]["security_regression"] is True
    assert drift["summary"]["new_findings"] == 1
    assert drift["summary"]["new_hosts"] == 1
    assert drift["port_changes"][0]["opened"] == [23]
    assert drift["summary"]["risk_score_delta"] == 30


def test_compare_reports_tracks_resolved_findings():
    finding = {"host": "10.0.0.5", "port": 23, "module": "vulnscan", "title": "Telnet service exposed", "severity": "medium"}
    drift = compare_reports(_report({}, [finding], 20), _report({}, [], 0))
    assert drift["summary"]["resolved_findings"] == 1
    assert drift["summary"]["security_regression"] is False
