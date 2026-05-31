from devsecops_radar.core.valuation import compute_dynamic_risk_score


def test_risk_score_critical_exposed():
    finding = {"severity": "CRITICAL", "id": "1", "target": "web-server"}
    topology = {"servers": [{"name": "web-server", "exposed": True, "data_classification": "sensitive"}]}
    score = compute_dynamic_risk_score(finding, topology)
    assert score >= 7.0


def test_risk_score_low_no_topo():
    finding = {"severity": "LOW", "id": "1"}
    score = compute_dynamic_risk_score(finding)
    assert score == 1.0
