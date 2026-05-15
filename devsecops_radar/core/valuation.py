def compute_fix_value(finding: dict, topology: dict = None) -> float:
    weights = {'CRITICAL': 100, 'HIGH': 70, 'MEDIUM': 40, 'LOW': 10}
    score = weights.get(finding.get('severity', 'LOW'), 10)
    if topology:
        target = finding.get('target', '')
        for server in topology.get('servers', []):
            if target in server.get('name', ''):
                score *= (1 + server.get('importance', 0.5))
                break
    return round(score, 2)