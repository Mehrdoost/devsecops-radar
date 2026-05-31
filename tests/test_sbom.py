import json
import os
import tempfile

from devsecops_radar.core.sbom import apply_vex_filter, detect_dependency_confusion


def test_dependency_confusion():
    with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
        f.write("mycompany-util==1.0")
        path = f.name
    findings = detect_dependency_confusion(path, internal_prefixes=['mycompany-'])
    os.unlink(path)
    assert len(findings) == 1


def test_vex_filter():
    findings = [{"id": "CVE-1"}, {"id": "CVE-2"}]
    vex = {"vulnerabilities": [{"id": "CVE-1", "analysis": {"state": "not_affected"}}]}
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        json.dump(vex, f)
        path = f.name
    filtered = apply_vex_filter(findings, path)
    os.unlink(path)
    assert len(filtered) == 1
    assert filtered[0]["id"] == "CVE-2"
