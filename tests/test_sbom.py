import json
import os
import tempfile
from unittest.mock import patch

from devsecops_radar.core.sbom import apply_vex_filter, detect_dependency_confusion, generate_sbom


@patch('subprocess.run')
def test_generate_sbom_success(mock_run):
    def side_effect(cmd, *args, **kwargs):
        if '--output' in cmd:
            idx = cmd.index('--output')
            output_file = cmd[idx+1]
            with open(output_file, 'w') as f:
                json.dump({"bomFormat": "CycloneDX", "components": []}, f)
    mock_run.side_effect = side_effect
    sbom = generate_sbom("/fake")
    assert sbom is not None
    assert sbom["bomFormat"] == "CycloneDX"

@patch('subprocess.run', side_effect=Exception("syft not installed"))
def test_generate_sbom_failure(mock_run):
    sbom = generate_sbom("/fake")
    assert sbom is None

def test_detect_dependency_confusion_package_json():
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        f.write('{"mycompany-internal": "1.0", "lodash": "4.0"}')
        path = f.name
    findings = detect_dependency_confusion(path, internal_prefixes=["mycompany-"])
    assert len(findings) == 1
    assert findings[0]["risk"] == "Potential dependency confusion"
    os.unlink(path)

def test_detect_dependency_confusion_requirements():
    with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
        f.write("mycompany-util==1.0\nrequests==2.28")
        path = f.name
    findings = detect_dependency_confusion(path, internal_prefixes=["mycompany-"])
    assert len(findings) == 1
    os.unlink(path)

def test_apply_vex_filter_no_file():
    findings = [{"id": "CVE-123"}]
    result = apply_vex_filter(findings, "/nonexistent")
    assert result == findings

def test_apply_vex_filter_excludes():
    vex_data = {
        "vulnerabilities": [
            {"id": "CVE-123", "analysis": {"state": "not_affected"}},
            {"id": "CVE-456", "analysis": {"state": "false_positive"}}
        ]
    }
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        json.dump(vex_data, f)
        vex_path = f.name
    findings = [
        {"id": "CVE-123", "title": "First"},
        {"id": "CVE-789", "title": "Second"},
        {"id": "CVE-456", "title": "Third"}
    ]
    result = apply_vex_filter(findings, vex_path)
    os.unlink(vex_path)
    assert len(result) == 1
    assert result[0]["id"] == "CVE-789"
