import os
import tempfile
from unittest.mock import patch

from devsecops_radar.core.remediation import (
    _TRACKED_FILES,
    apply_remediation,
    generate_fix_commands,
    generate_pr,
)


def test_apply_remediation_success():
    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.py') as f:
        f.write("line1\nline2\nline3\n")
        path = f.name
    finding = {"id": "TEST-1", "target": path, "line": 2}
    success = apply_remediation(finding, "new line2")
    os.unlink(path)
    assert success


def test_generate_fix_commands_requirements():
    findings = [{"tool": "Trivy", "id": "CVE-1", "target": "app/requirements.txt", "package": "flask"}]
    ai_summary = {"top_remediations": [{"finding_id": "CVE-1", "action": "Upgrade flask"}]}
    cmds = generate_fix_commands(findings, ai_summary)
    assert "pip install --upgrade flask" in cmds


def test_generate_pr_with_files(monkeypatch):
    _TRACKED_FILES.clear()
    _TRACKED_FILES.add("test.txt")
    with patch('subprocess.run') as mock_run:
        generate_pr("dummy")
        mock_run.assert_called()
    _TRACKED_FILES.clear()
