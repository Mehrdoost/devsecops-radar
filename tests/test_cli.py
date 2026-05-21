import os
import subprocess
import tempfile

import pytest


def test_cli_help():
    result = subprocess.run(['devsecops-radar', '--help'], capture_output=True, text=True)
    assert result.returncode == 0
    assert '--trivy' in result.stdout

def test_cli_wizard_flag():
    result = subprocess.run(['devsecops-radar', '--wizard'], capture_output=True, text=True)
    assert result.returncode == 0
    assert 'Quick Setup Wizard' in result.stdout or 'Welcome' in result.stdout

def test_cli_merge_sample_files():
    sample_dir = os.path.join(os.path.dirname(__file__), '..')
    trivy_sample = os.path.join(sample_dir, 'sample_trivy.json')
    semgrep_sample = os.path.join(sample_dir, 'sample_semgrep.json')
    if not os.path.exists(trivy_sample) or not os.path.exists(semgrep_sample):
        pytest.skip("Sample files not found")
    with tempfile.NamedTemporaryFile(suffix='.json', delete=False) as outfile:
        outpath = outfile.name
    result = subprocess.run(
        ['devsecops-radar', '--trivy', trivy_sample, '--semgrep', semgrep_sample, '--output', outpath],
        capture_output=True, text=True
    )
    assert result.returncode == 0
    # CLI logs to stderr, so check there
    assert 'Merged' in result.stderr
    os.unlink(outpath)
