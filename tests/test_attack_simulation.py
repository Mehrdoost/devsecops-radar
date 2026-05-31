import os
from unittest.mock import MagicMock, patch

from devsecops_radar.core.attack_simulation import run_sandboxed_poc, simulate_attack


def test_simulate_attack_creates_script():
    finding = {"id": "CVE-2024-9999", "title": "Test vulnerability"}
    path = simulate_attack(finding)
    assert os.path.exists(path)
    with open(path) as f:
        content = f.read()
    assert "#!/bin/bash" in content
    assert "CVE-2024-9999" in content
    assert "Test vulnerability" in content
    # Check permissions (owner read/write/execute)
    stat = os.stat(path)
    assert stat.st_mode & 0o700 == 0o700
    os.unlink(path)


@patch('subprocess.run')
def test_run_sandboxed_poc_success(mock_run):
    mock_run.return_value = MagicMock(stdout="Simulation OK\n", stderr="")
    output = run_sandboxed_poc("/tmp/fake_poc.sh")
    assert "Simulation OK" in output


@patch('subprocess.run')
def test_run_sandboxed_poc_docker_missing(mock_run):
    mock_run.side_effect = FileNotFoundError()
    output = run_sandboxed_poc("/tmp/fake_poc.sh")
    assert "Docker is not installed" in output


@patch('subprocess.run')
def test_run_sandboxed_poc_timeout(mock_run):
    import subprocess
    mock_run.side_effect = subprocess.TimeoutExpired(cmd="docker", timeout=30)
    output = run_sandboxed_poc("/tmp/fake_poc.sh")
    assert "timed out" in output
