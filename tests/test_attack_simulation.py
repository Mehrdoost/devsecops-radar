"""Tests for attack simulation module (updated for SimulationArtifact & static script)."""

import subprocess
from contextlib import contextmanager
from unittest.mock import MagicMock, patch

import pytest
from loguru import logger

from devsecops_radar.core.attack_simulation import (
    SimulationArtifact,
    _is_docker_available,
    run_sandboxed_poc,
    simulate_attack,
)


# ---------------------------------------------------------------------------
# Helper to capture loguru output
# ---------------------------------------------------------------------------
@contextmanager
def capture_loguru(level: str = "TRACE"):
    messages: list[str] = []

    def sink(msg):
        messages.append(str(msg))

    handler_id = logger.add(sink, level=level, format="{message}")
    try:
        yield messages
    finally:
        logger.remove(handler_id)


# ---------------------------------------------------------------------------
# Tests for _is_docker_available
# ---------------------------------------------------------------------------
class TestIsDockerAvailable:
    def test_no_cli(self):
        with patch("shutil.which", return_value=None):
            assert _is_docker_available() is False

    def test_cli_exists_daemon_ok(self):
        with patch("shutil.which", return_value="/usr/bin/docker"), \
             patch("subprocess.run") as mock_run:
            mock_run.return_value.returncode = 0
            assert _is_docker_available() is True

    def test_cli_exists_daemon_unreachable(self):
        with patch("shutil.which", return_value="/usr/bin/docker"), \
             patch("subprocess.run", side_effect=subprocess.TimeoutExpired(cmd="docker", timeout=3)):
            assert _is_docker_available() is False


# ---------------------------------------------------------------------------
# Tests for simulate_attack
# ---------------------------------------------------------------------------
class TestSimulateAttack:
    def test_invalid_finding_none(self):
        with capture_loguru() as msgs:
            result = simulate_attack(None)
        assert result is None
        assert any("Invalid finding data" in m for m in msgs)

    def test_invalid_finding_missing_id(self):
        finding = {"title": "No ID"}
        with capture_loguru() as msgs:
            result = simulate_attack(finding)
        assert result is None
        assert any("Invalid finding data" in m for m in msgs)

    def test_invalid_finding_missing_title(self):
        finding = {"id": "F1"}
        with capture_loguru() as msgs:
            result = simulate_attack(finding)
        assert result is None
        assert any("Invalid finding data" in m for m in msgs)

    def test_valid_finding(self):
        finding = {"id": "VULN-123", "title": "Remote Code Execution"}
        result = simulate_attack(finding)
        assert isinstance(result, SimulationArtifact)
        assert result.finding_id == "VULN-123"
        assert result.finding_title == "Remote Code Execution"
        assert result.script_path.name == "poc.sh"
        assert result.script_path.exists()
        content = result.script_path.read_text()
        assert "#!/bin/bash" in content
        # Clean up
        import shutil
        shutil.rmtree(result.temp_dir)

    def test_creates_unique_temp_dirs(self):
        finding = {"id": "F1", "title": "T"}
        a1 = simulate_attack(finding)
        a2 = simulate_attack(finding)
        assert a1.temp_dir != a2.temp_dir
        import shutil
        shutil.rmtree(a1.temp_dir)
        shutil.rmtree(a2.temp_dir)

    def test_script_creation_failure(self):
        finding = {"id": "F1", "title": "Issue"}
        with patch("tempfile.mkdtemp", side_effect=OSError("No space left")):
            result = simulate_attack(finding)
        assert result is None


# ---------------------------------------------------------------------------
# Tests for run_sandboxed_poc
# ---------------------------------------------------------------------------
class TestRunSandboxedPoc:
    @pytest.fixture
    def artifact(self, tmp_path):
        """Create a minimal artifact with a dummy script inside a temp dir."""
        temp_dir = tmp_path / "sim_temp"
        temp_dir.mkdir()
        script = temp_dir / "poc.sh"
        script.write_text("#!/bin/bash\necho 'hello'\n")
        script.chmod(0o755)
        return SimulationArtifact(
            script_path=script,
            temp_dir=temp_dir,
            finding_id="F1",
            finding_title="Test",
            target="127.0.0.1",
        )

    def test_script_not_found(self, artifact):
        artifact.script_path.unlink()
        output = run_sandboxed_poc(artifact)
        assert "script file not found" in output.lower()

    def test_script_outside_temp_dir(self, tmp_path):
        # Create an artifact with script outside the declared temp_dir
        bad_temp = tmp_path / "bad_temp"
        bad_temp.mkdir()
        script = bad_temp / "poc.sh"
        script.write_text("#!/bin/bash\necho bad\n")
        script.chmod(0o755)
        artifact = SimulationArtifact(
            script_path=script,
            temp_dir=tmp_path / "other_temp",  # different dir
            finding_id="F1",
            finding_title="Test",
            target="",
        )
        output = run_sandboxed_poc(artifact)
        assert "script location not allowed" in output.lower()

    def test_docker_not_available(self, artifact):
        with patch(
            "devsecops_radar.core.attack_simulation._is_docker_available",
            return_value=False,
        ):
            output = run_sandboxed_poc(artifact)
        assert "Docker is not available" in output

    @patch("subprocess.run")
    def test_successful_run(self, mock_run, artifact):
        mock_run.return_value = MagicMock(returncode=0, stdout="OK\n", stderr="")
        with patch(
            "devsecops_radar.core.attack_simulation._is_docker_available",
            return_value=True,
        ):
            output = run_sandboxed_poc(artifact)
        assert output == "OK"
        mock_run.assert_called_once()
        # Verify temp dir is cleaned up
        assert not artifact.temp_dir.exists()

    @patch("subprocess.run")
    def test_docker_run_timeout(self, mock_run, artifact):
        mock_run.side_effect = subprocess.TimeoutExpired(cmd="docker", timeout=30)
        with patch(
            "devsecops_radar.core.attack_simulation._is_docker_available",
            return_value=True,
        ):
            output = run_sandboxed_poc(artifact)
        assert "timed out" in output.lower()

    @patch("subprocess.run")
    def test_docker_run_nonzero_exit(self, mock_run, artifact):
        mock_run.return_value = MagicMock(returncode=1, stdout="", stderr="error")
        with patch(
            "devsecops_radar.core.attack_simulation._is_docker_available",
            return_value=True,
        ), capture_loguru() as msgs:
            output = run_sandboxed_poc(artifact)
        assert "failed (exit 1)" in output
        assert "error" in output
        assert any("exited with code" in m for m in msgs)

    @patch("subprocess.run")
    def test_docker_not_installed_during_run(self, mock_run, artifact):
        mock_run.side_effect = FileNotFoundError
        with patch(
            "devsecops_radar.core.attack_simulation._is_docker_available",
            return_value=True,
        ):
            output = run_sandboxed_poc(artifact)
        assert "Docker is not installed" in output

    @patch("subprocess.run")
    def test_unexpected_error(self, mock_run, artifact):
        mock_run.side_effect = Exception("Unknown")
        with patch(
            "devsecops_radar.core.attack_simulation._is_docker_available",
            return_value=True,
        ):
            output = run_sandboxed_poc(artifact)
        assert "Sandbox execution failed" in output
        assert "Unknown" in output
