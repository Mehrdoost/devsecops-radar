"""Tests for the attack simulation sandbox module."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import pytest

from devsecops_radar.core.attack_simulation import (
    SimulationArtifact,
    run_sandboxed_poc,
)


class TestRunSandboxedPoc:
    """Verify sandbox execution, path confinement, and error handling."""

    def test_script_not_found(self) -> None:
        """When the script file is missing, an error is returned as JSON."""
        artifact = SimulationArtifact(
            script_path=Path("/nonexistent"),
            temp_dir=Path("/tmp"),
            finding_id="1",
            finding_title="T",
            target="x",
        )
        result = run_sandboxed_poc(artifact)
        data = json.loads(result)
        assert "script file not found" in data["error"]

    def test_script_outside_temp_dir(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A script located outside the designated temp directory is rejected."""
        # Mock Docker availability so we can reach the path check
        monkeypatch.setattr(
            "devsecops_radar.core.attack_simulation._is_docker_available",
            lambda: True,
        )
        # Create a separate temp_dir inside tmp_path, and put the script outside it
        temp_dir = tmp_path / "sandbox"
        temp_dir.mkdir()
        outside_script = tmp_path / "outside.sh"
        outside_script.write_text("#!/bin/sh\necho 'bad'")
        outside_script.chmod(0o755)

        artifact = SimulationArtifact(
            script_path=outside_script,
            temp_dir=temp_dir,
            finding_id="1",
            finding_title="T",
            target="x",
        )
        result = run_sandboxed_poc(artifact)
        data = json.loads(result)
        assert "script location not allowed" in data["error"]

    def test_docker_not_available(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """If Docker is not installed, an appropriate error is returned."""
        monkeypatch.setattr(
            "devsecops_radar.core.attack_simulation._is_docker_available",
            lambda: False,
        )
        artifact = SimulationArtifact(
            script_path=Path("/fake/poc.sh"),
            temp_dir=Path("/fake"),
            finding_id="2",
            finding_title="Docker test",
            target="",
        )
        with patch("pathlib.Path.is_file", return_value=True), \
                patch("pathlib.Path.resolve", return_value=Path("/fake/poc.sh")), \
                patch("pathlib.Path.relative_to", return_value=Path("poc.sh")):
            result = run_sandboxed_poc(artifact)
        data = json.loads(result)
        assert "Docker is not installed or not running" in data["error"]
