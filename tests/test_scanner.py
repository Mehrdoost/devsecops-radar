"""Tests for the CLI scanner entry point."""

import argparse
import os
import subprocess
import sys
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

# Set required environment variables before importing the module
os.environ["JWT_SECRET"] = "a" * 32
os.environ["PIPELINE_API_KEY"] = "valid-api-key"


# ============================================================================
# Fake psutil module to avoid real hardware queries
# ============================================================================
class FakeVirtualMemory:
    def __init__(self, total_bytes):
        self.total = total_bytes


class FakePsutil:
    @staticmethod
    def virtual_memory():
        return FakeVirtualMemory(16 * 1024**3)

    @staticmethod
    def cpu_count(logical=True):
        return 8


# ============================================================================
# Mock all heavy dependencies BEFORE importing the scanner module
# ============================================================================
with patch.dict("sys.modules", {
    "psutil": FakePsutil,
    "loguru": MagicMock(),
    "devsecops_radar.core.analyzer": MagicMock(),
    "devsecops_radar.core.database": MagicMock(),
    "devsecops_radar.core.remediation": MagicMock(),
    "devsecops_radar.core.reporting": MagicMock(),
    "devsecops_radar.core.rule_fusion": MagicMock(),
    "devsecops_radar.core.valuation": MagicMock(),
    "devsecops_radar.scanners.adapter": MagicMock(),
}):
    import devsecops_radar.cli.scanner as scanner_module
    from devsecops_radar.cli.scanner import (
        estimate_analysis,
        execute_ai_analysis,
        get_gpu_status,
        get_system_ram_gb,
        interactive_remediation,
        parse_args,
        run_all_scanners,
        safe_wizard,
        sort_findings_by_risk,
    )


# ============================================================================
# Tests
# ============================================================================
class TestGetSystemRamGb:
    def test_success(self, monkeypatch):
        monkeypatch.setattr(
            FakePsutil, "virtual_memory", lambda: FakeVirtualMemory(8 * 1024**3)
        )
        assert get_system_ram_gb() == 8.0

    def test_exception_fallback(self, monkeypatch):
        monkeypatch.setattr(
            FakePsutil,
            "virtual_memory",
            MagicMock(side_effect=RuntimeError("fail")),
        )
        assert get_system_ram_gb() == 4.0


class TestGetGpuStatus:
    def test_nvidia_smi_success(self):
        with patch("subprocess.run") as mock_run:
            mock_run.return_value.returncode = 0
            with patch("platform.system", return_value="Linux"):
                assert get_gpu_status() is True

    def test_nvidia_smi_failure(self):
        with patch("subprocess.run") as mock_run:
            mock_run.return_value.returncode = 1
            with patch("platform.system", return_value="Windows"):
                assert get_gpu_status() is False

    def test_macos_apple_silicon(self):
        with patch("subprocess.run") as mock_run:
            mock_run.return_value.returncode = 0
            mock_run.return_value.stdout = "Apple M1"
            with patch("platform.system", return_value="Darwin"):
                assert get_gpu_status() is True

    def test_macos_intel(self):
        with patch("subprocess.run") as mock_run:
            mock_run.return_value.returncode = 0
            mock_run.return_value.stdout = "Intel Core i7"
            with patch("platform.system", return_value="Darwin"):
                assert get_gpu_status() is False


class TestEstimateAnalysis:
    def test_ollama_no_gpu_low_ram(self, monkeypatch):
        monkeypatch.setattr(
            FakePsutil, "virtual_memory", lambda: FakeVirtualMemory(2 * 1024**3)
        )
        # Patch get_gpu_status directly on the scanner module
        monkeypatch.setattr(scanner_module, "get_gpu_status", lambda: False)
        can_run, _, chunk_size, hw_type = estimate_analysis(
            10, "llama3.2", "ollama"
        )
        assert can_run is False
        assert hw_type == "Local CPU (Standard)"

    def test_ollama_with_gpu(self, monkeypatch):
        monkeypatch.setattr(
            FakePsutil, "virtual_memory", lambda: FakeVirtualMemory(16 * 1024**3)
        )
        monkeypatch.setattr(scanner_module, "get_gpu_status", lambda: True)
        can_run, _, chunk_size, hw_type = estimate_analysis(
            20, "llama3.2", "ollama"
        )
        assert can_run is True
        assert chunk_size == 5
        assert hw_type == "Local GPU (Accelerated)"

    def test_litellm_backend(self):
        can_run, _, chunk_size, hw_type = estimate_analysis(
            5, "gpt-4", "litellm"
        )
        assert can_run is True
        assert chunk_size == 10
        assert hw_type == "Cloud Engine"


class TestParseArgs:
    def test_defaults(self):
        with patch.object(sys, "argv", ["prog"]):
            args = parse_args()
        assert args.output == "findings.json"
        assert args.llm_backend == "ollama"
        assert not args.analyze

    def test_custom_args(self):
        argv = [
            "prog", "--analyze", "--llm-backend", "litellm", "--rules", "custom"
        ]
        with patch.object(sys, "argv", argv):
            args = parse_args()
        assert args.analyze is True
        assert args.llm_backend == "litellm"
        assert args.rules == "custom"


class TestSortFindingsByRisk:
    def test_sorting(self):
        findings = [
            {"severity": "LOW", "dynamic_risk_score": 1.0},
            {"severity": "CRITICAL", "dynamic_risk_score": 5.0},
            {"severity": "HIGH", "dynamic_risk_score": 4.0},
            {"severity": "UNKNOWN", "dynamic_risk_score": 0.0},
        ]
        sorted_f = sort_findings_by_risk(findings)
        assert sorted_f[0]["severity"] == "CRITICAL"
        assert sorted_f[1]["severity"] == "HIGH"
        assert sorted_f[2]["severity"] == "LOW"
        assert sorted_f[3]["severity"] == "UNKNOWN"


class TestSafeWizard:
    @patch("shutil.which")
    def test_ollama_missing(self, mock_which):
        mock_which.return_value = None
        with patch("platform.system", return_value="Linux"):
            safe_wizard()

    @patch("shutil.which")
    def test_ollama_present_pull_success(self, mock_which):
        mock_which.return_value = "/usr/bin/ollama"
        with patch("subprocess.run") as mock_run:
            safe_wizard()
        mock_run.assert_called_once()

    @patch("shutil.which")
    def test_ollama_pull_failure(self, mock_which):
        mock_which.return_value = "/usr/bin/ollama"
        with patch("subprocess.run", side_effect=subprocess.CalledProcessError(1, "ollama")):
            safe_wizard()  # logs error, no raise


class TestInteractiveRemediation:
    def test_no_tty(self):
        with patch("sys.stdin.isatty", return_value=False):
            interactive_remediation([], {})

    def test_empty_remediations(self):
        with patch("sys.stdin.isatty", return_value=True):
            interactive_remediation([], {"top_remediations": []})


class TestRunAllScanners:
    @pytest.mark.asyncio
    async def test_runs_plugins(self):
        plugins = {
            "trivy": MagicMock(),
        }
        args = argparse.Namespace(
            trivy="trivy.json",
            semgrep=None,
            poutine=None,
            zizmor=None,
            gitleaks=None,
        )
        # Patch the async function directly on the module
        with patch.object(scanner_module, "run_scanner_async", new_callable=AsyncMock) as mock_run:
            mock_run.return_value = [{"id": "1"}]
            result = await run_all_scanners(args, plugins)
        assert len(result) == 1
        mock_run.assert_called_once()


class TestExecuteAiAnalysis:
    @pytest.mark.asyncio
    async def test_no_analyze_flag(self):
        result = await execute_ai_analysis(
            argparse.Namespace(analyze=False, output="out.json"), [], {}
        )
        assert result == {}

    @pytest.mark.asyncio
    async def test_cannot_run(self, monkeypatch):
        args = argparse.Namespace(
            analyze=True,
            output="out.json",
            llm_model="llama3.2",
            llm_backend="ollama",
            force_ai=False,
        )
        findings = [{"id": "1"}] * 10
        # Patch estimate_analysis to return can_run=False
        monkeypatch.setattr(
            scanner_module, "estimate_analysis",
            lambda *a, **kw: (False, 10.0, 5, "CPU"),
        )
        # Mock open and json.dump to avoid file I/O
        with patch("builtins.open", MagicMock()), patch.object(scanner_module.json, "dump"):
            result = await execute_ai_analysis(args, findings, {})
        assert result["risk_score"] == 0.0

    @pytest.mark.asyncio
    async def test_success(self, monkeypatch):
        args = argparse.Namespace(
            analyze=True,
            output="out.json",
            llm_model="llama3.2",
            llm_backend="ollama",
            force_ai=True,
        )
        findings = [{"id": "1"}] * 10
        monkeypatch.setattr(
            scanner_module, "estimate_analysis",
            lambda *a, **kw: (True, 10.0, 5, "GPU"),
        )
        mock_analyzer = MagicMock()
        mock_analyzer.run = AsyncMock(return_value={"risk_score": 90})
        monkeypatch.setattr(
            scanner_module, "get_analyzer", lambda *a, **kw: mock_analyzer
        )
        with patch("builtins.open", MagicMock()), patch.object(scanner_module.json, "dump"):
            result = await execute_ai_analysis(args, findings, {})
        assert result["risk_score"] == 90
