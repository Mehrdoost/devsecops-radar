# tests/test_scanner.py (fully corrected)
"""Tests for the CLI scanner – all passing, no ruff errors."""

import argparse
import sys
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from devsecops_radar.cli.scanner import (
    ScanStatus,
    _execute_ai_analysis,
    _get_gpu_status,
    _get_system_ram_gb,
    _interactive_remediation,
    _safe_wizard,
    _sort_findings_by_risk,
    discover_plugins,
    estimate_analysis,
    main,
    parse_args,
    run_all_scanners,
    run_app,
    run_scanner_async,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------
@pytest.fixture
def mock_adapter():
    """Return a MagicMock that behaves like a ScannerAdapter."""
    adapter = MagicMock()
    adapter.parse.return_value = [
        MagicMock(model_dump=lambda: {"id": "R1", "tool": "dummy", "severity": "LOW"})
    ]
    adapter.run.return_value = [
        MagicMock(model_dump=lambda: {"id": "R2", "tool": "dummy", "severity": "HIGH"})
    ]
    return adapter


@pytest.fixture
def base_dir(tmp_path):
    return tmp_path


# ---------------------------------------------------------------------------
# Tests for helper functions
# ---------------------------------------------------------------------------
class TestGetSystemRamGb:
    def test_success(self):
        with patch("psutil.virtual_memory") as mock_vm:
            mock_vm.return_value.total = 8 * 1024**3
            assert _get_system_ram_gb() == 8.0

    def test_exception_returns_default(self):
        with patch("psutil.virtual_memory", side_effect=Exception):
            assert _get_system_ram_gb() == 4.0


class TestGetGpuStatus:
    def test_nvidia_smi_success(self):
        with patch("platform.system", return_value="Linux"), \
             patch("devsecops_radar.cli.scanner.safe_subprocess_run") as mock_run:
            mock_run.return_value.returncode = 0
            assert _get_gpu_status() is True

    def test_nvidia_smi_failure(self):
        with patch("platform.system", return_value="Linux"), \
             patch("devsecops_radar.cli.scanner.safe_subprocess_run") as mock_run:
            mock_run.return_value.returncode = 1
            assert _get_gpu_status() is False

    def test_macos_apple_silicon(self):
        with patch("platform.system", return_value="Darwin"), \
             patch("devsecops_radar.cli.scanner.safe_subprocess_run") as mock_run:
            mock_run.return_value.stdout = "Apple M1"
            assert _get_gpu_status() is True

    def test_macos_intel(self):
        with patch("platform.system", return_value="Darwin"), \
             patch("devsecops_radar.cli.scanner.safe_subprocess_run") as mock_run:
            mock_run.return_value.stdout = "Intel"
            assert _get_gpu_status() is False

    def test_unknown_os(self):
        with patch("platform.system", return_value="FreeBSD"):
            assert _get_gpu_status() is False

    def test_exception_returns_false(self):
        with patch("devsecops_radar.cli.scanner.safe_subprocess_run",
                   side_effect=Exception):
            assert _get_gpu_status() is False


class TestEstimateAnalysis:
    def test_litellm_backend(self):
        with patch("devsecops_radar.cli.scanner._get_system_ram_gb", return_value=8.0), \
             patch("devsecops_radar.cli.scanner._get_gpu_status", return_value=False):
            can_run, _est, chunk, hw = estimate_analysis(10, "gpt-4", "litellm")
            assert can_run is True
            assert chunk == 10
            assert "Cloud Engine" in hw

    def test_local_no_gpu_ram_ok(self):
        with patch("devsecops_radar.cli.scanner._get_system_ram_gb", return_value=8.0), \
             patch("devsecops_radar.cli.scanner._get_gpu_status", return_value=False):
            can_run, _est, _chunk, _hw = estimate_analysis(10, "llama3.2", "ollama")
            assert can_run is True

    def test_local_with_gpu(self):
        with patch("devsecops_radar.cli.scanner._get_system_ram_gb", return_value=8.0), \
             patch("devsecops_radar.cli.scanner._get_gpu_status", return_value=True):
            can_run, _est, _chunk, hw = estimate_analysis(10, "llama3.2", "ollama")
            assert can_run is True
            assert "GPU" in hw

    def test_low_ram_under_4_no_force(self):
        with patch("devsecops_radar.cli.scanner._get_system_ram_gb", return_value=3.0), \
             patch("devsecops_radar.cli.scanner._get_gpu_status", return_value=False):
            can_run, _est, _chunk, _hw = estimate_analysis(10, "llama3.2", "ollama")
            assert can_run is False

    def test_low_ram_force_ai(self):
        with patch("devsecops_radar.cli.scanner._get_system_ram_gb", return_value=3.0), \
             patch("devsecops_radar.cli.scanner._get_gpu_status", return_value=False):
            can_run, _est, chunk, _hw = estimate_analysis(10, "llama3.2", "ollama", True)
            assert can_run is True
            assert chunk == 2

    def test_ram_between_4_and_8(self):
        with patch("devsecops_radar.cli.scanner._get_system_ram_gb", return_value=6.0), \
             patch("devsecops_radar.cli.scanner._get_gpu_status", return_value=False):
            can_run, _est, chunk, _hw = estimate_analysis(10, "llama3.2", "ollama")
            assert can_run is True
            assert chunk == 3


class TestDiscoverPlugins:
    def test_success_internal_scanner(self):
        mock_cls = MagicMock()
        mock_cls.__module__ = "devsecops_radar.scanners.trivy"
        mock_cls.name = "trivy"
        with patch("devsecops_radar.cli.scanner.entry_points") as mock_ep:
            mock_ep.return_value = [MagicMock(load=lambda: mock_cls)]
            plugins = discover_plugins()
            assert "trivy" in plugins

    def test_block_external_plugin(self):
        mock_cls = MagicMock()
        mock_cls.__module__ = "evil.module"
        mock_cls.name = "evil"
        with patch("devsecops_radar.cli.scanner.entry_points") as mock_ep:
            mock_ep.return_value = [MagicMock(load=lambda: mock_cls)]
            plugins = discover_plugins()
            assert "evil" not in plugins

    def test_load_error(self):
        with patch("devsecops_radar.cli.scanner.entry_points", side_effect=Exception):
            plugins = discover_plugins()
            assert plugins == {}


class TestParseArgs:
    def test_defaults(self):
        """parse_args must be isolated from pytest args."""
        with patch.object(sys, "argv", ["scanner.py"]):
            args = parse_args()
        assert args.output == "findings.json"
        assert args.llm_backend == "ollama"

    def test_full_args(self):
        test_args = [
            "--trivy", "scan.json",
            "--analyze",
            "--fix",
            "--report", "report.pdf",
            "--export-sarif", "out.sarif",
            "--compliance", "CIS",
        ]
        with patch.object(sys, "argv", ["scanner.py"] + test_args):
            args = parse_args()
            assert args.trivy == "scan.json"
            assert args.analyze is True
            assert args.fix is True
            assert args.report == "report.pdf"
            assert args.export_sarif == "out.sarif"
            assert args.compliance == "CIS"


# ---------------------------------------------------------------------------
# Tests for scanner execution
# ---------------------------------------------------------------------------
class TestRunScannerAsync:
    @pytest.mark.asyncio
    async def test_file_target_parses(self, mock_adapter, base_dir):
        file_path = base_dir / "test.json"
        file_path.write_text("{}")
        status = ScanStatus()
        findings = await run_scanner_async(
            "dummy", str(file_path), mock_adapter, status, base_dir
        )
        assert len(findings) == 1
        assert findings[0]["id"] == "R1"
        mock_adapter.parse.assert_called_once()

    @pytest.mark.asyncio
    async def test_dir_target_runs(self, mock_adapter, base_dir):
        status = ScanStatus()
        findings = await run_scanner_async(
            "dummy", "nginx:latest", mock_adapter, status, base_dir
        )
        assert len(findings) == 1
        assert findings[0]["id"] == "R2"
        mock_adapter.run.assert_called_once_with("nginx:latest")

    @pytest.mark.asyncio
    async def test_exception_returns_empty(self, mock_adapter, base_dir):
        mock_adapter.run.side_effect = RuntimeError("fail")
        status = ScanStatus()
        findings = await run_scanner_async(
            "dummy", "target", mock_adapter, status, base_dir
        )
        assert findings == []
        assert status.any_failed()


class TestRunAllScanners:
    @pytest.mark.asyncio
    async def test_collects_all_findings(self):
        plugins = {"trivy": MagicMock(), "semgrep": MagicMock()}
        with patch("pathlib.Path.is_file", return_value=True), \
             patch("devsecops_radar.cli.scanner.resolve_safe_path") as mock_resolve, \
             patch("devsecops_radar.cli.scanner.ScannerAdapter") as MockAdapter:
            mock_resolve.side_effect = lambda p, b: Path(p).resolve()
            mock_adapter_instance = MagicMock()
            mock_adapter_instance.parse.return_value = [
                MagicMock(model_dump=lambda: {"id": "R1", "tool": "x", "severity": "LOW"})
            ]
            MockAdapter.return_value = mock_adapter_instance
            args = MagicMock()
            args.trivy = "file1.json"
            args.semgrep = "file2.json"
            args.poutine = args.zizmor = args.gitleaks = None
            findings, status = await run_all_scanners(args, plugins, Path("/fake"))
            assert len(findings) == 2

    @pytest.mark.asyncio
    async def test_task_exception_handled(self):
        plugins = {"trivy": MagicMock()}
        with patch("pathlib.Path.is_file", return_value=True), \
             patch("devsecops_radar.cli.scanner.resolve_safe_path"), \
             patch("devsecops_radar.cli.scanner.ScannerAdapter") as MockAdapter:
            mock_adapter_instance = MagicMock()
            mock_adapter_instance.parse.side_effect = RuntimeError("fail")
            MockAdapter.return_value = mock_adapter_instance
            args = MagicMock()
            args.trivy = "file.json"
            args.semgrep = args.poutine = args.zizmor = args.gitleaks = None
            findings, status = await run_all_scanners(args, plugins, Path("/fake"))
            assert findings == []

    @pytest.mark.asyncio
    async def test_scanner_not_in_plugins_skipped(self):
        plugins = {"trivy": MagicMock()}
        args = MagicMock()
        args.trivy = None
        args.semgrep = "file.json"
        args.poutine = args.zizmor = args.gitleaks = None
        findings, status = await run_all_scanners(args, plugins, Path("/fake"))
        assert findings == []


# ---------------------------------------------------------------------------
# Tests for AI analysis & remediation helpers
# ---------------------------------------------------------------------------
class TestSortFindingsByRisk:
    def test_sorting_order(self):
        findings = [
            {"severity": "LOW", "dynamic_risk_score": 0.5},
            {"severity": "CRITICAL", "dynamic_risk_score": 9.0},
            {"severity": "HIGH", "dynamic_risk_score": 6.0},
        ]
        sorted_findings = _sort_findings_by_risk(findings)
        assert sorted_findings[0]["severity"] == "CRITICAL"
        assert sorted_findings[-1]["severity"] == "LOW"


class TestExecuteAiAnalysis:
    @pytest.mark.asyncio
    async def test_no_analyze_flag(self):
        args = argparse.Namespace(analyze=False)
        result = await _execute_ai_analysis(args, [], {})
        assert result == {}

    @pytest.mark.asyncio
    async def test_no_findings(self):
        args = argparse.Namespace(analyze=True)
        result = await _execute_ai_analysis(args, [], {})
        assert result == {}

    @pytest.mark.asyncio
    async def test_cannot_run_writes_fallback(self, tmp_path):
        args = argparse.Namespace(
            analyze=True,
            output=str(tmp_path / "findings.json"),
            llm_model="llama3.2",
            llm_backend="ollama",
            force_ai=False,
        )
        with patch("devsecops_radar.cli.scanner.estimate_analysis") as mock_est, \
             patch("devsecops_radar.cli.scanner.resolve_safe_path",
                   side_effect=lambda p, b: Path(p).resolve()):
            mock_est.return_value = (False, 0, 0, "CPU")
            result = await _execute_ai_analysis(args, [{"severity": "LOW"}], {})
            assert "Analysis aborted" in result["executive_summary"]

    @pytest.mark.asyncio
    async def test_analysis_exception_returns_empty(self):
        args = argparse.Namespace(
            analyze=True, output="findings.json",
            llm_model="llama3.2", llm_backend="ollama", force_ai=False,
        )
        with patch("devsecops_radar.cli.scanner.estimate_analysis") as mock_est, \
             patch("devsecops_radar.cli.scanner.resolve_safe_path",
                   side_effect=lambda p, b: Path(p).resolve()), \
             patch("devsecops_radar.cli.scanner.get_analyzer",
                   side_effect=RuntimeError):
            mock_est.return_value = (True, 1, 5, "CPU")
            result = await _execute_ai_analysis(args, [{"severity": "LOW"}], {})
            assert result == {}

    @pytest.mark.asyncio
    async def test_successful_analysis(self):
        args = argparse.Namespace(
            analyze=True, output="findings.json",
            llm_model="llama3.2", llm_backend="ollama", force_ai=False,
        )
        mock_analyzer = MagicMock()
        mock_analyzer.run = AsyncMock(return_value={"executive_summary": "ok", "risk_score": 50})
        with patch("devsecops_radar.cli.scanner.estimate_analysis") as mock_est, \
             patch("devsecops_radar.cli.scanner.resolve_safe_path",
                   side_effect=lambda p, b: Path(p).resolve()), \
             patch("devsecops_radar.cli.scanner.get_analyzer", return_value=mock_analyzer):
            mock_est.return_value = (True, 1, 5, "CPU")
            result = await _execute_ai_analysis(args, [{"severity": "LOW"}], {})
            assert result["executive_summary"] == "ok"


class TestInteractiveRemediation:
    @pytest.mark.asyncio
    async def test_no_tty(self):
        with patch("sys.stdin.isatty", return_value=False):
            await _interactive_remediation([], {})

    @pytest.mark.asyncio
    async def test_no_remediations(self):
        with patch("sys.stdin.isatty", return_value=True):
            await _interactive_remediation([], {"top_remediations": []})

    @pytest.mark.asyncio
    async def test_patches_accepted_and_applied(self):
        """Simulate user input without triggering pytest capture conflict."""
        with patch("sys.stdin.isatty", return_value=True), \
             patch("devsecops_radar.cli.scanner.auto_fix") as mock_fix, \
             patch("devsecops_radar.cli.scanner.generate_pr"), \
             patch("builtins.input", return_value="y"):
            mock_fix.return_value = {"/tmp/x"}
            await _interactive_remediation(
                [],
                {"top_remediations": [{"finding_id": "F1", "patch_content": "patch"}]},
            )

    @pytest.mark.asyncio
    async def test_eof_breaks_review(self):
        with patch("sys.stdin.isatty", return_value=True), \
             patch("builtins.input", side_effect=EOFError):
            await _interactive_remediation(
                [],
                {"top_remediations": [{"finding_id": "F1", "patch_content": "patch"}]},
            )


# ---------------------------------------------------------------------------
# Tests for wizard
# ---------------------------------------------------------------------------
class TestSafeWizard:
    def test_ollama_not_installed(self):
        with patch("devsecops_radar.cli.scanner.safe_subprocess_run",
                   side_effect=FileNotFoundError), \
             patch("devsecops_radar.cli.scanner.logger") as mock_logger:
            _safe_wizard()
            assert any("not installed" in str(call)
                       for call in mock_logger.warning.call_args_list)

    def test_ollama_pull_failure(self):
        with patch("devsecops_radar.cli.scanner.safe_subprocess_run") as mock_run:
            mock_run.side_effect = [MagicMock(), RuntimeError("network error")]
            with patch("devsecops_radar.cli.scanner.logger") as mock_logger:
                _safe_wizard()
                assert any("Failed to pull" in str(call)
                           for call in mock_logger.error.call_args_list)

    def test_ollama_present_pull_success(self):
        with patch("devsecops_radar.cli.scanner.safe_subprocess_run") as mock_run:
            _safe_wizard()
            assert mock_run.call_count == 2


# ---------------------------------------------------------------------------
# Tests for the main orchestrator
# ---------------------------------------------------------------------------
class TestRunApp:
    @pytest.mark.asyncio
    async def test_wizard_mode(self):
        args = argparse.Namespace(wizard=True)
        with patch("devsecops_radar.cli.scanner.parse_args", return_value=args), \
             patch("devsecops_radar.cli.scanner._safe_wizard") as mock_wiz:
            await run_app()
            mock_wiz.assert_called_once()

    @pytest.mark.asyncio
    async def test_update_rules(self):
        args = argparse.Namespace(wizard=False, update_rules=True)
        with patch("devsecops_radar.cli.scanner.parse_args", return_value=args), \
             patch("devsecops_radar.cli.scanner.RuleFusionEngine") as mock_engine:
            await run_app()
            mock_engine.return_value.update_community_rules.assert_called_once()

    @pytest.mark.asyncio
    async def test_no_findings_exits_gracefully(self):
        args = argparse.Namespace(
            wizard=False, update_rules=False, trivy=None, semgrep=None,
            poutine=None, zizmor=None, gitleaks=None, rules=None,
            topology=None, output="out.json", analyze=False,
            policy=None, rego_policy=None, fix=False, review=False,
            report=None, export_sarif=None, export_cyclonedx=None,
            compliance=None, notify_jira=None, notify_asana=None,
            force_ai=False, llm_backend="ollama", llm_model="llama3.2",
            fail_on_scanner_error=False,
        )
        with patch("devsecops_radar.cli.scanner.parse_args", return_value=args), \
             patch("devsecops_radar.cli.scanner.discover_plugins", return_value={}), \
             patch("devsecops_radar.cli.scanner.run_all_scanners",
                   new_callable=AsyncMock) as mock_scan:
            mock_scan.return_value = ([], MagicMock())
            await run_app()

    @pytest.mark.asyncio
    async def test_policy_violation_exits(self):
        args = argparse.Namespace(
            wizard=False, update_rules=False, trivy="scan.json", semgrep=None,
            poutine=None, zizmor=None, gitleaks=None, rules=None,
            topology=None, output="out.json", analyze=False,
            policy="policy.json", rego_policy=None, fix=False, review=False,
            report=None, export_sarif=None, export_cyclonedx=None,
            compliance=None, notify_jira=None, notify_asana=None,
            force_ai=False, llm_backend="ollama", llm_model="llama3.2",
            fail_on_scanner_error=False,
        )
        with patch("devsecops_radar.cli.scanner.parse_args", return_value=args), \
             patch("devsecops_radar.cli.scanner.discover_plugins"), \
             patch("devsecops_radar.cli.scanner.run_all_scanners",
                   new_callable=AsyncMock) as mock_scan, \
             patch("devsecops_radar.cli.scanner.RuleFusionEngine") as mock_engine, \
             patch("devsecops_radar.cli.scanner.resolve_safe_path"), \
             patch("devsecops_radar.cli.scanner.compute_dynamic_risk_score", return_value=0):
            mock_scan.return_value = ([{"severity": "CRITICAL"}], MagicMock())
            mock_engine.return_value.evaluate_policy.return_value = False
            with pytest.raises(SystemExit):
                await run_app()

    @pytest.mark.asyncio
    async def test_successful_scan_with_output_and_reports(self, tmp_path):
        out_file = tmp_path / "out.json"
        args = argparse.Namespace(
            wizard=False, update_rules=False, trivy="scan.json", semgrep=None,
            poutine=None, zizmor=None, gitleaks=None, rules=None,
            topology=None, output=str(out_file), analyze=False,
            policy=None, rego_policy=None, fix=False, review=False,
            report="report.pdf", export_sarif="out.sarif", export_cyclonedx="out.cdx",
            compliance="CIS", notify_jira=None, notify_asana=None,
            force_ai=False, llm_backend="ollama", llm_model="llama3.2",
            fail_on_scanner_error=False,
        )
        # Patch the real export functions where they are called from
        with patch("devsecops_radar.cli.scanner.parse_args", return_value=args), \
             patch("devsecops_radar.cli.scanner.discover_plugins"), \
             patch("devsecops_radar.cli.scanner.run_all_scanners",
                   new_callable=AsyncMock) as mock_scan, \
             patch("devsecops_radar.cli.scanner.resolve_safe_path",
                   side_effect=lambda p, b: Path(p).resolve()), \
             patch("devsecops_radar.cli.scanner.compute_dynamic_risk_score", return_value=0), \
             patch("devsecops_radar.cli.scanner.save_scan", return_value=1), \
             patch("devsecops_radar.core.sarif_export.export_sarif") as mock_sarif, \
             patch("devsecops_radar.core.sarif_export.export_cyclonedx") as mock_cdx, \
             patch("devsecops_radar.cli.scanner.generate_pdf_report") as mock_pdf:
            mock_scan.return_value = ([{"severity": "LOW"}], MagicMock())
            await run_app()
            assert out_file.exists()
            mock_pdf.assert_called_once()
            mock_sarif.assert_called_once()
            mock_cdx.assert_called_once()

    @pytest.mark.asyncio
    async def test_auto_fix_without_review(self):
        args = argparse.Namespace(
            wizard=False, update_rules=False, trivy="scan.json", semgrep=None,
            poutine=None, zizmor=None, gitleaks=None, rules=None,
            topology=None, output="out.json", analyze=False,
            policy=None, rego_policy=None, fix=True, review=False,
            report=None, export_sarif=None, export_cyclonedx=None,
            compliance=None, notify_jira=None, notify_asana=None,
            force_ai=False, llm_backend="ollama", llm_model="llama3.2",
            fail_on_scanner_error=False,
        )
        ai_summary = {"top_remediations": [{"finding_id": "F1", "patch_content": "patch"}]}
        with patch("devsecops_radar.cli.scanner.parse_args", return_value=args), \
             patch("devsecops_radar.cli.scanner.discover_plugins"), \
             patch("devsecops_radar.cli.scanner.run_all_scanners",
                   new_callable=AsyncMock) as mock_scan, \
             patch("devsecops_radar.cli.scanner.resolve_safe_path",
                   side_effect=lambda p, b: Path(p).resolve()), \
             patch("devsecops_radar.cli.scanner.compute_dynamic_risk_score", return_value=0), \
             patch("devsecops_radar.cli.scanner.save_scan", return_value=1), \
             patch("devsecops_radar.cli.scanner._execute_ai_analysis",
                   new_callable=AsyncMock) as mock_ai, \
             patch("devsecops_radar.cli.scanner.auto_fix") as mock_fix, \
             patch("devsecops_radar.cli.scanner.generate_pr"):
            mock_scan.return_value = ([{"severity": "LOW"}], MagicMock())
            mock_ai.return_value = ai_summary
            mock_fix.return_value = {"/tmp/x"}
            await run_app()
            mock_fix.assert_called_once()

    @pytest.mark.asyncio
    async def test_rego_policy_violation_exits(self):
        args = argparse.Namespace(
            wizard=False, update_rules=False, trivy="scan.json", semgrep=None,
            poutine=None, zizmor=None, gitleaks=None, rules=None,
            topology=None, output="out.json", analyze=False,
            policy=None, rego_policy="policy.rego", fix=False, review=False,
            report=None, export_sarif=None, export_cyclonedx=None,
            compliance=None, notify_jira=None, notify_asana=None,
            force_ai=False, llm_backend="ollama", llm_model="llama3.2",
            fail_on_scanner_error=False,
        )
        with patch("devsecops_radar.cli.scanner.parse_args", return_value=args), \
             patch("devsecops_radar.cli.scanner.discover_plugins"), \
             patch("devsecops_radar.cli.scanner.run_all_scanners",
                   new_callable=AsyncMock) as mock_scan, \
             patch("devsecops_radar.cli.scanner.RuleFusionEngine") as mock_engine, \
             patch("devsecops_radar.cli.scanner.resolve_safe_path"), \
             patch("devsecops_radar.cli.scanner.compute_dynamic_risk_score", return_value=0):
            mock_scan.return_value = ([{"severity": "LOW"}], MagicMock())
            mock_engine.return_value.evaluate_rego_policy.return_value = False
            with pytest.raises(SystemExit):
                await run_app()

    @pytest.mark.asyncio
    async def test_fail_on_scanner_error(self):
        args = argparse.Namespace(
            wizard=False, update_rules=False, trivy="scan.json", semgrep=None,
            poutine=None, zizmor=None, gitleaks=None, rules=None,
            topology=None, output="out.json", analyze=False,
            policy=None, rego_policy=None, fix=False, review=False,
            report=None, export_sarif=None, export_cyclonedx=None,
            compliance=None, notify_jira=None, notify_asana=None,
            force_ai=False, llm_backend="ollama", llm_model="llama3.2",
            fail_on_scanner_error=True,
        )
        status = MagicMock()
        status.any_failed.return_value = True
        with patch("devsecops_radar.cli.scanner.parse_args", return_value=args), \
             patch("devsecops_radar.cli.scanner.discover_plugins"), \
             patch("devsecops_radar.cli.scanner.run_all_scanners",
                   new_callable=AsyncMock) as mock_scan:
            mock_scan.return_value = ([], status)
            with pytest.raises(SystemExit):
                await run_app()


class TestMain:
    def test_keyboard_interrupt(self):
        with patch("asyncio.run", side_effect=KeyboardInterrupt), \
             patch("devsecops_radar.cli.scanner.sys.exit") as mock_exit:
            main()
            mock_exit.assert_called_once_with(130)
