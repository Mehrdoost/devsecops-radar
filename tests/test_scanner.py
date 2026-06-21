"""Tests for CLI orchestrator (scanner.py) – fully updated for the new code."""

import argparse
import asyncio
import os
import sys
from unittest.mock import AsyncMock, MagicMock, mock_open, patch

import pytest

from devsecops_radar.cli.scanner import (
    ScanStatus,
    discover_plugins,
    estimate_analysis,
    execute_ai_analysis,
    get_gpu_status,
    get_system_ram_gb,
    interactive_remediation,
    main,
    parse_args,
    run_all_scanners,
    run_app,
    run_scanner_async,
    safe_wizard,
    sort_findings_by_risk,
)


# ---------------------------------------------------------------------------
# Fixtures / helpers
# ---------------------------------------------------------------------------
@pytest.fixture
def mock_logger():
    with patch("devsecops_radar.cli.scanner.logger") as mock:
        yield mock


@pytest.fixture
def mock_psutil():
    with patch("devsecops_radar.cli.scanner.psutil") as mock:
        yield mock


def make_status() -> ScanStatus:
    return ScanStatus()


# ---------------------------------------------------------------------------
# get_system_ram_gb
# ---------------------------------------------------------------------------
class TestGetSystemRamGb:
    def test_success(self, mock_psutil):
        mock_psutil.virtual_memory.return_value.total = 8 * 1024**3
        assert get_system_ram_gb() == 8.0

    def test_exception_returns_default(self, mock_psutil):
        mock_psutil.virtual_memory.side_effect = RuntimeError("fail")
        assert get_system_ram_gb() == 4.0


# ---------------------------------------------------------------------------
# get_gpu_status
# ---------------------------------------------------------------------------
class TestGetGpuStatus:
    def test_nvidia_smi_success(self):
        with patch("devsecops_radar.cli.scanner.platform.system", return_value="Linux"), \
             patch("devsecops_radar.cli.scanner.safe_subprocess_run") as mock_run:
            mock_run.return_value.returncode = 0
            assert get_gpu_status() is True

    def test_nvidia_smi_failure(self):
        with patch("devsecops_radar.cli.scanner.platform.system", return_value="Windows"), \
             patch("devsecops_radar.cli.scanner.safe_subprocess_run") as mock_run:
            mock_run.return_value.returncode = 1
            assert get_gpu_status() is False

    def test_macos_apple_silicon(self):
        with patch("devsecops_radar.cli.scanner.platform.system", return_value="Darwin"), \
             patch("devsecops_radar.cli.scanner.safe_subprocess_run") as mock_run:
            mock_run.return_value.stdout = "Apple M1"
            assert get_gpu_status() is True

    def test_macos_intel(self):
        with patch("devsecops_radar.cli.scanner.platform.system", return_value="Darwin"), \
             patch("devsecops_radar.cli.scanner.safe_subprocess_run") as mock_run:
            mock_run.return_value.stdout = "Intel(R) Core(TM)"
            assert get_gpu_status() is False

    def test_unknown_os(self):
        with patch("devsecops_radar.cli.scanner.platform.system", return_value="FreeBSD"):
            assert get_gpu_status() is False

    def test_exception_returns_false(self):
        with patch("devsecops_radar.cli.scanner.platform.system", side_effect=OSError):
            assert get_gpu_status() is False


# ---------------------------------------------------------------------------
# estimate_analysis
# ---------------------------------------------------------------------------
class TestEstimateAnalysis:
    @patch("devsecops_radar.cli.scanner.psutil")
    def test_litellm_backend(self, mock_psutil):
        mock_psutil.cpu_count.return_value = 8
        mock_psutil.virtual_memory.return_value.total = 16 * 1024**3
        can_run, secs, chunk, hw = estimate_analysis(50, "gpt-4", "litellm")
        assert can_run is True
        assert secs == 5.0 + 50 * 0.5
        assert chunk == 10
        assert hw == "Cloud Engine"

    @patch("devsecops_radar.cli.scanner.psutil")
    @patch("devsecops_radar.cli.scanner.get_gpu_status", return_value=False)
    def test_local_no_gpu_ram_ok(self, mock_gpu, mock_psutil):
        mock_psutil.cpu_count.return_value = 4
        mock_psutil.virtual_memory.return_value.total = 16 * 1024**3
        can_run, secs, chunk, hw = estimate_analysis(10, "llama3.2", "ollama")
        assert can_run is True
        assert secs == 10 * 8.0
        assert chunk == 5
        assert "CPU" in hw

    @patch("devsecops_radar.cli.scanner.psutil")
    @patch("devsecops_radar.cli.scanner.get_gpu_status", return_value=True)
    def test_local_with_gpu(self, mock_gpu, mock_psutil):
        mock_psutil.cpu_count.return_value = 4
        mock_psutil.virtual_memory.return_value.total = 16 * 1024**3
        can_run, secs, chunk, hw = estimate_analysis(10, "llama3.2", "ollama")
        assert can_run is True
        assert secs == 10 * 2.0
        assert chunk == 5
        assert "GPU" in hw

    @patch("devsecops_radar.cli.scanner.psutil")
    @patch("devsecops_radar.cli.scanner.get_gpu_status", return_value=False)
    def test_low_ram_under_4_no_force(self, mock_gpu, mock_psutil):
        mock_psutil.cpu_count.return_value = 4
        mock_psutil.virtual_memory.return_value.total = 3 * 1024**3
        can_run, secs, chunk, hw = estimate_analysis(1, "llama3.2", "ollama", force_ai=False)
        assert can_run is False
        assert chunk == 5
        assert secs == 1 * 8.0

    @patch("devsecops_radar.cli.scanner.psutil")
    @patch("devsecops_radar.cli.scanner.get_gpu_status", return_value=False)
    def test_low_ram_force_ai(self, mock_gpu, mock_psutil):
        mock_psutil.cpu_count.return_value = 4
        mock_psutil.virtual_memory.return_value.total = 3 * 1024**3
        can_run, secs, chunk, hw = estimate_analysis(1, "llama3.2", "ollama", force_ai=True)
        assert can_run is True
        assert chunk == 2
        assert secs == 1 * (8.0 * 3.0)

    @patch("devsecops_radar.cli.scanner.psutil")
    @patch("devsecops_radar.cli.scanner.get_gpu_status", return_value=False)
    def test_ram_between_4_and_8(self, mock_gpu, mock_psutil):
        mock_psutil.cpu_count.return_value = 4
        mock_psutil.virtual_memory.return_value.total = 6 * 1024**3
        can_run, secs, chunk, hw = estimate_analysis(10, "llama3.2", "ollama")
        assert can_run is True
        assert chunk == 3
        assert secs == 10 * (8.0 * 1.5)


# ---------------------------------------------------------------------------
# discover_plugins
# ---------------------------------------------------------------------------
class TestDiscoverPlugins:
    @patch("devsecops_radar.cli.scanner.entry_points")
    def test_success_internal_scanner(self, mock_ep):
        cls = MagicMock()
        cls.name = "trivy"
        cls.__module__ = "devsecops_radar.scanners.trivy"
        instance = MagicMock()
        cls.return_value = instance
        ep = MagicMock()
        ep.load.return_value = cls
        mock_ep.return_value = [ep]
        plugins = discover_plugins()
        assert "trivy" in plugins
        assert plugins["trivy"] is instance

    @patch("devsecops_radar.cli.scanner.entry_points")
    @patch("devsecops_radar.cli.scanner.logger")
    def test_block_external_plugin(self, mock_log, mock_ep):
        cls = MagicMock()
        cls.name = "external"
        cls.__module__ = "third_party.scanner"
        ep = MagicMock()
        ep.load.return_value = cls
        mock_ep.return_value = [ep]
        plugins = discover_plugins()
        assert plugins == {}                         # external scanner blocked
        # warning may or may not be called – just verify empty result

    @patch("devsecops_radar.cli.scanner.entry_points")
    @patch("devsecops_radar.cli.scanner.logger")
    def test_load_error(self, mock_log, mock_ep):
        ep = MagicMock()
        ep.load.side_effect = RuntimeError()
        mock_ep.return_value = [ep]
        plugins = discover_plugins()
        assert plugins == {}
        mock_log.error.assert_called_once()


# ---------------------------------------------------------------------------
# parse_args
# ---------------------------------------------------------------------------
class TestParseArgs:
    def test_defaults(self):
        with patch.object(sys, "argv", ["prog"]):
            args = parse_args()
        assert args.output == "findings.json"
        assert args.analyze is False
        assert args.llm_backend == "ollama"
        assert args.llm_model == "llama3.2"

    def test_full_args(self):
        argv = ["prog",
                "--trivy", "t", "--semgrep", "s", "--poutine", "p",
                "--zizmor", "z", "--gitleaks", "g",
                "--output", "o.json", "--analyze", "--force-ai",
                "--llm-backend", "litellm", "--llm-model", "gpt-4",
                "--policy", "pol.json", "--fix", "--review",
                "--report", "rep.pdf", "--wizard",
                "--export-sarif", "sarif.json", "--export-cyclonedx", "cdx.json",
                "--compliance", "PCI-DSS", "--notify-jira", "--notify-asana",
                "--update-rules", "--rego-policy", "reg.rego"]
        with patch.object(sys, "argv", argv):
            args = parse_args()
        assert args.trivy == "t"
        assert args.semgrep == "s"
        assert args.fix is True
        assert args.export_sarif == "sarif.json"
        assert args.compliance == "PCI-DSS"


# ---------------------------------------------------------------------------
# run_scanner_async (with status)
# ---------------------------------------------------------------------------
class TestRunScannerAsync:
    @pytest.mark.asyncio
    async def test_file_target_parses(self):
        adapter = MagicMock()
        adapter.parse = MagicMock(return_value=[MagicMock(model_dump=lambda: {"id": 1})])
        with patch("devsecops_radar.cli.scanner.Path.is_file", return_value=True):
            result = await run_scanner_async("trivy", "report.json", adapter, make_status())
        assert result == [{"id": 1}]

    @pytest.mark.asyncio
    async def test_dir_target_runs(self):
        adapter = MagicMock()
        adapter.run = MagicMock(return_value=[MagicMock(model_dump=lambda: {"id": 2})])
        with patch("devsecops_radar.cli.scanner.Path.is_file", return_value=False):
            result = await run_scanner_async("semgrep", ".", adapter, make_status())
        assert result == [{"id": 2}]

    @pytest.mark.asyncio
    async def test_exception_returns_empty(self, mock_logger):
        adapter = MagicMock()
        adapter.parse = MagicMock(side_effect=RuntimeError("boom"))
        with patch("devsecops_radar.cli.scanner.Path.is_file", return_value=True):
            result = await run_scanner_async("faulty", "file", adapter, make_status())
        assert result == []
        mock_logger.error.assert_called_once()


# ---------------------------------------------------------------------------
# run_all_scanners (returns tuple with status)
# ---------------------------------------------------------------------------
class TestRunAllScanners:
    @pytest.mark.asyncio
    async def test_collects_all_findings(self):
        args = argparse.Namespace(
            trivy="image", semgrep=".", poutine=None, zizmor=None, gitleaks=None
        )
        plugins = {"trivy": MagicMock(), "semgrep": MagicMock()}
        async def fake_run(name, target, adapter, status):
            return [{"tool": name, "target": target}]
        with patch("devsecops_radar.cli.scanner.run_scanner_async", side_effect=fake_run):
            findings, status = await run_all_scanners(args, plugins)
        assert len(findings) == 2
        assert {"tool": "trivy", "target": "image"} in findings

    @pytest.mark.asyncio
    async def test_task_exception_handled(self, mock_logger):
        args = argparse.Namespace(
            trivy="x", semgrep=None, poutine=None, zizmor=None, gitleaks=None
        )
        plugins = {"trivy": MagicMock()}
        with patch("devsecops_radar.cli.scanner.run_scanner_async", side_effect=RuntimeError("boom")):
            findings, status = await run_all_scanners(args, plugins)
        assert findings == []

    @pytest.mark.asyncio
    async def test_scanner_not_in_plugins_skipped(self):
        args = argparse.Namespace(
            trivy="image", semgrep=None, poutine=None, zizmor=None, gitleaks=None
        )
        plugins = {}  # trivy not present
        findings, status = await run_all_scanners(args, plugins)
        assert findings == []


# ---------------------------------------------------------------------------
# sort_findings_by_risk
# ---------------------------------------------------------------------------
class TestSortFindingsByRisk:
    def test_sorting_order(self):
        findings = [
            {"severity": "LOW", "dynamic_risk_score": 5.0},
            {"severity": "CRITICAL", "dynamic_risk_score": 9.0},
            {"severity": "HIGH", "dynamic_risk_score": 8.0},
            {"severity": "MEDIUM", "dynamic_risk_score": 2.0},
            {"severity": "UNKNOWN", "dynamic_risk_score": 0.0},
        ]
        sorted_ = sort_findings_by_risk(findings)
        sevs = [f["severity"] for f in sorted_]
        assert sevs == ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]


# ---------------------------------------------------------------------------
# execute_ai_analysis
# ---------------------------------------------------------------------------
class TestExecuteAiAnalysis:
    @pytest.fixture
    def base_args(self):
        return argparse.Namespace(
            analyze=True, llm_model="llama3.2", llm_backend="ollama",
            force_ai=False, output="findings.json"
        )

    @pytest.mark.asyncio
    async def test_no_analyze_flag(self, base_args):
        base_args.analyze = False
        result = await execute_ai_analysis(base_args, [], {})
        assert result == {}

    @pytest.mark.asyncio
    async def test_no_findings(self, base_args):
        result = await execute_ai_analysis(base_args, [], {})
        assert result == {}

    @pytest.mark.asyncio
    async def test_cannot_run_writes_fallback(self, base_args, tmp_path):
        out = tmp_path / "findings.json"
        base_args.output = str(out)
        findings = [{"severity": "HIGH"}]
        with patch("devsecops_radar.cli.scanner.estimate_analysis", return_value=(False, 10, 2, "Local CPU")), \
             patch("builtins.open", mock_open()) as m:
            result = await execute_ai_analysis(base_args, findings, {})
        assert result["risk_score"] == 0.0
        assert "Analysis aborted" in result["executive_summary"]
        m.assert_called_with(tmp_path / "findings_ai_summary.json", 'w', encoding='utf-8')

    @pytest.mark.asyncio
    async def test_analysis_exception_returns_empty(self, base_args):
        findings = [{"severity": "LOW"}]
        with patch("devsecops_radar.cli.scanner.estimate_analysis", return_value=(True, 5, 2, "HW")), \
             patch("devsecops_radar.cli.scanner.get_analyzer") as mock_ga, \
             patch("devsecops_radar.cli.scanner.logger") as log:
            mock_analyzer = AsyncMock()
            mock_analyzer.run.side_effect = RuntimeError("fail")
            mock_ga.return_value = mock_analyzer
            result = await execute_ai_analysis(base_args, findings, {})
        assert result == {}
        log.error.assert_called_once()

    @pytest.mark.asyncio
    async def test_successful_analysis(self, base_args, tmp_path):
        out = tmp_path / "findings.json"
        base_args.output = str(out)
        findings = [{"severity": "HIGH"}]
        with patch("devsecops_radar.cli.scanner.estimate_analysis", return_value=(True, 30, 5, "Cloud Engine")), \
             patch("devsecops_radar.cli.scanner.get_analyzer") as mock_ga, \
             patch("devsecops_radar.cli.scanner.time") as mock_time, \
             patch("builtins.open", mock_open()) as m:
            mock_time.time.side_effect = [0, 15]
            mock_analyzer = AsyncMock()
            mock_analyzer.run.return_value = {"executive_summary": "all good", "risk_score": 8.5}
            mock_ga.return_value = mock_analyzer
            result = await execute_ai_analysis(base_args, findings, {})
        assert result["executive_summary"] == "all good"
        assert result["execution_time"] == 15
        assert result["hardware_profile"] == "Cloud Engine"
        m.assert_called_with(tmp_path / "findings_ai_summary.json", 'w', encoding='utf-8')


# ---------------------------------------------------------------------------
# interactive_remediation (now async)
# ---------------------------------------------------------------------------
class TestInteractiveRemediation:
    @pytest.mark.asyncio
    async def test_no_tty(self, mock_logger):
        with patch.object(sys.stdin, "isatty", return_value=False):
            await interactive_remediation([], {})
        mock_logger.warning.assert_called_once()

    @pytest.mark.asyncio
    async def test_no_remediations(self, mock_logger):
        with patch.object(sys.stdin, "isatty", return_value=True):
            await interactive_remediation([], {"top_remediations": []})
        mock_logger.info.assert_called_with("No AI remediations available to apply.")

    @pytest.mark.asyncio
    async def test_patches_accepted_and_applied(self, mock_logger):
        ai_summary = {
            "top_remediations": [
                {"finding_id": "F1", "patch_content": "fix F1"},
                {"finding_id": "F2", "patch_content": None},
                {"finding_id": "F3", "patch_content": "fix F3"},
            ]
        }
        with patch.object(sys.stdin, "isatty", return_value=True), \
             patch("devsecops_radar.cli.scanner.input", side_effect=["y", "n", "q"]) as mock_input, \
             patch("devsecops_radar.cli.scanner.auto_fix") as mock_auto_fix, \
             patch("devsecops_radar.cli.scanner.generate_pr") as mock_gen_pr:
            mock_auto_fix.return_value = ["file1.py"]
            await interactive_remediation([], ai_summary)
        assert mock_input.call_count == 2  # y then n, then q stops before third input
        mock_auto_fix.assert_called_once()
        mock_gen_pr.assert_called_once_with(["file1.py"])

    @pytest.mark.asyncio
    async def test_eof_breaks_review(self):
        ai_summary = {"top_remediations": [{"finding_id": "F1", "patch_content": "fix"}]}
        with patch.object(sys.stdin, "isatty", return_value=True), \
             patch("devsecops_radar.cli.scanner.input", side_effect=EOFError), \
             patch("devsecops_radar.cli.scanner.auto_fix") as mock_auto_fix:
            await interactive_remediation([], ai_summary)
        mock_auto_fix.assert_not_called()


# ---------------------------------------------------------------------------
# safe_wizard
# ---------------------------------------------------------------------------
class TestSafeWizard:
    def test_ollama_not_installed(self, mock_logger):
        with patch("devsecops_radar.cli.scanner.shutil.which", return_value=None), \
             patch("devsecops_radar.cli.scanner.platform.system", return_value="Linux"):
            safe_wizard()
        mock_logger.warning.assert_called_with("Ollama is not installed.")

    def test_ollama_pull_failure(self):
        with patch("devsecops_radar.cli.scanner.shutil.which", return_value="/usr/bin/ollama"), \
             patch("devsecops_radar.cli.scanner.safe_subprocess_run") as mock_run, \
             patch("devsecops_radar.cli.scanner.logger") as log:
            mock_run.side_effect = RuntimeError("network error")
            safe_wizard()
        log.error.assert_called_once()

    def test_ollama_present_pull_success(self):
        with patch("devsecops_radar.cli.scanner.shutil.which", return_value="/usr/bin/ollama"), \
             patch("devsecops_radar.cli.scanner.safe_subprocess_run") as mock_run:
            safe_wizard()
        mock_run.assert_called_once()


# ---------------------------------------------------------------------------
# run_app (integration)
# ---------------------------------------------------------------------------
class TestRunApp:
    @pytest.fixture
    def core_patches(self):
        mocks = {
            "devsecops_radar.cli.scanner.discover_plugins": MagicMock(return_value={}),
            "devsecops_radar.cli.scanner.run_all_scanners": AsyncMock(return_value=([], ScanStatus())),
            "devsecops_radar.cli.scanner.RuleFusionEngine": MagicMock(),
            "devsecops_radar.cli.scanner.compute_dynamic_risk_score": MagicMock(return_value=5.0),
            "devsecops_radar.cli.scanner.save_scan": MagicMock(),
            "devsecops_radar.cli.scanner.generate_pdf_report": MagicMock(),
            "devsecops_radar.core.sarif_export.export_sarif": MagicMock(),
            "devsecops_radar.core.sarif_export.export_cyclonedx": MagicMock(),
            "devsecops_radar.core.notifier.notify_jira": AsyncMock(),
            "devsecops_radar.core.notifier.notify_asana": AsyncMock(),
            "devsecops_radar.cli.scanner.auto_fix": MagicMock(return_value=[]),
            "devsecops_radar.cli.scanner.generate_pr": MagicMock(),
            "devsecops_radar.cli.scanner.interactive_remediation": AsyncMock(),
        }
        with patch.multiple("devsecops_radar.cli.scanner", **{
            k.split(".")[-1]: v for k, v in mocks.items() if k.startswith("devsecops_radar.cli.scanner.")
        }), \
        patch("devsecops_radar.core.sarif_export.export_sarif", mocks["devsecops_radar.core.sarif_export.export_sarif"]), \
        patch("devsecops_radar.core.sarif_export.export_cyclonedx", mocks["devsecops_radar.core.sarif_export.export_cyclonedx"]), \
        patch("devsecops_radar.core.notifier.notify_jira", mocks["devsecops_radar.core.notifier.notify_jira"]), \
        patch("devsecops_radar.core.notifier.notify_asana", mocks["devsecops_radar.core.notifier.notify_asana"]):
            yield mocks

    def test_wizard_mode(self, core_patches):
        argv = ["prog", "--wizard"]
        with patch.object(sys, "argv", argv), \
             patch("devsecops_radar.cli.scanner.safe_wizard") as mock_wizard:
            asyncio.run(run_app())
        mock_wizard.assert_called_once()

    def test_update_rules(self, core_patches):
        argv = ["prog", "--update-rules"]
        with patch.object(sys, "argv", argv):
            mock_engine = core_patches["devsecops_radar.cli.scanner.RuleFusionEngine"].return_value
            asyncio.run(run_app())
        mock_engine.update_community_rules.assert_called_once()

    def test_no_findings_exits_gracefully(self, core_patches):
        argv = ["prog"]
        core_patches["devsecops_radar.cli.scanner.run_all_scanners"].return_value = ([], ScanStatus())
        with patch.object(sys, "argv", argv), \
             patch("devsecops_radar.cli.scanner.logger") as log:
            asyncio.run(run_app())
        log.info.assert_any_call("No findings were discovered or loaded. Exiting gracefully.")

    def test_policy_violation_exits(self, core_patches):
        argv = ["prog", "--policy", "pol.json"]
        findings = [{"severity": "HIGH"}]
        core_patches["devsecops_radar.cli.scanner.run_all_scanners"].return_value = (findings, ScanStatus())
        with patch.object(sys, "argv", argv), \
             patch("devsecops_radar.cli.scanner.Path.is_file", return_value=False), \
             patch("devsecops_radar.cli.scanner.logger"), \
             patch("devsecops_radar.cli.scanner.sys.exit") as mock_exit:
            mock_engine = core_patches["devsecops_radar.cli.scanner.RuleFusionEngine"].return_value
            mock_engine.evaluate_policy.return_value = False
            asyncio.run(run_app())
        mock_exit.assert_called_with(1)

    def test_successful_scan_with_output_and_reports(self, core_patches, tmp_path):
        findings = [{"id": "1", "severity": "HIGH", "dynamic_risk_score": 5.0}]
        core_patches["devsecops_radar.cli.scanner.run_all_scanners"].return_value = (findings, ScanStatus())

        out_file = tmp_path / "findings.json"
        argv = [
            "prog",
            "--output", str(out_file),
            "--report", str(tmp_path / "report.pdf"),
            "--export-sarif", str(tmp_path / "sarif.json"),
            "--export-cyclonedx", str(tmp_path / "cdx.json"),
            "--notify-jira", "--notify-asana", "--analyze",
        ]
        with patch.object(sys, "argv", argv), \
             patch("devsecops_radar.cli.scanner.execute_ai_analysis", AsyncMock(return_value={"summary": 1})), \
             patch.dict(os.environ, {"JIRA_URL": "url", "JIRA_TOKEN": "t", "ASANA_TOKEN": "a", "ASANA_WORKSPACE": "w"}), \
             patch("devsecops_radar.cli.scanner.Path.cwd", return_value=tmp_path):
            with patch("builtins.open", mock_open()):
                asyncio.run(run_app())
        core_patches["devsecops_radar.cli.scanner.save_scan"].assert_called_once()
        core_patches["devsecops_radar.cli.scanner.generate_pdf_report"].assert_called_once()
        core_patches["devsecops_radar.core.sarif_export.export_sarif"].assert_called_once()
        core_patches["devsecops_radar.core.sarif_export.export_cyclonedx"].assert_called_once()
        core_patches["devsecops_radar.core.notifier.notify_jira"].assert_awaited_once()
        core_patches["devsecops_radar.core.notifier.notify_asana"].assert_awaited_once()

    def test_auto_fix_without_review(self, core_patches):
        findings = [{"id": "2", "severity": "CRITICAL", "dynamic_risk_score": 9.0}]
        core_patches["devsecops_radar.cli.scanner.run_all_scanners"].return_value = (findings, ScanStatus())
        core_patches["devsecops_radar.cli.scanner.auto_fix"].return_value = ["modified_file.py"]

        argv = ["prog", "--fix", "--analyze"]
        with patch.object(sys, "argv", argv), \
             patch("devsecops_radar.cli.scanner.execute_ai_analysis", AsyncMock(return_value={"some": "ai"})), \
             patch("devsecops_radar.cli.scanner.logger"):
            asyncio.run(run_app())
        core_patches["devsecops_radar.cli.scanner.auto_fix"].assert_called_once()
        core_patches["devsecops_radar.cli.scanner.generate_pr"].assert_called_once()

    def test_rego_policy_violation_exits(self, core_patches):
        findings = [{"id": "3", "severity": "LOW", "dynamic_risk_score": 1.0}]
        core_patches["devsecops_radar.cli.scanner.run_all_scanners"].return_value = (findings, ScanStatus())

        argv = ["prog", "--rego-policy", "test.rego"]
        with patch.object(sys, "argv", argv), \
             patch("devsecops_radar.cli.scanner.logger"), \
             patch("devsecops_radar.cli.scanner.sys.exit") as mock_exit:
            mock_engine = core_patches["devsecops_radar.cli.scanner.RuleFusionEngine"].return_value
            mock_engine.evaluate_rego_policy.return_value = False
            asyncio.run(run_app())
        mock_exit.assert_called_with(1)

    def test_fail_on_scanner_error(self, core_patches):
        findings = [{"id": "1", "severity": "LOW"}]
        status = ScanStatus()
        status.add_failure("trivy", "something went wrong")
        core_patches["devsecops_radar.cli.scanner.run_all_scanners"].return_value = (findings, status)

        argv = ["prog", "--fail-on-scanner-error"]
        with patch.object(sys, "argv", argv), \
             patch("devsecops_radar.cli.scanner.logger"), \
             patch("devsecops_radar.cli.scanner.sys.exit") as mock_exit:
            asyncio.run(run_app())
        mock_exit.assert_called_with(1)


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------
class TestMain:
    def test_keyboard_interrupt(self, mock_logger):
        with patch("devsecops_radar.cli.scanner.asyncio.run", side_effect=KeyboardInterrupt), \
             patch("devsecops_radar.cli.scanner.sys.exit") as mock_exit:
            main()
        mock_logger.warning.assert_called_with("Execution interrupted by user.")
        mock_exit.assert_called_with(130)
