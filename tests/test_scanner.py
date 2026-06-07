import sys
from unittest.mock import AsyncMock, MagicMock, mock_open, patch

import psutil
import pytest

from devsecops_radar.cli.scanner import (
    discover_plugins,
    estimate_analysis,
    execute_ai_analysis,
    get_gpu_status,
    get_system_ram_gb,
    interactive_remediation,
    logger,
    parse_args,
    run_all_scanners,
    run_scanner_async,
    safe_wizard,
    sort_findings_by_risk,
)


# ------------------------------------------------------------
# get_system_ram_gb
# ------------------------------------------------------------
class TestGetSystemRamGb:
    def test_success(self):
        with patch.object(psutil, "virtual_memory") as mock_vm:
            mock_vm.return_value.total = 8 * 1024**3
            assert get_system_ram_gb() == 8.0

    def test_failure_returns_fallback(self):
        with patch.object(psutil, "virtual_memory", side_effect=Exception("no mem")), \
             patch.object(logger, "debug") as mock_debug:
            assert get_system_ram_gb() == 4.0
            mock_debug.assert_called_once()


# ------------------------------------------------------------
# get_gpu_status
# ------------------------------------------------------------
class TestGetGpuStatus:
    @pytest.mark.parametrize("sys_os, nvidia_return, sysctl_stdout, expected", [
        ("Windows", 0, None, True),
        ("Windows", 1, None, False),
        ("Linux", 0, None, True),
        ("Darwin", None, "Apple M1 Pro", True),
        ("Darwin", None, "Intel Core i7", False),
        ("Other", None, None, False),
    ])
    def test_variations(self, sys_os, nvidia_return, sysctl_stdout, expected):
        with patch("platform.system", return_value=sys_os), \
             patch("subprocess.run") as mock_run:
            if sys_os in ["Windows", "Linux"]:
                mock_run.return_value.returncode = nvidia_return
            elif sys_os == "Darwin":
                mock_run.return_value.stdout = sysctl_stdout
            assert get_gpu_status() == expected

    def test_exception_returns_false(self):
        with patch("platform.system", side_effect=Exception):
            assert get_gpu_status() is False


# ------------------------------------------------------------
# estimate_analysis
# ------------------------------------------------------------
class TestEstimateAnalysis:
    @pytest.fixture(autouse=True)
    def mocks(self):
        # patch functions and store the mocks, not the patcher
        self._ram = patch("devsecops_radar.cli.scanner.get_system_ram_gb", return_value=16.0)
        self._gpu = patch("devsecops_radar.cli.scanner.get_gpu_status", return_value=True)
        self._cores = patch.object(psutil, "cpu_count", return_value=8)
        self._info = patch.object(logger, "info")
        self._warn = patch.object(logger, "warning")
        self._error = patch.object(logger, "error")

        # start and save the mock objects
        self.mock_ram = self._ram.start()
        self.mock_gpu = self._gpu.start()
        self.mock_cores = self._cores.start()
        self.mock_info = self._info.start()
        self.mock_warn = self._warn.start()
        self.mock_error = self._error.start()
        yield
        self._ram.stop()
        self._gpu.stop()
        self._cores.stop()
        self._info.stop()
        self._warn.stop()
        self._error.stop()

    def test_litellm_backend(self):
        can_run, time_est, chunk, hw = estimate_analysis(20, "gpt-4", "litellm")
        assert can_run is True
        assert chunk == 10
        assert hw == "Cloud Engine"
        assert time_est == 5.0 + 20 * 0.5

    def test_local_gpu_present(self):
        can_run, time_est, chunk, hw = estimate_analysis(10, "llama3.2", "ollama")
        assert can_run is True
        assert hw == "Local GPU (Accelerated)"
        assert time_est == 10 * 2.0

    def test_local_no_gpu_warning(self):
        self.mock_gpu.return_value = False
        can_run, _, _, _ = estimate_analysis(5, "llama3.2", "ollama")
        assert can_run is True
        self.mock_warn.assert_any_call(
            "WARNING: No GPU detected. Local AI analysis will be slow. Consider using --llm-backend litellm."
        )

    def test_low_ram_fatal_no_force(self):
        self.mock_ram.return_value = 3.0
        self.mock_gpu.return_value = False
        can_run, _, chunk, hw = estimate_analysis(5, "llama3.2", "ollama", force_ai=False)
        assert can_run is False
        self.mock_error.assert_any_call(
            "FATAL: System RAM < 4GB. Aborting local LLM to prevent system crash. Use --force-ai to override."
        )

    def test_low_ram_force_ai(self):
        self.mock_ram.return_value = 3.0
        self.mock_gpu.return_value = False
        can_run, _, chunk, _ = estimate_analysis(5, "llama3.2", "ollama", force_ai=True)
        assert can_run is True
        self.mock_warn.assert_any_call("WARNING: Force AI active on low RAM. Risk of freezing.")
        assert chunk == 2

    def test_ram_between_4_and_8(self):
        self.mock_ram.return_value = 6.0
        self.mock_gpu.return_value = False
        can_run, _, chunk, _ = estimate_analysis(5, "llama3.2", "ollama")
        assert can_run is True
        assert chunk == 3


# ------------------------------------------------------------
# discover_plugins
# ------------------------------------------------------------
class TestDiscoverPlugins:
    def test_loads_plugins(self):
        fake_plugin = MagicMock()
        fake_plugin.name = "test-plugin"
        fake_entry = MagicMock()
        fake_entry.load.return_value = fake_plugin
        with patch("devsecops_radar.cli.scanner.entry_points", return_value=[fake_entry]):
            result = discover_plugins()
            assert "test-plugin" in result

    def test_load_failure(self):
        with patch("devsecops_radar.cli.scanner.entry_points", side_effect=Exception("boom")), \
             patch.object(logger, "error") as mock_error:
            result = discover_plugins()
            assert result == {}
            mock_error.assert_called_once()


# ------------------------------------------------------------
# parse_args
# ------------------------------------------------------------
class TestParseArgs:
    def test_defaults(self):
        with patch.object(sys, "argv", ["prog"]):
            args = parse_args()
            assert args.output == "findings.json"
            assert args.analyze is False
            assert args.llm_backend == "ollama"
            assert args.llm_model == "llama3.2"


# ------------------------------------------------------------
# run_scanner_async
# ------------------------------------------------------------
class TestRunScannerAsync:
    @pytest.mark.asyncio
    async def test_parse_file(self, tmp_path):
        file_path = tmp_path / "report.json"
        file_path.write_text("{}")
        adapter = MagicMock()
        adapter.parse.return_value = [MagicMock()]
        adapter.parse.return_value[0].model_dump.return_value = {"finding": "test"}
        with patch.object(logger, "info") as mock_info:
            result = await run_scanner_async("testscanner", str(file_path), adapter)
            assert result == [{"finding": "test"}]
            mock_info.assert_called_with(f"Parsing testscanner report: {file_path}")

    @pytest.mark.asyncio
    async def test_run_scan(self):
        adapter = MagicMock()
        adapter.run.return_value = [MagicMock()]
        adapter.run.return_value[0].model_dump.return_value = {"finding": "run"}
        with patch.object(logger, "info") as mock_info:
            result = await run_scanner_async("test", "/some/path", adapter)
            assert result == [{"finding": "run"}]
            mock_info.assert_called_with("Running test scan on: /some/path")

    @pytest.mark.asyncio
    async def test_exception(self):
        adapter = MagicMock()
        adapter.run.side_effect = Exception("fail")
        with patch.object(logger, "error") as mock_error:
            result = await run_scanner_async("test", "/path", adapter)
            assert result == []
            mock_error.assert_called_with("test plugin execution failed: fail")


# ------------------------------------------------------------
# run_all_scanners
# ------------------------------------------------------------
class TestRunAllScanners:
    @pytest.mark.asyncio
    async def test_runs_configured(self):
        args = MagicMock()
        args.trivy = "trivy.json"
        args.semgrep = None
        plugins = {"trivy": MagicMock(), "semgrep": MagicMock()}
        with patch("devsecops_radar.cli.scanner.run_scanner_async", new_callable=AsyncMock) as mock_run:
            mock_run.return_value = [{"id": 1}]
            result = await run_all_scanners(args, plugins)
            assert mock_run.call_count == 1
            assert len(result) == 1

    @pytest.mark.asyncio
    async def test_exception_in_task(self):
        args = MagicMock()
        args.trivy = "trivy.json"
        args.semgrep = "semgrep.json"
        plugins = {"trivy": MagicMock(), "semgrep": MagicMock()}
        with patch("devsecops_radar.cli.scanner.run_scanner_async", new_callable=AsyncMock) as mock_run, \
             patch.object(logger, "error") as mock_error:
            mock_run.side_effect = [Exception("boom"), [{"id": 2}]]
            result = await run_all_scanners(args, plugins)
            assert result == [{"id": 2}]
            mock_error.assert_called_once()


# ------------------------------------------------------------
# sort_findings_by_risk
# ------------------------------------------------------------
class TestSortFindingsByRisk:
    def test_ordering(self):
        findings = [
            {"severity": "LOW", "dynamic_risk_score": 10},
            {"severity": "CRITICAL", "dynamic_risk_score": 5},
            {"severity": "MEDIUM", "dynamic_risk_score": 0},
            {"severity": "HIGH"},
        ]
        sorted_f = sort_findings_by_risk(findings)
        assert sorted_f[0]["severity"] == "CRITICAL"
        assert sorted_f[1]["severity"] == "HIGH"
        assert sorted_f[2]["severity"] == "MEDIUM"
        assert sorted_f[3]["severity"] == "LOW"


# ------------------------------------------------------------
# execute_ai_analysis
# ------------------------------------------------------------
class TestExecuteAiAnalysis:
    @pytest.fixture
    def base_args(self):
        args = MagicMock()
        args.analyze = True
        args.llm_backend = "ollama"
        args.llm_model = "llama3.2"
        args.force_ai = False
        args.output = "output.json"
        return args

    @pytest.mark.asyncio
    async def test_no_analyze_flag(self, base_args):
        base_args.analyze = False
        result = await execute_ai_analysis(base_args, [{"id": "1"}], {})
        assert result == {}

    @pytest.mark.asyncio
    async def test_no_findings(self, base_args):
        result = await execute_ai_analysis(base_args, [], {})
        assert result == {}

    @pytest.mark.asyncio
    async def test_success_flow(self, base_args):
        findings = [{"severity": "HIGH", "dynamic_risk_score": 8.0} for _ in range(5)]
        topology = {"key": "value"}
        ai_result = {"risk_score": 75, "executive_summary": "ok"}
        with patch("devsecops_radar.cli.scanner.sort_findings_by_risk", return_value=findings), \
             patch("devsecops_radar.cli.scanner.estimate_analysis", return_value=(True, 10, 10, "GPU")), \
             patch("devsecops_radar.cli.scanner.get_analyzer") as mock_get_analyzer, \
             patch("builtins.open", mock_open()), \
             patch("json.dump") as mock_json_dump, \
             patch("devsecops_radar.cli.scanner.time.time", side_effect=[100, 115]):
            analyzer = MagicMock()
            analyzer.run = AsyncMock(return_value=ai_result)
            mock_get_analyzer.return_value = analyzer

            result = await execute_ai_analysis(base_args, findings, topology)

            assert result["risk_score"] == 75
            assert result["execution_time"] == "15s"
            assert result["hardware_profile"] == "GPU"
            mock_json_dump.assert_called_once()
            assert mock_json_dump.call_args[0][0] == ai_result

    @pytest.mark.asyncio
    async def test_analysis_aborted_due_to_resources(self, base_args):
        findings = [{"severity": "LOW"}]
        with patch("devsecops_radar.cli.scanner.sort_findings_by_risk", return_value=findings), \
             patch("devsecops_radar.cli.scanner.estimate_analysis", return_value=(False, 0, 5, "CPU")), \
             patch("builtins.open", mock_open()), \
             patch("json.dump") as mock_json_dump:
            result = await execute_ai_analysis(base_args, findings, {})
            assert result["executive_summary"] == "Analysis aborted due to low system resources. Use --force-ai to bypass."
            assert result["risk_score"] == 0.0
            mock_json_dump.assert_called_once()
            fallback = mock_json_dump.call_args[0][0]
            assert fallback["risk_score"] == 0.0

    @pytest.mark.asyncio
    async def test_ai_engine_crash(self, base_args):
        findings = [{"severity": "LOW"}]
        with patch("devsecops_radar.cli.scanner.sort_findings_by_risk", return_value=findings), \
             patch("devsecops_radar.cli.scanner.estimate_analysis", return_value=(True, 10, 10, "GPU")), \
             patch("devsecops_radar.cli.scanner.get_analyzer") as mock_get_analyzer, \
             patch.object(logger, "error") as mock_error:
            analyzer = MagicMock()
            analyzer.run = AsyncMock(side_effect=Exception("crash"))
            mock_get_analyzer.return_value = analyzer
            result = await execute_ai_analysis(base_args, findings, {})
            assert result == {}
            mock_error.assert_called_with("AI Engine crashed during analysis: crash")


# ------------------------------------------------------------
# interactive_remediation
# ------------------------------------------------------------
class TestInteractiveRemediation:
    def test_no_remediations(self):
        with patch.object(logger, "info") as mock_info:
            interactive_remediation([], {"top_remediations": []})
            mock_info.assert_called_with("No AI remediations available to apply.")

    def test_patch_review_accept_and_reject(self):
        ai_summary = {
            "top_remediations": [
                {"finding_id": "F1", "patch_content": "patch1", "title": "Fix 1", "remediation_steps": ["step"]},
                {"finding_id": "F2", "patch_content": "patch2", "title": "Fix 2", "remediation_steps": []},
            ]
        }
        with patch("builtins.input", side_effect=["y", "n"]), \
             patch.object(logger, "info"), \
             patch.object(logger, "success"), \
             patch("devsecops_radar.cli.scanner.generate_remediation_guide", return_value="guide"), \
             patch("devsecops_radar.cli.scanner.auto_fix") as mock_auto_fix, \
             patch("devsecops_radar.cli.scanner.generate_pr") as mock_generate_pr:
            interactive_remediation([], ai_summary)
            call_args = mock_auto_fix.call_args[0]
            assert len(call_args[1]["top_remediations"]) == 1
            assert call_args[1]["top_remediations"][0]["finding_id"] == "F1"
            mock_generate_pr.assert_called_once()

    def test_quit_early(self):
        ai_summary = {
            "top_remediations": [
                {"finding_id": "F1", "patch_content": "patch1", "title": "Fix 1"}
            ]
        }
        with patch("builtins.input", return_value="q"), \
             patch.object(logger, "info"), \
             patch.object(logger, "warning"), \
             patch("devsecops_radar.cli.scanner.generate_remediation_guide", return_value="guide"), \
             patch("devsecops_radar.cli.scanner.auto_fix") as mock_auto_fix:
            interactive_remediation([], ai_summary)
            mock_auto_fix.assert_not_called()


# ------------------------------------------------------------
# safe_wizard
# ------------------------------------------------------------
class TestSafeWizard:
    def test_ollama_not_installed(self):
        mock_shutil = MagicMock()
        mock_shutil.which.return_value = None
        with patch.dict("devsecops_radar.cli.scanner.__dict__", {"shutil": mock_shutil}), \
             patch("platform.system", return_value="Darwin"), \
             patch.object(logger, "warning") as mock_warn, \
             patch.object(logger, "info") as mock_info:
            safe_wizard()
            mock_warn.assert_called_with("Ollama is not installed.")
            mock_info.assert_any_call("Please install via Homebrew: brew install ollama")

    def test_ollama_present_pull_success(self):
        mock_shutil = MagicMock()
        mock_shutil.which.return_value = "/usr/local/bin/ollama"
        with patch.dict("devsecops_radar.cli.scanner.__dict__", {"shutil": mock_shutil}), \
             patch("subprocess.run") as mock_run, \
             patch.object(logger, "info"), \
             patch.object(logger, "success") as mock_success:
            safe_wizard()
            mock_run.assert_called_with(['ollama', 'pull', 'llama3.2:latest'], check=True)
            mock_success.assert_called_with("Setup complete! You are ready to scan.")

    def test_pull_failure(self):
        mock_shutil = MagicMock()
        mock_shutil.which.return_value = "/usr/bin/ollama"
        with patch.dict("devsecops_radar.cli.scanner.__dict__", {"shutil": mock_shutil}), \
             patch("subprocess.run", side_effect=Exception("fail")), \
             patch.object(logger, "info"), \
             patch.object(logger, "error") as mock_error:
            safe_wizard()
            mock_error.assert_called_with("Failed to pull AI model: fail")
