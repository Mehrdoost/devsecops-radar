import argparse
import sys
import tempfile
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from devsecops_radar.cli.scanner import (
    discover_plugins,
    estimate_analysis,
    get_gpu_status,
    get_safe_chunk_size,
    get_system_ram_gb,
    load_custom_rules,
    parse_args,
    run_analysis,
    run_policy_check,
    save_results,
    wizard,
)


def test_parse_args(monkeypatch):
    monkeypatch.setattr(sys, "argv", ["prog"])
    args = parse_args()
    assert args.output == "findings.json"
    assert args.analyze is False
    assert args.force_ai is False


def test_discover_plugins():
    plugins = discover_plugins()
    assert "trivy" in plugins
    assert "semgrep" in plugins


def test_save_results_creates_file():
    findings = [{"id": "1", "severity": "HIGH"}]
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
        out = f.name
    args = argparse.Namespace(output=out)
    with patch("devsecops_radar.cli.scanner.save_scan") as mock_save:
        save_results(args, findings)
        import json

        with open(out) as f:
            data = json.load(f)
        assert len(data) == 1
        mock_save.assert_called_once()


def test_load_custom_rules_no_rules():
    args = argparse.Namespace(rules=None)
    assert load_custom_rules(args) == []


@patch("devsecops_radar.cli.scanner.RuleFusion")
def test_load_custom_rules_with_dir(mock_rf):
    mock_rf.return_value.load_all_rules.return_value = [{"id": "r1"}]
    args = argparse.Namespace(rules="/tmp/dummy")
    result = load_custom_rules(args)
    assert len(result) == 1


def test_run_policy_check_pass():
    findings = [{"severity": "CRITICAL"}] * 2
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        f.write('{"max_critical": 5, "on_violation": "fail"}')
        policy_file = f.name
    args = argparse.Namespace(policy=policy_file, rego_policy=None)
    run_policy_check(args, findings)


@patch("platform.system", return_value="UnknownOS")
def test_get_system_ram_gb_unknown(mock_system):
    assert get_system_ram_gb() is None


@patch("platform.system", return_value="UnknownOS")
def test_get_gpu_status_unknown(mock_system):
    assert get_gpu_status() is False


def test_get_safe_chunk_size():
    assert get_safe_chunk_size(8.0, True, 50, "litellm") == 0
    assert get_safe_chunk_size(None, False, 50, "ollama") == 5
    assert get_safe_chunk_size(2.0, False, 50, "ollama") == 2
    assert get_safe_chunk_size(6.0, False, 50, "ollama") == 5
    assert get_safe_chunk_size(12.0, False, 50, "ollama") == 10
    assert get_safe_chunk_size(32.0, True, 50, "ollama") == 0


@patch("devsecops_radar.cli.scanner.get_system_ram_gb", return_value=16.0)
@patch("devsecops_radar.cli.scanner.get_gpu_status", return_value=True)
def test_estimate_analysis_optimal(mock_gpu, mock_ram):
    can_run, est_seconds, chunk_size, hw_type = estimate_analysis(10, "llama3.2", "ollama", False)
    assert can_run is True
    assert chunk_size == 0
    assert "GPU" in hw_type


@patch("devsecops_radar.cli.scanner.get_system_ram_gb", return_value=2.0)
@patch("devsecops_radar.cli.scanner.get_gpu_status", return_value=False)
def test_estimate_analysis_fatal_low_ram(mock_gpu, mock_ram):
    can_run, est_seconds, chunk_size, hw_type = estimate_analysis(10, "llama3.2", "ollama", False)
    assert can_run is False


@patch("devsecops_radar.cli.scanner.get_system_ram_gb", return_value=2.0)
@patch("devsecops_radar.cli.scanner.get_gpu_status", return_value=False)
def test_estimate_analysis_force_ai_low_ram(mock_gpu, mock_ram):
    can_run, est_seconds, chunk_size, hw_type = estimate_analysis(10, "llama3.2", "ollama", True)
    assert can_run is True
    assert chunk_size == 2


@pytest.mark.asyncio
@patch("devsecops_radar.cli.scanner.get_analyzer")
@patch("devsecops_radar.cli.scanner.estimate_analysis")
async def test_run_analysis_success(mock_estimate, mock_get_analyzer):
    mock_estimate.return_value = (True, 60, 0, "Local GPU")
    mock_analyzer = MagicMock()
    mock_analyzer.analyze = AsyncMock(return_value={"executive_summary": "ok"})
    mock_get_analyzer.return_value = mock_analyzer

    findings = [{"severity": "CRITICAL"}]
    args = argparse.Namespace(
        analyze=True, llm_backend="ollama", llm_model="test", output="findings.json", force_ai=False
    )
    result = await run_analysis(args, findings)
    assert result["executive_summary"] == "ok"
    assert "execution_time" in result


@pytest.mark.asyncio
@patch("devsecops_radar.cli.scanner.estimate_analysis")
async def test_run_analysis_aborted_due_to_hardware(mock_estimate):
    mock_estimate.return_value = (False, 0, 2, "Local CPU")
    findings = [{"severity": "CRITICAL"}]
    args = argparse.Namespace(
        analyze=True, llm_backend="ollama", llm_model="test", output="findings.json", force_ai=False
    )
    result = await run_analysis(args, findings)
    assert "aborted" in result["executive_summary"]
    assert len(result["attack_paths"]) == 0


def test_wizard(monkeypatch):
    monkeypatch.setattr("subprocess.run", lambda *args, **kwargs: None)
    monkeypatch.setattr("builtins.input", lambda _: "y")
    monkeypatch.setattr("builtins.print", lambda *args, **kwargs: None)
    try:
        wizard()
    except SystemExit:
        pass
