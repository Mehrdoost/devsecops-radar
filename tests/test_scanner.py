import argparse
import tempfile
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from devsecops_radar.cli.scanner import (
    discover_plugins,
    load_custom_rules,
    parse_args,
    run_analysis,
    run_policy_check,
    save_results,
    wizard,
)


def test_parse_args():
    args = parse_args()
    assert args.output == 'findings.json'
    assert args.analyze is False


def test_discover_plugins():
    plugins = discover_plugins()
    assert 'trivy' in plugins
    assert 'semgrep' in plugins


def test_save_results_creates_file():
    findings = [{"id": "1", "severity": "HIGH"}]
    with tempfile.NamedTemporaryFile(suffix='.json', delete=False) as f:
        out = f.name
    args = argparse.Namespace(output=out)
    with patch('devsecops_radar.cli.scanner.save_scan') as mock_save:
        save_results(args, findings)
        import json
        with open(out) as f:
            data = json.load(f)
        assert len(data) == 1
        mock_save.assert_called_once()


def test_load_custom_rules_no_rules():
    args = argparse.Namespace(rules=None)
    assert load_custom_rules(args) == []


@patch('devsecops_radar.cli.scanner.RuleFusion')
def test_load_custom_rules_with_dir(mock_rf):
    mock_rf.return_value.load_all_rules.return_value = [{"id": "r1"}]
    args = argparse.Namespace(rules="/tmp/dummy")
    result = load_custom_rules(args)
    assert len(result) == 1


def test_run_policy_check_pass():
    findings = [{"severity": "CRITICAL"}] * 2
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        f.write('{"max_critical": 5, "on_violation": "fail"}')
        policy_file = f.name
    args = argparse.Namespace(policy=policy_file, rego_policy=None)
    run_policy_check(args, findings)  # should not exit


@pytest.mark.asyncio
@patch('devsecops_radar.cli.scanner.get_analyzer')
async def test_run_analysis(mock_get_analyzer):
    mock_analyzer = MagicMock()
    mock_analyzer.analyze = AsyncMock(return_value={"executive_summary": "ok"})
    mock_get_analyzer.return_value = mock_analyzer
    findings = [{"severity": "CRITICAL"}]
    args = argparse.Namespace(analyze=True, llm_backend='ollama', llm_model=None, output='findings.json')
    result = await run_analysis(args, findings)
    assert result["executive_summary"] == "ok"


def test_wizard(monkeypatch):
    monkeypatch.setattr('subprocess.run', lambda *args, **kwargs: None)
    monkeypatch.setattr('builtins.input', lambda _: 'y')
    monkeypatch.setattr('builtins.print', lambda *args, **kwargs: None)
    try:
        wizard()
    except SystemExit:
        pass
