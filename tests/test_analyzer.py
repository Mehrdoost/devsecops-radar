import pytest
from unittest.mock import MagicMock, patch

from devsecops_radar.core.analyzer import (
    OllamaAnalyzer,
    extract_json,
    select_findings_for_llm,
)


def test_extract_json_plain():
    text = '{"executive_summary": "test", "attack_paths": [], "top_remediations": []}'
    result = extract_json(text)
    assert result["executive_summary"] == "test"


def test_extract_json_malformed():
    result = extract_json("some text {invalid")
    assert "executive_summary" in result


def test_select_findings_for_llm():
    findings = [{"severity": "CRITICAL"}] * 120 + [{"severity": "LOW"}] * 50
    selected = select_findings_for_llm(findings, max_items=100)
    assert len(selected) == 100
    criticals = [f for f in selected if f["severity"] == "CRITICAL"]
    assert len(criticals) == 100


@pytest.mark.asyncio
@patch('httpx.AsyncClient.post')
async def test_ollama_analyzer_success(mock_post):
    mock_response = MagicMock()
    mock_response.json.return_value = {
        "response": (
            '{"executive_summary": "ok", '
            '"attack_paths": [], '
            '"top_remediations": []}'
        )
    }
    mock_response.raise_for_status.return_value = None
    mock_post.return_value = mock_response
    analyzer = OllamaAnalyzer()
    findings = [{"severity": "CRITICAL", "id": "1", "tool": "test"}]
    analysis = await analyzer.analyze(findings)
    assert analysis["executive_summary"] == "ok"


@pytest.mark.asyncio
@patch('httpx.AsyncClient.post')
async def test_ollama_analyzer_network_error(mock_post):
    mock_post.side_effect = Exception("Network down")
    analyzer = OllamaAnalyzer()
    findings = [{"severity": "CRITICAL", "id": "1", "tool": "test"}]
    analysis = await analyzer.analyze(findings)
    assert "AI failed" in analysis["executive_summary"]