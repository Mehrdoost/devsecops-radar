from unittest.mock import MagicMock, patch

import httpx
import pytest

from devsecops_radar.core.analyzer import (
    OllamaAnalyzer,
    extract_json,
    merge_analyses,
)


def test_extract_json_plain():
    text = '{"executive_summary": "test", "attack_paths": [], "top_remediations": []}'
    result = extract_json(text)
    assert result["executive_summary"] == "test"


def test_extract_json_malformed():
    result = extract_json("some text {invalid")
    assert "executive_summary" in result


def test_merge_analyses():
    empty_result = merge_analyses([])
    assert empty_result["risk_score"] == 0
    assert "No analysis" in empty_result["executive_summary"]

    analyses = [
        {
            "executive_summary": "Summary part 1.",
            "attack_paths": [{"id": "PATH-1"}],
            "top_remediations": [{"id": "REM-1"}],
            "risk_score": 60
        },
        {
            "executive_summary": "Summary part 2.",
            "attack_paths": [{"id": "PATH-2"}],
            "top_remediations": [],
            "risk_score": 95
        }
    ]
    merged = merge_analyses(analyses)
    assert "Composite Summary:" in merged["executive_summary"]
    assert "Summary part 1." in merged["executive_summary"]
    assert len(merged["attack_paths"]) == 2
    assert len(merged["top_remediations"]) == 1
    assert merged["risk_score"] == 95


@pytest.mark.asyncio
@patch('httpx.AsyncClient.post')
async def test_ollama_analyzer_success(mock_post):
    mock_response = MagicMock()
    mock_response.json.return_value = {
        "response": (
            '{"executive_summary": "ok", '
            '"attack_paths": [], '
            '"top_remediations": [], '
            '"risk_score": 40}'
        )
    }
    mock_response.raise_for_status.return_value = None
    mock_post.return_value = mock_response

    analyzer = OllamaAnalyzer()
    findings = [{"severity": "CRITICAL", "id": "1", "tool": "test"}]
    analysis = await analyzer.analyze(findings)

    assert analysis["executive_summary"] == "ok"
    assert mock_post.call_count == 1


@pytest.mark.asyncio
@patch('httpx.AsyncClient.post')
async def test_ollama_analyzer_chunking(mock_post):
    mock_response = MagicMock()
    mock_response.json.return_value = {
        "response": (
            '{"executive_summary": "chunk_ok", '
            '"attack_paths": [{"id": "TEST"}], '
            '"top_remediations": [], '
            '"risk_score": 50}'
        )
    }
    mock_response.raise_for_status.return_value = None
    mock_post.return_value = mock_response

    analyzer = OllamaAnalyzer()
    findings = [{"id": str(i)} for i in range(5)]

    analysis = await analyzer.analyze(findings, chunk_size=2)

    assert mock_post.call_count == 3
    assert "Composite Summary" in analysis["executive_summary"]
    assert len(analysis["attack_paths"]) == 3
    assert analysis["risk_score"] == 50


@pytest.mark.asyncio
@patch('httpx.AsyncClient.post')
async def test_ollama_analyzer_timeout_error(mock_post):
    mock_post.side_effect = httpx.TimeoutException("Timeout")
    analyzer = OllamaAnalyzer()
    findings = [{"severity": "CRITICAL", "id": "1", "tool": "test"}]

    analysis = await analyzer.analyze(findings)
    assert "timed out" in analysis["executive_summary"]


@pytest.mark.asyncio
@patch('httpx.AsyncClient.post')
async def test_ollama_analyzer_connect_error(mock_post):
    mock_post.side_effect = httpx.ConnectError("Connection refused")
    analyzer = OllamaAnalyzer()
    findings = [{"severity": "CRITICAL", "id": "1", "tool": "test"}]

    analysis = await analyzer.analyze(findings)
    assert "Cannot connect to Ollama" in analysis["executive_summary"]


@pytest.mark.asyncio
@patch('httpx.AsyncClient.post')
async def test_ollama_analyzer_generic_error(mock_post):
    mock_post.side_effect = Exception("Unknown internal error")
    analyzer = OllamaAnalyzer()
    findings = [{"severity": "CRITICAL", "id": "1", "tool": "test"}]

    analysis = await analyzer.analyze(findings)
    assert "AI failed: Unknown internal error" in analysis["executive_summary"]
