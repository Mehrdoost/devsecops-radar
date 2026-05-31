from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from devsecops_radar.core.analyzer import (
    LiteLLMAnalyzer,
    OllamaAnalyzer,
    extract_json,
    select_findings_for_llm,
)


@pytest.mark.asyncio
async def test_ollama_success():
    analyzer = OllamaAnalyzer()
    findings = [{"severity": "CRITICAL", "id": "1", "tool": "test"}]
    mock_response = MagicMock()
    mock_response.json.return_value = {
        "response": '{"executive_summary": "ok", "attack_paths": [], "top_remediations": []}'
    }
    mock_response.raise_for_status = MagicMock()
    with patch('httpx.AsyncClient.post', new_callable=AsyncMock) as mock_post:
        mock_post.return_value = mock_response
        result = await analyzer.analyze(findings)
        assert result["executive_summary"] == "ok"


@pytest.mark.asyncio
async def test_ollama_timeout():
    analyzer = OllamaAnalyzer()
    findings = [{"severity": "CRITICAL", "id": "1"}]
    with patch('httpx.AsyncClient.post', new_callable=AsyncMock) as mock_post:
        mock_post.side_effect = httpx.TimeoutException("timeout")
        result = await analyzer.analyze(findings)
        assert "timed out" in result["executive_summary"]


@pytest.mark.asyncio
async def test_litellm_success():
    analyzer = LiteLLMAnalyzer(model="gpt-3.5-turbo")
    findings = [{"severity": "HIGH", "id": "1"}]
    mock_response = MagicMock()
    mock_response.choices = [MagicMock()]
    mock_response.choices[0].message.content = '{"executive_summary": "ok", "attack_paths": [], "top_remediations": []}'
    with patch.object(analyzer, 'litellm', create=True) as mock_litellm:
        mock_litellm.acompletion = AsyncMock(return_value=mock_response)
        result = await analyzer.analyze(findings)
        assert result["executive_summary"] == "ok"


def test_extract_json_valid():
    assert extract_json('{"a":1}') == {"a": 1}


def test_extract_json_invalid():
    res = extract_json("not json")
    assert "executive_summary" in res


def test_select_findings_truncation():
    findings = [{"severity": "CRITICAL"}] * 120 + [{"severity": "LOW"}] * 50
    selected = select_findings_for_llm(findings, max_items=100)
    assert len(selected) == 100
    assert all(f["severity"] == "CRITICAL" for f in selected)
