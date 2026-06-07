import json
import os
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest
from pydantic import ValidationError

from devsecops_radar.core.analyzer import (
    AIAnalysisResponse,
    AIAnalyzer,
    AttackPath,
    LiteLLMAnalyzer,
    OllamaAnalyzer,
    Remediation,
    get_analyzer,
    logger,
)


# ------------------------- Pydantic Models -------------------------
class TestAttackPath:
    def test_valid(self):
        ap = AttackPath(title="T1", description="desc", impact="high")
        assert ap.title == "T1"

    def test_missing_fields_raises(self):
        with pytest.raises(ValidationError):
            AttackPath(title="only title")


class TestRemediation:
    def test_valid(self):
        r = Remediation(
            finding_id="F-1",
            title="Fix X",
            remediation_steps=["step1", "step2"],
        )
        assert r.finding_id == "F-1"
        assert len(r.remediation_steps) == 2

    def test_missing_fields_raises(self):
        with pytest.raises(ValidationError):
            Remediation(title="only title")


class TestAIAnalysisResponse:
    def test_valid_full(self):
        data = {
            "executive_summary": "All good",
            "risk_score": 42.5,
            "attack_paths": [{"title": "X", "description": "Y", "impact": "Z"}],
            "top_remediations": [
                {"finding_id": "1", "title": "Fix", "remediation_steps": ["do this"]}
            ],
        }
        resp = AIAnalysisResponse(**data)
        assert resp.risk_score == 42.5

    def test_risk_score_bounds(self):
        with pytest.raises(ValidationError):
            AIAnalysisResponse(executive_summary="s", risk_score=150)
        with pytest.raises(ValidationError):
            AIAnalysisResponse(executive_summary="s", risk_score=-1)

    def test_default_lists(self):
        resp = AIAnalysisResponse(executive_summary="s", risk_score=0)
        assert resp.attack_paths == []
        assert resp.top_remediations == []


# ------------------------- Dummy for testing base -------------------------
class DummyAnalyzer(AIAnalyzer):
    async def _analyze_chunk(self, prompt: str) -> dict:
        return {"executive_summary": "dummy", "risk_score": 50.0}


# ------------------------- AIAnalyzer base tests -------------------------
class TestValidateModelName:
    def test_valid_names(self):
        assert AIAnalyzer._validate_model_name("gpt-4") == "gpt-4"

    def test_suspicious_name_fallback(self):
        with patch.object(logger, "warning") as mock_warning:
            result = AIAnalyzer._validate_model_name("bad; rm -rf /")
            assert result == "secure-model-fallback"
            mock_warning.assert_called_once()
            assert "Suspicious model name detected" in mock_warning.call_args[0][0]

    def test_empty_name_fallback(self):
        with patch.object(logger, "warning") as mock_warning:
            result = AIAnalyzer._validate_model_name("")
            assert result == "secure-model-fallback"
            mock_warning.assert_called_once()


class TestBuildPrompt:
    def test_basic_structure(self):
        analyzer = DummyAnalyzer("test-model")
        findings = [{"id": "1", "severity": "high"}]
        prompt = analyzer._build_prompt(findings)
        assert "Analyze the following security findings." in prompt
        assert "<FINDINGS_DATA>" in prompt
        # Use same indent as source: indent=2
        assert json.dumps(findings, indent=2) in prompt

    def test_topology_inclusion_and_truncation(self):
        analyzer = DummyAnalyzer("test-model")
        topology = {"nodes": ["a"] * 1000}
        prompt = analyzer._build_prompt([], topology)
        assert "Asset Topology:" in prompt
        assert "... [TRUNCATED]" in prompt

    def test_no_topology(self):
        analyzer = DummyAnalyzer("test-model")
        prompt = analyzer._build_prompt([{"id": "1"}])
        assert "Asset Topology:" not in prompt


class TestExtractAndValidateJson:
    @pytest.fixture
    def analyzer(self):
        return DummyAnalyzer("test-model")

    def test_direct_valid_json(self, analyzer):
        data = {"executive_summary": "ok", "risk_score": 10.0}
        result = analyzer._extract_and_validate_json(json.dumps(data))
        assert result["executive_summary"] == "ok"

    def test_markdown_wrapped_json(self, analyzer):
        raw = '```json\n{"executive_summary": "x", "risk_score": 20}\n```'
        result = analyzer._extract_and_validate_json(raw)
        assert result["executive_summary"] == "x"

    def test_unparsable_text_returns_fallback(self, analyzer):
        with patch.object(logger, "error") as mock_error:
            result = analyzer._extract_and_validate_json("gibberish")
            assert result["executive_summary"] == "Analysis failed due to unparsable AI output."
            assert result["risk_score"] == 0.0
            mock_error.assert_called_once()
            assert "LLM failed to produce parsable JSON" in mock_error.call_args[0][0]

    def test_valid_json_but_bad_schema(self, analyzer):
        bad = json.dumps({"executive_summary": "x", "risk_score": 999})
        with patch.object(logger, "error") as mock_error:
            result = analyzer._extract_and_validate_json(bad)
            assert result["executive_summary"] == "Analysis completed but output formatting was corrupted."
            assert result["risk_score"] == 0.0
            mock_error.assert_called_once()
            assert "LLM output failed strict schema validation" in mock_error.call_args[0][0]


class TestMergeAnalyses:
    def test_empty_list(self):
        merged = DummyAnalyzer("m").merge_analyses([])
        assert merged["executive_summary"] == "No data analyzed."

    def test_single_entry_passed_through(self):
        entry = {"executive_summary": "solo", "risk_score": 55.0}
        assert DummyAnalyzer("m").merge_analyses([entry]) == entry

    def test_average_risk_score(self):
        analyses = [
            {"executive_summary": "a", "risk_score": 10.0},
            {"executive_summary": "b", "risk_score": 20.0},
        ]
        merged = DummyAnalyzer("m").merge_analyses(analyses)
        assert merged["risk_score"] == 15.0

    def test_deduplicate_remediations(self):
        a1 = {
            "executive_summary": "x",
            "risk_score": 0,
            "top_remediations": [
                {"finding_id": "F1", "title": "Fix A", "remediation_steps": ["step"]}
            ],
        }
        a2 = {
            "executive_summary": "y",
            "risk_score": 0,
            "top_remediations": [
                {"finding_id": "F1", "title": "Fix A dup", "remediation_steps": ["another"]},
                {"finding_id": "F2", "title": "Fix B", "remediation_steps": ["do"]},
            ],
        }
        merged = DummyAnalyzer("m").merge_analyses([a1, a2])
        assert len(merged["top_remediations"]) == 2
        ids = [r["finding_id"] for r in merged["top_remediations"]]
        assert ids == ["F1", "F2"]


class TestRun:
    @pytest.mark.asyncio
    async def test_chunking_and_merge(self):
        analyzer = DummyAnalyzer("test")
        findings = [{"id": i} for i in range(25)]
        with patch.object(analyzer, "_analyze_chunk", new_callable=AsyncMock) as mock_chunk:
            mock_chunk.return_value = {"executive_summary": "chunk", "risk_score": 50.0}
            result = await analyzer.run(findings, chunk_size=10)
            assert mock_chunk.call_count == 3
            assert result["executive_summary"].startswith("Composite Analysis:")

    @pytest.mark.asyncio
    async def test_more_than_10_chunks_warning(self):
        analyzer = DummyAnalyzer("test")
        with patch.object(logger, "warning") as mock_warning:
            # 5 chunks → no warning
            await analyzer.run([{"id": i} for i in range(5)], chunk_size=1)
            mock_warning.assert_not_called()
            # 11 chunks → warning
            mock_warning.reset_mock()
            await analyzer.run([{"id": i} for i in range(11)], chunk_size=1)
            mock_warning.assert_called_once()
            assert "High load" in mock_warning.call_args[0][0]

    @pytest.mark.asyncio
    async def test_chunk_exception_isolated(self):
        analyzer = DummyAnalyzer("test")
        findings = [{"id": 1}, {"id": 2}]
        with patch.object(analyzer, "_analyze_chunk", new_callable=AsyncMock) as mock_chunk, \
             patch.object(logger, "error") as mock_error:
            mock_chunk.side_effect = [Exception("fail"), {"executive_summary": "ok", "risk_score": 10}]
            result = await analyzer.run(findings, chunk_size=1)
            assert mock_error.call_count == 1
            assert "Chunk analysis failed" in mock_error.call_args[0][0]
            assert result["executive_summary"] == "ok"


# ------------------------- Helper classes for Ollama tests -------------------------
class MockResponse:
    def __init__(self, json_data, status_code=200):
        self._json = json_data
        self.status_code = status_code

    def raise_for_status(self):
        if self.status_code >= 400:
            raise httpx.HTTPStatusError(
                "error",
                request=MagicMock(),
                response=MagicMock(status_code=self.status_code),
            )

    def json(self):
        return self._json


class MockAsyncClient:
    def __init__(self, response=None, post_side_effect=None):
        self._response = response
        self._post_side_effect = post_side_effect
        self.post_calls = []

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        pass

    async def post(self, *args, **kwargs):
        self.post_calls.append((args, kwargs))
        if self._post_side_effect is not None:
            if isinstance(self._post_side_effect, list):
                item = self._post_side_effect.pop(0)
            else:
                item = self._post_side_effect
            if isinstance(item, Exception):
                raise item
            return item
        return self._response


# ------------------------- OllamaAnalyzer tests -------------------------
class TestOllamaAnalyzerInit:
    def test_defaults(self):
        with patch.dict(os.environ, {}, clear=True):
            ollama = OllamaAnalyzer()
            assert ollama.endpoint == "http://localhost:11434/api/generate"

    def test_invalid_scheme_fallback(self):
        with patch.dict(os.environ, {"OLLAMA_API_BASE": "ftp://bad.scheme"}), \
             patch.object(logger, "warning") as mock_warning:
            ollama = OllamaAnalyzer()
            assert ollama.endpoint == "http://localhost:11434/api/generate"
            mock_warning.assert_called_once()
            assert "Invalid OLLAMA_API_BASE scheme" in mock_warning.call_args[0][0]


class TestOllamaAnalyzeChunk:
    @pytest.mark.asyncio
    async def test_successful_call(self):
        ollama = OllamaAnalyzer(model_name="test-model")
        valid_response = {"executive_summary": "all secure", "risk_score": 5.0}
        mock_resp = MockResponse(json_data={"response": json.dumps(valid_response)})
        mock_client = MockAsyncClient(response=mock_resp)

        with patch("httpx.AsyncClient", return_value=mock_client):
            result = await ollama._analyze_chunk("prompt")
            assert result["executive_summary"] == "all secure"
            assert mock_client.post_calls
            payload = mock_client.post_calls[0][1]["json"]
            assert payload["model"] == "test-model"
            assert payload["stream"] is False
            assert payload["format"] == "json"

    @pytest.mark.asyncio
    async def test_retry_on_http_error(self):
        ollama = OllamaAnalyzer(model_name="test-model")
        valid_json = json.dumps({"executive_summary": "retry worked", "risk_score": 10})
        fail_resp = MockResponse(json_data={}, status_code=500)
        ok_resp = MockResponse(json_data={"response": valid_json}, status_code=200)
        mock_client = MockAsyncClient(post_side_effect=[fail_resp, ok_resp])

        with patch("httpx.AsyncClient", return_value=mock_client):
            result = await ollama._analyze_chunk("prompt")
            assert result["risk_score"] == 10
            assert len(mock_client.post_calls) == 2

    @pytest.mark.asyncio
    async def test_invalid_json_in_response(self):
        ollama = OllamaAnalyzer(model_name="test-model")
        mock_resp = MockResponse(json_data={"response": "not json"})
        mock_client = MockAsyncClient(response=mock_resp)

        with patch("httpx.AsyncClient", return_value=mock_client), \
             patch.object(logger, "error") as mock_error:
            result = await ollama._analyze_chunk("prompt")
            assert result["executive_summary"] == "Analysis failed due to unparsable AI output."
            mock_error.assert_called()


# ------------------------- LiteLLMAnalyzer tests -------------------------
class TestLiteLLMInit:
    def test_import_error(self):
        with patch.dict("sys.modules", {"litellm": None}):
            with pytest.raises(ImportError, match="Missing litellm package"):
                LiteLLMAnalyzer()


class TestLiteLLMAnalyzeChunk:
    @pytest.mark.asyncio
    async def test_successful_call(self):
        mock_litellm = MagicMock()
        mock_response = MagicMock()
        mock_response.choices = [
            MagicMock(message=MagicMock(content=json.dumps({"executive_summary": "cloud", "risk_score": 70})))
        ]
        mock_litellm.acompletion = AsyncMock(return_value=mock_response)

        with patch.dict("sys.modules", {"litellm": mock_litellm}):
            analyzer = LiteLLMAnalyzer(model_name="gpt-4")
            analyzer.litellm = mock_litellm
            result = await analyzer._analyze_chunk("prompt")
            assert result["executive_summary"] == "cloud"

    @pytest.mark.asyncio
    async def test_retry_on_exception(self):
        mock_litellm = MagicMock()
        valid_content = json.dumps({"executive_summary": "after retry", "risk_score": 90})
        mock_ok = MagicMock()
        mock_ok.choices = [MagicMock(message=MagicMock(content=valid_content))]
        mock_litellm.acompletion = AsyncMock(side_effect=[Exception("timeout"), mock_ok])

        with patch.dict("sys.modules", {"litellm": mock_litellm}):
            analyzer = LiteLLMAnalyzer(model_name="gpt-4")
            analyzer.litellm = mock_litellm
            result = await analyzer._analyze_chunk("prompt")
            assert result["risk_score"] == 90
            assert mock_litellm.acompletion.call_count == 2


# ------------------------- Factory -------------------------
class TestGetAnalyzer:
    def test_ollama_default(self):
        analyzer = get_analyzer("ollama")
        assert isinstance(analyzer, OllamaAnalyzer)

    def test_ollama_custom_model(self):
        analyzer = get_analyzer("ollama", model="my-model")
        assert analyzer.model_name == "my-model"

    def test_litellm_default_model(self):
        with patch("devsecops_radar.core.analyzer.LiteLLMAnalyzer.__init__", return_value=None) as mock_init:
            get_analyzer("litellm")
            mock_init.assert_called_once_with(model_name="gpt-4")

    def test_unknown_backend_fallback(self):
        with patch.object(logger, "warning") as mock_warning:
            analyzer = get_analyzer("unknown")
            assert isinstance(analyzer, OllamaAnalyzer)
            mock_warning.assert_called_once()
            assert "Unknown backend" in mock_warning.call_args[0][0]
