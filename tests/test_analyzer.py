"""Tests for the AI analysis engine (analyzer module)."""

import json
from contextlib import contextmanager
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest
from loguru import logger
from pydantic import ValidationError

from devsecops_radar.core.analyzer import (
    AIAnalysisResponse,
    AIAnalyzer,
    AttackPath,
    LiteLLMAnalyzer,
    OllamaAnalyzer,
    Remediation,
    get_analyzer,
)


# ---------------------------------------------------------------------------
# Helper to capture loguru output
# ---------------------------------------------------------------------------
@contextmanager
def capture_loguru(level: str = "TRACE"):
    """Capture loguru messages into a list of plain strings."""
    messages: list[str] = []

    def sink(msg):
        messages.append(str(msg))

    handler_id = logger.add(sink, level=level, format="{message}")
    try:
        yield messages
    finally:
        logger.remove(handler_id)


# ---------------------------------------------------------------------------
# Concrete AIAnalyzer for testing
# ---------------------------------------------------------------------------
class _ConcreteAnalyzer(AIAnalyzer):
    """Concrete implementation that returns predefined responses for testing."""

    def __init__(self, responses: list[dict[str, Any]] | None = None, **kwargs):
        super().__init__(**kwargs)
        self.responses = responses or []
        self.call_count = 0

    async def _analyze_chunk(self, prompt: str) -> dict[str, Any]:
        if self.call_count < len(self.responses):
            resp = self.responses[self.call_count]
        else:
            resp = {}
        self.call_count += 1
        return resp


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------
@pytest.fixture
def sample_findings():
    return [
        {"id": "F1", "severity": "HIGH", "title": "SQL Injection", "source": "semgrep"},
        {"id": "F2", "severity": "MEDIUM", "title": "Weak Crypto", "source": "trivy"},
    ]


@pytest.fixture
def sample_topology():
    return {"services": [{"name": "web", "dependencies": ["db"]}]}


# ============================== Pydantic Models ==============================
class TestModels:
    def test_attack_path_valid(self):
        ap = AttackPath(title="Path1", description="desc", impact="high")
        assert ap.title == "Path1"
        assert ap.impact == "high"

    def test_attack_path_missing_fields(self):
        with pytest.raises(ValidationError):
            AttackPath(title="Path1")  # missing description

    def test_remediation_valid(self):
        rem = Remediation(
            finding_id="F1", title="Fix SQLi", remediation_steps=["Step1", "Step2"]
        )
        assert len(rem.remediation_steps) == 2

    def test_analysis_response_defaults(self):
        resp = AIAnalysisResponse(executive_summary="test", risk_score=50)
        assert resp.attack_paths == []
        assert resp.top_remediations == []
        assert resp.risk_score == 50

    def test_analysis_response_risk_score_bounds(self):
        with pytest.raises(ValidationError):
            AIAnalysisResponse(executive_summary="x", risk_score=150)
        with pytest.raises(ValidationError):
            AIAnalysisResponse(executive_summary="x", risk_score=-1)


# ============================== AIAnalyzer Base ==============================
class TestAIAnalyzerBase:
    def test_validate_model_name_safe(self):
        assert AIAnalyzer._validate_model_name("gpt-4") == "gpt-4"
        assert AIAnalyzer._validate_model_name("llama3.2:latest") == "llama3.2:latest"

    def test_validate_model_name_suspicious(self):
        with capture_loguru() as msgs:
            result = AIAnalyzer._validate_model_name("../../etc/passwd")
        assert result == "llama3.2:latest"
        assert any("Suspicious model name" in m for m in msgs)

    def test_validate_model_name_empty(self):
        with capture_loguru() as msgs:
            result = AIAnalyzer._validate_model_name("")
        assert result == "llama3.2:latest"
        # Optionally check that warning was emitted
        assert any("Suspicious" in m for m in msgs)

    def test_build_prompt_without_topology(self, sample_findings):
        analyzer = _ConcreteAnalyzer(model_name="test")
        prompt = analyzer._build_prompt(sample_findings)
        assert "FINDINGS_DATA_" in prompt
        assert json.dumps(sample_findings, indent=2) in prompt
        assert "Asset Topology:" not in prompt

    def test_build_prompt_with_topology(self, sample_findings, sample_topology):
        analyzer = _ConcreteAnalyzer(model_name="test")
        prompt = analyzer._build_prompt(sample_findings, sample_topology)
        assert "Asset Topology:" in prompt
        topo_str = json.dumps(sample_topology)
        assert topo_str in prompt  # not truncated because short

    def test_build_prompt_topology_truncation(self, sample_findings):
        big_topo = {"key": "x" * 3000}
        analyzer = _ConcreteAnalyzer(model_name="test")
        prompt = analyzer._build_prompt(sample_findings, big_topo)
        # Verify truncation marker present and full topology absent
        assert "[TRUNCATED]" in prompt
        full_topo_str = json.dumps(big_topo)
        assert full_topo_str not in prompt  # entire string not included
        # The prompt contains the first 2000 characters of the topology string
        # (which includes the json structure). We simply check that the prompt
        # length is much smaller than it would be with the full topology.
        assert len(prompt) < len(full_topo_str) + 500  # rough sanity

    def test_extract_and_validate_json_valid(self):
        analyzer = _ConcreteAnalyzer(model_name="test")
        valid = {
            "executive_summary": "All good",
            "risk_score": 45.5,
            "attack_paths": [
                {"title": "Path", "description": "desc", "impact": "impact"}
            ],
            "top_remediations": [
                {
                    "finding_id": "F1",
                    "title": "Fix",
                    "remediation_steps": ["step"],
                }
            ],
        }
        result = analyzer._extract_and_validate_json(json.dumps(valid))
        assert result["executive_summary"] == "All good"
        assert result["risk_score"] == 45.5
        assert len(result["attack_paths"]) == 1

    def test_extract_and_validate_json_missing_field(self):
        analyzer = _ConcreteAnalyzer(model_name="test")
        invalid = {"risk_score": 10}
        with capture_loguru() as msgs:
            result = analyzer._extract_and_validate_json(json.dumps(invalid))
        assert result["risk_score"] == 0.0
        assert any("schema validation" in m.lower() for m in msgs)

    def test_extract_and_validate_json_invalid_json(self):
        analyzer = _ConcreteAnalyzer(model_name="test")
        with capture_loguru() as msgs:
            result = analyzer._extract_and_validate_json("not json at all")
        assert result["risk_score"] == 0.0
        # The actual log says "parsable JSON", not "unparsable"
        assert any("parsable" in m for m in msgs)

    def test_extract_and_validate_json_schema_instead_of_data(self):
        analyzer = _ConcreteAnalyzer(model_name="test")
        schema_like = {"$defs": {}, "properties": {}}
        with capture_loguru() as msgs:
            result = analyzer._extract_and_validate_json(json.dumps(schema_like))
        assert result["risk_score"] == 0.0
        assert any("returned the json schema" in m.lower() for m in msgs)

    def test_extract_and_validate_json_regex_recovery(self):
        analyzer = _ConcreteAnalyzer(model_name="test")
        raw = (
            'Here is your JSON:\n```json\n{"executive_summary":"ok",'
            '"risk_score":20,"attack_paths":[],"top_remediations":[]}\n```'
        )
        result = analyzer._extract_and_validate_json(raw)
        assert result["executive_summary"] == "ok"
        assert result["risk_score"] == 20


class TestMergeAnalyses:
    def test_empty_list(self):
        analyzer = _ConcreteAnalyzer(model_name="test")
        result = analyzer.merge_analyses([])
        assert result["executive_summary"] == "No data analyzed."
        assert result["risk_score"] == 0.0
        assert result["attack_paths"] == []
        assert result["top_remediations"] == []

    def test_single_analysis(self):
        analyzer = _ConcreteAnalyzer(model_name="test")
        single = {
            "executive_summary": "One",
            "risk_score": 80,
            "attack_paths": [{"title": "x", "description": "y", "impact": "z"}],
            "top_remediations": [
                {"finding_id": "1", "title": "r", "remediation_steps": ["s"]}
            ],
        }
        result = analyzer.merge_analyses([single])
        assert result == single

    def test_multiple_analyses_average(self):
        analyzer = _ConcreteAnalyzer(model_name="test")
        a = {
            "executive_summary": "A",
            "risk_score": 30,
            "attack_paths": [],
            "top_remediations": [],
        }
        b = {
            "executive_summary": "B",
            "risk_score": 70,
            "attack_paths": [],
            "top_remediations": [],
        }
        result = analyzer.merge_analyses([a, b])
        assert result["risk_score"] == 50.0  # average (30+70)/2
        assert "Composite Analysis:" in result["executive_summary"]
        assert "A" in result["executive_summary"]
        assert "B" in result["executive_summary"]

    def test_ignores_zero_scores_when_averaging(self):
        analyzer = _ConcreteAnalyzer(model_name="test")
        a = {
            "executive_summary": "A",
            "risk_score": 0,
            "attack_paths": [],
            "top_remediations": [],
        }
        b = {
            "executive_summary": "B",
            "risk_score": 60,
            "attack_paths": [],
            "top_remediations": [],
        }
        c = {
            "executive_summary": "C",
            "risk_score": 40,
            "attack_paths": [],
            "top_remediations": [],
        }
        result = analyzer.merge_analyses([a, b, c])
        # a score=0 is excluded, average of (60+40)/2 = 50
        assert result["risk_score"] == 50.0

    def test_summary_truncation(self):
        analyzer = _ConcreteAnalyzer(model_name="test")
        many = [
            {
                "executive_summary": f"Sum{i}",
                "risk_score": 10,
                "attack_paths": [],
                "top_remediations": [],
            }
            for i in range(5)
        ]
        result = analyzer.merge_analyses(many)
        assert "Sum0" in result["executive_summary"]
        assert "Sum1" in result["executive_summary"]
        assert "Sum2" in result["executive_summary"]
        assert "and 2 more" in result["executive_summary"]

    def test_deduplication_remediations(self):
        analyzer = _ConcreteAnalyzer(model_name="test")
        a = {
            "executive_summary": "A",
            "risk_score": 10,
            "attack_paths": [],
            "top_remediations": [
                {"finding_id": "1", "title": "R1", "remediation_steps": ["s"]},
            ],
        }
        b = {
            "executive_summary": "B",
            "risk_score": 20,
            "attack_paths": [],
            "top_remediations": [
                {"finding_id": "1", "title": "R1", "remediation_steps": ["s"]},
                {"finding_id": "2", "title": "R2", "remediation_steps": ["t"]},
            ],
        }
        result = analyzer.merge_analyses([a, b])
        ids = [r["finding_id"] for r in result["top_remediations"]]
        assert ids == ["1", "2"]

    def test_merge_attack_paths_concatenation(self):
        analyzer = _ConcreteAnalyzer(model_name="test")
        a = {
            "executive_summary": "A",
            "risk_score": 10,
            "attack_paths": [
                {"title": "T1", "description": "d", "impact": "i"}
            ],
        }
        b = {
            "executive_summary": "B",
            "risk_score": 10,
            "attack_paths": [
                {"title": "T2", "description": "d", "impact": "i"}
            ],
        }
        result = analyzer.merge_analyses([a, b])
        assert len(result["attack_paths"]) == 2


# ============================== Run Method ==================================
class TestRunMethod:
    @pytest.mark.asyncio
    async def test_run_splits_into_chunks(self, sample_findings):
        responses = [{"executive_summary": "ok", "risk_score": 10}]
        analyzer = _ConcreteAnalyzer(model_name="x", responses=responses)
        result = await analyzer.run(sample_findings, chunk_size=1)
        assert analyzer.call_count == 2
        assert result["executive_summary"] is not None

    @pytest.mark.asyncio
    async def test_run_handles_chunk_exception(self, sample_findings):
        class ErrorAnalyzer(_ConcreteAnalyzer):
            async def _analyze_chunk(self, prompt):
                raise RuntimeError("simulated failure")

        analyzer = ErrorAnalyzer(model_name="x")
        result = await analyzer.run(sample_findings, chunk_size=1)
        assert result["risk_score"] == 0.0
        assert "No data analyzed" in result["executive_summary"]

    @pytest.mark.asyncio
    async def test_run_high_chunk_warning(self, sample_findings):
        many_findings = [{"id": str(i)} for i in range(110)]
        analyzer = _ConcreteAnalyzer(
            model_name="x", responses=[{"risk_score": 0}]
        )
        with capture_loguru() as msgs:
            await analyzer.run(many_findings, chunk_size=10)
        assert any("High load" in m for m in msgs)


# ============================== OllamaAnalyzer ==============================
class TestOllamaAnalyzer:
    def test_init_defaults(self, monkeypatch):
        monkeypatch.delenv("OLLAMA_API_BASE", raising=False)
        analyzer = OllamaAnalyzer()
        assert analyzer.endpoint == "http://localhost:11434/api/generate"
        assert analyzer.model_name == "llama3.2:latest"

    def test_init_localhost_env(self, monkeypatch):
        monkeypatch.setenv("OLLAMA_API_BASE", "http://127.0.0.1:8080/generate")
        analyzer = OllamaAnalyzer()
        assert analyzer.endpoint == "http://127.0.0.1:8080/generate"

    def test_init_invalid_scheme(self, monkeypatch):
        monkeypatch.setenv("OLLAMA_API_BASE", "ftp://localhost/generate")
        with capture_loguru() as msgs:
            analyzer = OllamaAnalyzer()
        assert analyzer.endpoint == "http://localhost:11434/api/generate"
        assert any("Invalid OLLAMA_API_BASE scheme" in m for m in msgs)

    def test_init_non_local_host(self, monkeypatch):
        monkeypatch.setenv("OLLAMA_API_BASE", "http://evil.com/api")
        with capture_loguru() as msgs:
            analyzer = OllamaAnalyzer()
        assert analyzer.endpoint == "http://localhost:11434/api/generate"
        assert any("Blocked for security" in m for m in msgs)

    @pytest.mark.asyncio
    async def test_analyze_chunk_success(self):
        analyzer = OllamaAnalyzer(model_name="llama3.2:latest")
        valid_response = {
            "executive_summary": "All good",
            "risk_score": 50,
            "attack_paths": [],
            "top_remediations": [],
        }
        mock_response = MagicMock(spec=httpx.Response)
        mock_response.json.return_value = {"response": json.dumps(valid_response)}
        mock_response.raise_for_status = MagicMock()

        with patch("httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client_cls.return_value.__aenter__.return_value = mock_client
            mock_client.post.return_value = mock_response

            result = await analyzer._analyze_chunk("test prompt")

        assert result["executive_summary"] == "All good"
        mock_client.post.assert_called_once()
        call_args = mock_client.post.call_args
        payload = call_args[1]["json"]
        assert payload["model"] == "llama3.2:latest"
        assert payload["prompt"] == "test prompt"
        assert payload["stream"] is False
        assert payload["format"] == "json"

    @pytest.mark.asyncio
    async def test_analyze_chunk_retry_then_success(self):
        analyzer = OllamaAnalyzer(model_name="llama")
        valid = {
            "executive_summary": "ok",
            "risk_score": 10,
            "attack_paths": [],
            "top_remediations": [],
        }
        mock_response_ok = MagicMock(spec=httpx.Response)
        mock_response_ok.json.return_value = {"response": json.dumps(valid)}
        mock_response_ok.raise_for_status = MagicMock()

        with patch("httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client_cls.return_value.__aenter__.return_value = mock_client
            # First call fails, second succeeds
            mock_client.post.side_effect = [
                httpx.HTTPError("network"),
                mock_response_ok,
            ]

            result = await analyzer._analyze_chunk("prompt")

        assert result["risk_score"] == 10
        assert mock_client.post.call_count == 2

    @pytest.mark.asyncio
    async def test_analyze_chunk_unparsable_response(self):
        analyzer = OllamaAnalyzer()
        mock_response = MagicMock(spec=httpx.Response)
        mock_response.json.return_value = {"response": "not valid json at all"}
        mock_response.raise_for_status = MagicMock()

        with patch("httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client_cls.return_value.__aenter__.return_value = mock_client
            mock_client.post.return_value = mock_response

            result = await analyzer._analyze_chunk("prompt")

        assert result["risk_score"] == 0.0  # fallback


# ============================== LiteLLMAnalyzer ==============================
class TestLiteLLMAnalyzer:
    def test_init_import_success(self):
        with patch.dict("sys.modules", {"litellm": MagicMock()}):
            analyzer = LiteLLMAnalyzer()
            assert analyzer.model_name == "gpt-4"

    def test_init_import_failure(self):
        with patch.dict("sys.modules", {"litellm": None}):
            with pytest.raises(ImportError, match="Missing litellm"):
                LiteLLMAnalyzer()

    @pytest.mark.asyncio
    async def test_analyze_chunk_success(self):
        mock_litellm = MagicMock()
        mock_completion = AsyncMock()
        mock_completion.return_value.choices = [
            MagicMock(
                message=MagicMock(
                    content=json.dumps(
                        {
                            "executive_summary": "OK",
                            "risk_score": 75,
                            "attack_paths": [],
                            "top_remediations": [],
                        }
                    )
                )
            )
        ]
        mock_litellm.acompletion = mock_completion

        analyzer = LiteLLMAnalyzer(model_name="gpt-4")
        analyzer.litellm = mock_litellm

        result = await analyzer._analyze_chunk("test prompt")
        assert result["risk_score"] == 75
        mock_completion.assert_awaited_once()
        call_kwargs = mock_completion.call_args[1]
        assert call_kwargs["model"] == "gpt-4"
        assert call_kwargs["timeout"] == 120
        assert call_kwargs["response_format"] == {"type": "json_object"}
        assert call_kwargs["drop_params"] is True

    @pytest.mark.asyncio
    async def test_analyze_chunk_retry_on_failure(self):
        mock_litellm = MagicMock()
        mock_litellm.acompletion = AsyncMock()
        mock_litellm.acompletion.side_effect = [
            Exception("API error"),
            MagicMock(
                choices=[
                    MagicMock(
                        message=MagicMock(
                            content=json.dumps(
                                {
                                    "executive_summary": "retried",
                                    "risk_score": 30,
                                    "attack_paths": [],
                                    "top_remediations": [],
                                }
                            )
                        )
                    )
                ]
            ),
        ]
        analyzer = LiteLLMAnalyzer(model_name="gpt-4")
        analyzer.litellm = mock_litellm

        result = await analyzer._analyze_chunk("prompt")
        assert result["executive_summary"] == "retried"
        assert mock_litellm.acompletion.call_count == 2


# ============================== get_analyzer Factory =========================
class TestGetAnalyzer:
    def test_ollama_default(self):
        a = get_analyzer("ollama")
        assert isinstance(a, OllamaAnalyzer)
        assert a.model_name == "llama3.2:latest"

    def test_ollama_custom_model(self):
        a = get_analyzer("ollama", "mistral")
        assert isinstance(a, OllamaAnalyzer)
        assert a.model_name == "mistral"

    def test_litellm_default(self):
        with patch.dict("sys.modules", {"litellm": MagicMock()}):
            a = get_analyzer("litellm")
        assert isinstance(a, LiteLLMAnalyzer)
        assert a.model_name == "gpt-4"

    def test_litellm_custom_model(self):
        with patch.dict("sys.modules", {"litellm": MagicMock()}):
            a = get_analyzer("litellm", "gpt-3.5")
        assert isinstance(a, LiteLLMAnalyzer)
        assert a.model_name == "gpt-3.5"

    def test_unknown_backend(self):
        with capture_loguru() as msgs:
            a = get_analyzer("unknown")
        assert isinstance(a, OllamaAnalyzer)
        assert any("Unknown backend" in m for m in msgs)
