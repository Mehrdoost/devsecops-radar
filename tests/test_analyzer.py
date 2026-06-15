"""Tests for the AI analysis engine (updated for token‑aware chunking & new merge)."""

import asyncio
import json
from contextlib import contextmanager
from typing import Any
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
)
from loguru import logger


@contextmanager
def capture_loguru(level: str = "TRACE"):
    messages: list[str] = []

    def sink(msg):
        messages.append(str(msg))

    handler_id = logger.add(sink, level=level, format="{message}")
    try:
        yield messages
    finally:
        logger.remove(handler_id)


class _ConcreteAnalyzer(AIAnalyzer):
    def __init__(self, responses=None, **kwargs):
        super().__init__(**kwargs)
        self.responses = responses or []
        self.call_count = 0

    async def _analyze_chunk(self, prompt: str) -> dict:
        if self.call_count < len(self.responses):
            resp = self.responses[self.call_count]
        else:
            resp = {}
        self.call_count += 1
        return resp


@pytest.fixture
def sample_findings():
    return [
        {"id": "F1", "severity": "HIGH", "title": "SQL Injection", "source": "semgrep"},
        {"id": "F2", "severity": "MEDIUM", "title": "Weak Crypto", "source": "trivy"},
    ]


@pytest.fixture
def sample_topology():
    return {"services": [{"name": "web", "dependencies": ["db"]}]}


# ============================== Models ==============================
class TestModels:
    def test_attack_path_valid(self):
        ap = AttackPath(title="Path1", description="desc", impact="high")
        assert ap.title == "Path1"

    def test_attack_path_missing_fields(self):
        with pytest.raises(ValidationError):
            AttackPath(title="Path1")

    def test_remediation_valid(self):
        rem = Remediation(finding_id="F1", title="Fix", remediation_steps=["s"])
        assert len(rem.remediation_steps) == 1

    def test_analysis_response_defaults(self):
        resp = AIAnalysisResponse(executive_summary="x", risk_score=50)
        assert resp.attack_paths == []

    def test_analysis_response_risk_score_range(self):
        assert AIAnalysisResponse(executive_summary="x", risk_score=-1).risk_score == -1.0
        assert AIAnalysisResponse(executive_summary="x", risk_score=100).risk_score == 100.0

    def test_risk_score_out_of_range_raises(self):
        with pytest.raises(ValidationError):
            AIAnalysisResponse(executive_summary="x", risk_score=150)


class TestAIAnalyzerBase:
    def test_validate_model_name_safe(self):
        assert AIAnalyzer._validate_model_name("gpt-4") == "gpt-4"

    def test_validate_model_name_suspicious(self):
        with capture_loguru() as msgs:
            assert AIAnalyzer._validate_model_name("../../x") == "llama3.2:latest"
        assert any("Suspicious" in m for m in msgs)

    def test_build_prompt_without_topology(self, sample_findings):
        a = _ConcreteAnalyzer(model_name="x")
        prompt = a._build_prompt(sample_findings)
        assert "Asset Topology:" not in prompt

    def test_build_prompt_with_topology_explicit(self, sample_findings, sample_topology):
        a = _ConcreteAnalyzer(model_name="x")
        prompt = a._build_prompt(sample_findings, sample_topology, include_topology=True)
        assert "Asset Topology:" in prompt

    def test_build_prompt_topology_truncation(self, sample_findings):
        big = {"k": "x" * 3000}
        a = _ConcreteAnalyzer(model_name="x")
        prompt = a._build_prompt(sample_findings, big, include_topology=True)
        assert "[TRUNCATED]" in prompt

    def test_extract_and_validate_json_valid(self):
        a = _ConcreteAnalyzer(model_name="x")
        data = {"executive_summary": "ok", "risk_score": 45.5, "attack_paths": [],
                "top_remediations": []}
        assert a._extract_and_validate_json(json.dumps(data))["risk_score"] == 45.5

    def test_extract_and_validate_json_missing_field(self):
        a = _ConcreteAnalyzer(model_name="x")
        assert a._extract_and_validate_json(json.dumps({"risk_score":10}))["risk_score"] == -1.0

    def test_extract_and_validate_json_invalid_json(self):
        a = _ConcreteAnalyzer(model_name="x")
        assert a._extract_and_validate_json("not json")["risk_score"] == -1.0

    def test_extract_and_validate_json_schema_instead_of_data(self):
        a = _ConcreteAnalyzer(model_name="x")
        assert a._extract_and_validate_json(json.dumps({"$defs":{}}))["risk_score"] == -1.0


class TestMergeAnalyses:
    def test_empty(self):
        a = _ConcreteAnalyzer(model_name="x")
        res = a.merge_analyses([], [])
        assert res["risk_score"] == 0.0

    def test_single(self):
        a = _ConcreteAnalyzer(model_name="x")
        single = {"executive_summary": "S", "risk_score": 80, "attack_paths": [], "top_remediations": []}
        assert a.merge_analyses([single], [5]) == single

    def test_weighted_average(self):
        a = _ConcreteAnalyzer(model_name="x")
        res = a.merge_analyses(
            [{"executive_summary": "A", "risk_score": 30, "attack_paths": [], "top_remediations": []},
             {"executive_summary": "B", "risk_score": 70, "attack_paths": [], "top_remediations": []}],
            [5, 10]
        )
        assert res["risk_score"] == round((30*5 + 70*10) / 15, 1)

    def test_zero_scores_included(self):
        a = _ConcreteAnalyzer(model_name="x")
        res = a.merge_analyses(
            [{"executive_summary": "A", "risk_score": 0, "attack_paths": [], "top_remediations": []},
             {"executive_summary": "B", "risk_score": 60, "attack_paths": [], "top_remediations": []},
             {"executive_summary": "C", "risk_score": 40, "attack_paths": [], "top_remediations": []}],
            [5, 10, 10]
        )
        # (0*5 + 60*10 + 40*10) / 25 = 40.0
        assert res["risk_score"] == 40.0

    def test_summary_truncation(self):
        a = _ConcreteAnalyzer(model_name="x")
        many = [{"executive_summary": f"S{i}", "risk_score": 10, "attack_paths": [], "top_remediations": []} for i in range(5)]
        res = a.merge_analyses(many, [1]*5)
        assert "and 2 more" in res["executive_summary"]

    def test_deduplication_remediations(self):
        a = _ConcreteAnalyzer(model_name="x")
        res = a.merge_analyses(
            [{"executive_summary": "A", "risk_score": 10, "attack_paths": [],
              "top_remediations": [{"finding_id": "1", "title": "R1", "remediation_steps": ["s"]}]},
             {"executive_summary": "B", "risk_score": 20, "attack_paths": [],
              "top_remediations": [{"finding_id": "1", "title": "R1", "remediation_steps": ["s"]},
                                   {"finding_id": "2", "title": "R2", "remediation_steps": ["t"]}]}],
            [5, 5]
        )
        ids = [r["finding_id"] for r in res["top_remediations"]]
        assert ids == ["1", "2"]

    def test_merge_attack_paths_concatenation(self):
        a = _ConcreteAnalyzer(model_name="x")
        res = a.merge_analyses(
            [{"executive_summary": "A", "risk_score": 10, "attack_paths": [{"title": "T1", "description": "d", "impact": "i"}]},
             {"executive_summary": "B", "risk_score": 10, "attack_paths": [{"title": "T2", "description": "d", "impact": "i"}]}],
            [3, 5]
        )
        assert len(res["attack_paths"]) == 2


class TestRunMethod:
    @pytest.mark.asyncio
    async def test_run_ok(self, sample_findings):
        a = _ConcreteAnalyzer(model_name="x", responses=[{"executive_summary": "ok", "risk_score": 10}])
        res = await a.run(sample_findings, chunk_size=1)
        assert res["executive_summary"] is not None


class TestOllamaAnalyzer:
    @pytest.mark.asyncio
    async def test_unparsable_response(self):
        a = OllamaAnalyzer()
        mock_resp = MagicMock(spec=httpx.Response)
        mock_resp.json.return_value = {"response": "not json"}
        mock_resp.raise_for_status = MagicMock()

        with patch("httpx.AsyncClient") as mock_cls:
            mock_client = AsyncMock()
            mock_cls.return_value.__aenter__.return_value = mock_client
            mock_client.post.return_value = mock_resp
            result = await a._analyze_chunk("prompt")
        assert result["risk_score"] == -1.0