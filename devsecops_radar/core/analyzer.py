import asyncio
import json
import os
import re
import uuid
from abc import ABC, abstractmethod
from typing import Any
from urllib.parse import urlparse

import httpx
from loguru import logger
from pydantic import BaseModel, Field, ValidationError
from tenacity import retry, stop_after_attempt, wait_exponential


class AttackPath(BaseModel):
    title: str = Field(..., description="Short title of the attack path")
    description: str = Field(
        ..., description="Explanation of how the vulnerabilities chain together"
    )
    impact: str = Field(
        default="Impact assessment was not provided by the AI model.",
        description="Potential business or technical impact",
    )


class Remediation(BaseModel):
    finding_id: str = Field(
        ..., description="The ID of the finding this relates to"
    )
    title: str = Field(..., description="Short title for the fix")
    remediation_steps: list[str] = Field(
        ..., description="Step-by-step human-readable instructions to fix the issue"
    )


class AIAnalysisResponse(BaseModel):
    executive_summary: str = Field(
        ..., description="High-level summary of the security posture"
    )
    risk_score: float = Field(
        ..., ge=0, le=100, description="Overall risk score between 0 and 100"
    )
    attack_paths: list[AttackPath] = Field(default_factory=list)
    top_remediations: list[Remediation] = Field(default_factory=list)


class AIAnalyzer(ABC):
    """Abstract base class for AI security analysis engines."""

    def __init__(self, model_name: str, timeout: int = 300) -> None:
        self.model_name = self._validate_model_name(model_name)
        self.timeout = timeout

    @staticmethod
    def _validate_model_name(model: str) -> str:
        if not re.match(r"^[a-zA-Z0-9_.:-]+$", model):
            logger.warning(
                f"Suspicious model name detected: {model}. "
                "Falling back to 'llama3.2:latest'."
            )
            return "llama3.2:latest"   # safer fallback than a non-existent model
        return model

    def _build_prompt(
        self, findings: list[dict[str, Any]], topology: dict[str, Any] | None = None
    ) -> str:
        # Generate random boundary to prevent prompt injection
        boundary = uuid.uuid4().hex
        start_tag = f"<FINDINGS_DATA_{boundary}>"
        end_tag = f"</FINDINGS_DATA_{boundary}>"

        topology_text = ""
        if topology:
            topo_str = json.dumps(topology)
            topology_text = (
                f"\nAsset Topology:\n{topo_str[:2000]}"
                + ("... [TRUNCATED]" if len(topo_str) > 2000 else "")
            )

        prompt = f"""Analyze the following security findings.

IMPORTANT: Your response must be a single JSON object with exactly these fields:
- "executive_summary": string (high-level summary)
- "risk_score": number between 0 and 100
- "attack_paths": list of objects with "title", "description", "impact" (string describing the impact)
- "top_remediations": list of objects with "finding_id", "title", "remediation_steps" (list of strings)

Make sure every object in "attack_paths" includes all three fields. Do NOT include any other text or the JSON schema. Output ONLY the JSON object.

{start_tag}
{json.dumps(findings, indent=2)}
{topology_text}
{end_tag}
"""
        return prompt

    def _extract_and_validate_json(self, text: str) -> dict[str, Any]:
        extracted = {}
        try:
            extracted = json.loads(text)
        except json.JSONDecodeError:
            match = re.search(r'\{.*\}', text, re.DOTALL)
            if match:
                try:
                    extracted = json.loads(match.group(0))
                except json.JSONDecodeError:
                    logger.error("Failed to decode JSON from regex match.")

        if not extracted:
            logger.error("LLM failed to produce parsable JSON. Using safe fallback.")
            return AIAnalysisResponse(
                executive_summary="Analysis failed due to unparsable AI output.",
                risk_score=0.0,
            ).model_dump()

        if "$defs" in extracted or "properties" in extracted:
            logger.error(
                "LLM returned the JSON schema instead of analysis. "
                "Using safe fallback."
            )
            return AIAnalysisResponse(
                executive_summary=(
                    "AI analysis failed due to invalid model output. Please retry."
                ),
                risk_score=0.0,
            ).model_dump()

        try:
            validated_data = AIAnalysisResponse(**extracted)
            return validated_data.model_dump()
        except ValidationError as e:
            logger.error(f"LLM output failed strict schema validation: {e}")
            return AIAnalysisResponse(
                executive_summary=(
                    "Analysis completed but output formatting was corrupted."
                ),
                risk_score=0.0,
            ).model_dump()

    def merge_analyses(
        self, analyses: list[dict[str, Any]]
    ) -> dict[str, Any]:
        if not analyses:
            return AIAnalysisResponse(
                executive_summary="No data analyzed.", risk_score=0.0
            ).model_dump()
        if len(analyses) == 1:
            return analyses[0]

        valid_scores = [
            a.get("risk_score", 0)
            for a in analyses
            if a.get("risk_score", 0) > 0
        ]
        avg_risk = (
            sum(valid_scores) / len(valid_scores) if valid_scores else 0.0
        )

        summaries = [
            a.get("executive_summary", "").strip()
            for a in analyses
            if a.get("executive_summary")
        ]
        merged_summary = "Composite Analysis:\n- " + "\n- ".join(summaries[:3])
        if len(summaries) > 3:
            merged_summary += f"\n... (and {len(summaries) - 3} more sub-analyses)"

        seen_finding_ids = set()
        merged_remediations = []
        for a in analyses:
            for r in a.get("top_remediations", []):
                if r.get("finding_id") not in seen_finding_ids:
                    seen_finding_ids.add(r.get("finding_id"))
                    merged_remediations.append(r)

        merged_paths = []
        for a in analyses:
            merged_paths.extend(a.get("attack_paths", []))

        return {
            "executive_summary": merged_summary,
            "risk_score": round(avg_risk, 1),
            "attack_paths": merged_paths,
            "top_remediations": merged_remediations,
        }

    @abstractmethod
    async def _analyze_chunk(self, prompt: str) -> dict[str, Any]:
        pass

    async def run(
        self,
        findings: list[dict[str, Any]],
        topology: dict[str, Any] | None = None,
        chunk_size: int = 10,
    ) -> dict[str, Any]:
        chunks = [
            findings[i : i + chunk_size]
            for i in range(0, len(findings), chunk_size)
        ]
        if len(chunks) > 10:
            logger.warning(
                f"High load: Processing {len(chunks)} chunks. "
                "Consider increasing 'chunk_size' to optimize performance."
            )

        # Limit concurrency to avoid overwhelming the backend
        sem = asyncio.Semaphore(5)
        async def _sem_task(chunk):
            async with sem:
                return await self._analyze_chunk(
                    self._build_prompt(chunk, topology)
                )

        tasks = [_sem_task(chunk) for chunk in chunks]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        valid_results = []
        for res in results:
            if isinstance(res, Exception):
                logger.error(f"Chunk analysis failed: {res}")
            else:
                valid_results.append(res)
        return self.merge_analyses(valid_results)


class OllamaAnalyzer(AIAnalyzer):
    def __init__(
        self, model_name: str = "llama3.2:latest", timeout: int = 300
    ) -> None:
        super().__init__(model_name, timeout)
        raw_url = os.environ.get(
            "OLLAMA_API_BASE", "http://localhost:11434/api/generate"
        )
        parsed = urlparse(raw_url)
        # Strictly restrict to localhost/private IPs to maintain air-gapped guarantee
        if parsed.scheme not in ["http", "https"]:
            logger.warning(
                "Invalid OLLAMA_API_BASE scheme. Falling back to localhost."
            )
            raw_url = "http://localhost:11434/api/generate"
        elif parsed.hostname not in ["localhost", "127.0.0.1", "[::1]", None]:
            logger.error(
                f"OLLAMA_API_BASE is not a local address ({parsed.hostname}). "
                "Blocked for security. Use only localhost."
            )
            raw_url = "http://localhost:11434/api/generate"

        self.endpoint = raw_url

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=2, max=10),
    )
    async def _analyze_chunk(self, prompt: str) -> dict[str, Any]:
        timeout_config = httpx.Timeout(
            connect=10.0, read=self.timeout, write=10.0, pool=10.0
        )
        payload = {
            "model": self.model_name,
            "prompt": prompt,
            "stream": False,
            "format": "json",
            "system": (
                "You are a DevSecOps AI assistant. Analyze security findings and output "
                "a JSON object with keys: executive_summary, risk_score, attack_paths, top_remediations. "
                "Each attack path must include title, description, and impact. "
                "Output ONLY the JSON object, no other text."
            ),
        }
        async with httpx.AsyncClient(timeout=timeout_config) as client:
            resp = await client.post(self.endpoint, json=payload)
            resp.raise_for_status()
            data = resp.json()
            return self._extract_and_validate_json(
                data.get("response", "{}")
            )


class LiteLLMAnalyzer(AIAnalyzer):
    def __init__(
        self, model_name: str = "gpt-4", timeout: int = 120
    ) -> None:
        super().__init__(model_name, timeout)
        try:
            import litellm
            self.litellm = litellm
            self.litellm.set_verbose = False
        except ImportError as err:
            logger.error(
                "LiteLLM is not installed. To use cloud models, run: "
                "pip install litellm"
            )
            raise ImportError(
                "Missing litellm package. Alternatively, use the default "
                "Ollama backend."
            ) from err

    @retry(
        stop=stop_after_attempt(4),
        wait=wait_exponential(multiplier=1.5, min=2, max=20),
    )
    async def _analyze_chunk(self, prompt: str) -> dict[str, Any]:
        response = await self.litellm.acompletion(
            model=self.model_name,
            messages=[
                {
                    "role": "system",
                    "content": (
                        "You are a DevSecOps AI assistant. Analyze security findings and output "
                        "a JSON object with keys: executive_summary, risk_score, attack_paths, top_remediations. "
                        "Each attack path must include title, description, and impact. "
                        "Output ONLY the JSON object, no other text."
                    ),
                },
                {"role": "user", "content": prompt},
            ],
            timeout=self.timeout,
            response_format={"type": "json_object"},
            drop_params=True,   # safely ignore unsupported params
        )
        content = response.choices[0].message.content
        return self._extract_and_validate_json(content)


def get_analyzer(
    backend: str = "ollama", model: str | None = None
) -> AIAnalyzer:
    if backend.lower() == "litellm":
        return LiteLLMAnalyzer(model_name=model or "gpt-4")
    elif backend.lower() == "ollama":
        return OllamaAnalyzer(model_name=model or "llama3.2:latest")
    else:
        logger.warning(
            f"Unknown backend '{backend}'. Falling back to Ollama."
        )
        return OllamaAnalyzer(model_name=model or "llama3.2:latest")
