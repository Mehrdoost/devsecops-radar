# devsecops_radar/core/analyzer.py
import asyncio
import json
import os
import re
import uuid
from abc import ABC, abstractmethod
from typing import Any, cast
from urllib.parse import urlparse

import httpx
from loguru import logger
from pydantic import BaseModel, Field, ValidationError
from tenacity import retry, stop_after_attempt, wait_exponential

try:
    import tiktoken
    TOKENIZER: tiktoken.Encoding | None = tiktoken.get_encoding("cl100k_base")
except ImportError:
    TOKENIZER = None
    logger.warning("tiktoken not installed; token‑aware chunking disabled.")


# ---------------------------------------------------------------------------
# Pydantic models (updated)
# ---------------------------------------------------------------------------
class AttackPath(BaseModel):
    title: str = Field(..., description="Short title of the attack path")
    description: str = Field(
        ..., description="Explanation of how the vulnerabilities chain together"
    )
    impact: str = Field(
        default="Impact assessment was not provided by the AI model.",
        description="Potential business or technical impact",
    )
    involved_findings: list[str] = Field(          # <-- NEW
        default_factory=list,
        description="List of finding IDs that form this attack path",
    )


class Remediation(BaseModel):
    finding_id: str = Field(
        ..., description="The ID of the finding this relates to"
    )
    title: str = Field(..., description="Short title for the fix")
    remediation_steps: list[str] = Field(
        ..., description="Step-by-step human-readable instructions to fix the issue"
    )
    patch_content: str | None = Field(
        default=None,
        description="Optional unified diff or patch content to apply automatically",
    )


class AIAnalysisResponse(BaseModel):
    executive_summary: str = Field(
        ..., description="High-level summary of the security posture"
    )
    risk_score: float = Field(
        ..., ge=-1, le=100, description="Overall risk score between -1 and 100. -1 means analysis failed."
    )
    attack_paths: list[AttackPath] = Field(default_factory=list)
    top_remediations: list[Remediation] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------
def _count_tokens(text: str) -> int:
    if TOKENIZER:
        try:
            return len(TOKENIZER.encode(text))
        except Exception:
            logger.debug("tiktoken encoding failed, falling back to character count", exc_info=True)
    return len(text) // 4


def _sanitize_for_prompt(text: str) -> str:
    """Remove control characters and null bytes to prevent prompt injection."""
    if not isinstance(text, str):
        return ""
    # Remove null bytes
    text = text.replace("\x00", "")
    # Remove ASCII control characters except tab, newline, carriage return
    text = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f]", "", text)
    return text


def _sanitize_finding(finding: dict[str, Any]) -> dict[str, Any]:
    sanitized: dict[str, Any] = {}
    for key, value in finding.items():
        if isinstance(value, str):
            sanitized[key] = _sanitize_for_prompt(value)
        elif isinstance(value, dict):
            sanitized[key] = _sanitize_finding(value)
        elif isinstance(value, list):
            sanitized[key] = [
                _sanitize_finding(item) if isinstance(item, dict)
                else _sanitize_for_prompt(item) if isinstance(item, str)
                else item
                for item in value
            ]
        else:
            sanitized[key] = value
    return sanitized


# ---------------------------------------------------------------------------
# Base Analyzer
# ---------------------------------------------------------------------------
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
            return "llama3.2:latest"
        return model

    def _build_prompt(
        self,
        findings: list[dict[str, Any]],
        topology: dict[str, Any] | None = None,
        include_topology: bool = False,
    ) -> str:
        boundary = uuid.uuid4().hex
        start_tag = f"<FINDINGS_DATA_{boundary}>"
        end_tag = f"</FINDINGS_DATA_{boundary}>"

        # Sanitize all findings before putting them in the prompt
        [_sanitize_finding(f) for f in findings]

        topology_text = ""
        if include_topology and topology:
            topo_str = json.dumps(topology)
            topology_text = (
                f"\nAsset Topology:\n{topo_str[:2000]}"
                + ("... [TRUNCATED]" if len(topo_str) > 2000 else "")
            )

        prompt = f"""Analyze the following security findings.

IMPORTANT: Your response must be a single JSON object with exactly these fields:
- "executive_summary": string (high-level summary)
- "risk_score": number between 0 and 100
- "attack_paths": list of objects with "title", "description", "impact", and
  "involved_findings" (list of finding IDs that form this attack path)
- "top_remediations": list of objects with "finding_id", "title",
  "remediation_steps" (list of strings), and optionally "patch_content"
  (a string containing the exact code patch to apply, or null)

Make sure every object in "attack_paths" includes all four fields.
Do NOT include any other text or the JSON schema. Output ONLY the JSON object.

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
                risk_score=-1.0,
            ).model_dump()

        if "$defs" in extracted or "properties" in extracted:
            logger.error(
                "LLM returned the JSON schema instead of analysis. "
                "Using safe fallback."
            )
            return AIAnalysisResponse(
                executive_summary="AI analysis failed due to invalid model output. Please retry.",
                risk_score=-1.0,
            ).model_dump()

        try:
            validated_data = AIAnalysisResponse(**extracted)
            return validated_data.model_dump()
        except ValidationError as e:
            logger.error(f"LLM output failed strict schema validation: {e}")
            return AIAnalysisResponse(
                executive_summary="Analysis completed but output formatting was corrupted.",
                risk_score=-1.0,
            ).model_dump()

    def merge_analyses(
        self, analyses: list[dict[str, Any]], chunk_sizes: list[int]
    ) -> dict[str, Any]:
        if not analyses:
            return AIAnalysisResponse(
                executive_summary="No data analyzed.", risk_score=0.0
            ).model_dump()
        if len(analyses) == 1:
            return analyses[0]

        total_items = sum(chunk_sizes)
        if total_items > 0:
            weighted_score = sum(
                a.get("risk_score", 0) * size
                for a, size in zip(analyses, chunk_sizes, strict=False)
                if a.get("risk_score", -1) >= 0
            ) / total_items
        else:
            weighted_score = 0.0

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
                fid = r.get("finding_id")
                if fid and fid not in seen_finding_ids:
                    seen_finding_ids.add(fid)
                    merged_remediations.append(r)

        merged_paths = []
        for a in analyses:
            merged_paths.extend(a.get("attack_paths", []))

        return {
            "executive_summary": merged_summary,
            "risk_score": round(weighted_score, 1),
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
        chunk_size: int = 5,
    ) -> dict[str, Any]:
        # Use chunk_size to split findings into smaller batches
        chunks = [findings[i:i + chunk_size] for i in range(0, len(findings), chunk_size)]

        if len(chunks) > 10:
            logger.warning(
                f"High load: Processing {len(chunks)} chunks. "
                "Consider increasing 'chunk_size' to reduce overhead."
            )

        sem = asyncio.Semaphore(5)

        async def _sem_task(chunk, include_topo=False):
            async with sem:
                prompt = self._build_prompt(chunk, topology, include_topo)
                return await self._analyze_chunk(prompt)

        tasks = [_sem_task(chunks[i], i == 0) for i in range(len(chunks))]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        valid_results: list[dict[str, Any]] = []
        valid_chunk_sizes: list[int] = []
        for res, chunk in zip(results, chunks, strict=False):
            if not isinstance(res, Exception):
                valid_results.append(cast(dict[str, Any], res))
                valid_chunk_sizes.append(len(chunk))

        merged = self.merge_analyses(valid_results, valid_chunk_sizes)

        # ------------------------------------------------------------------
        # Deterministic sanity check – uses dynamic_risk_score to set a floor.
        # ------------------------------------------------------------------
        # Compute average dynamic_risk_score as a floor
        dynamic_scores = [
            f.get("dynamic_risk_score", 0.0)
            for f in findings
            if isinstance(f.get("dynamic_risk_score"), (int, float))
        ]
        if dynamic_scores:
            avg_dynamic = sum(dynamic_scores) / len(dynamic_scores)
            # Scale from 0-10 to 0-100
            deterministic_floor = min(100.0, avg_dynamic * 10.0)
        else:
            deterministic_floor = 0.0

        if merged["risk_score"] < 0:
            pass  # already marked as failure
        elif merged["risk_score"] < deterministic_floor * 0.6:
            logger.warning(
                f"LLM reported risk {merged['risk_score']}, but deterministic "
                f"floor is {deterministic_floor:.1f}. Overriding to deterministic floor."
            )
            merged["risk_score"] = round(deterministic_floor, 1)

        return merged


# ---------------------------------------------------------------------------
# Ollama implementation
# ---------------------------------------------------------------------------
class OllamaAnalyzer(AIAnalyzer):
    def __init__(
        self, model_name: str = "llama3.2:latest", timeout: int = 300
    ) -> None:
        super().__init__(model_name, timeout)
        raw_url = os.environ.get(
            "OLLAMA_API_BASE", "http://localhost:11434/api/generate"
        )
        parsed = urlparse(raw_url)
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
                "Each attack path must include title, description, impact, and involved_findings. "
                "Each remediation may optionally include patch_content. "
                "Output ONLY the JSON object, no other text."
            ),
        }
        async with httpx.AsyncClient(timeout=timeout_config) as client:
            resp = await client.post(self.endpoint, json=payload)
            resp.raise_for_status()
            data = resp.json()
            if "error" in data:
                logger.error(f"Ollama API error: {data['error']}")
                raise RuntimeError(f"Ollama API error: {data['error']}")
            return self._extract_and_validate_json(
                data.get("response", "{}")
            )


# ---------------------------------------------------------------------------
# LiteLLM implementation
# ---------------------------------------------------------------------------
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
                        "Each attack path must include title, description, impact, and involved_findings. "
                        "Each remediation may optionally include patch_content. "
                        "Output ONLY the JSON object, no other text."
                    ),
                },
                {"role": "user", "content": prompt},
            ],
            timeout=self.timeout,
            response_format={"type": "json_object"},
            drop_params=True,
        )
        content = response.choices[0].message.content
        return self._extract_and_validate_json(content)


# ---------------------------------------------------------------------------
# Factory function
# ---------------------------------------------------------------------------
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
