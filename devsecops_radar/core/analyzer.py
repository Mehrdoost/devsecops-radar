import json
import os
import re
from typing import Any

import httpx
from loguru import logger

MAX_ANALYZER_FINDINGS = int(os.environ.get("ANALYZER_MAX_FINDINGS", "100"))
ANALYZER_TIMEOUT = int(os.environ.get("ANALYZER_TIMEOUT", "1800"))

FEW_SHOT_EXAMPLE = {
    "executive_summary": (
        "A leaked CI/CD credential combined with an unpatched container image "
        "creates a critical supply chain attack path. Immediate action is required."
    ),
    "risk_score": 92,
    "attack_paths": [
        {
            "name": "Supply Chain Compromise via Credential Leak",
            "description": (
                "An exposed GitHub Actions secret (ID: SECRET-001) allows an attacker "
                "to push malicious images to the container registry. Combined with a known "
                "RCE vulnerability in the web server (CVE-2026-1234), this chain grants "
                "full control over the production environment."
            ),
            "involved_findings": ["SECRET-001", "CVE-2026-1234"],
            "mitre_tactics": ["TA0001", "TA0042"],
            "mitre_techniques": ["T1078", "T1578"],
            "potential_impact": "Full compromise of production services",
            "difficulty": "medium",
            "enrichment": {
                "nist_nvd": "https://nvd.nist.gov/vuln/detail/CVE-2026-1234",
                "github_advisory": "https://github.com/advisories/GHSA-xxxx-xxxx-xxxx",
                "poc_available": True
            }
        }
    ],
    "top_remediations": [
        {
            "priority": 1,
            "finding_id": "SECRET-001",
            "action": (
                "Rotate the exposed secret and remove it from the workflow log. "
                "Use GitHub's masked variables."
            ),
            "fix_diff": (
                "--- a/.github/workflows/deploy.yml\n"
                "+++ b/.github/workflows/deploy.yml\n"
                "- run: echo ${{ secrets.DEPLOY_KEY }}\n"
                "+ run: echo '**redacted**'"
            ),
            "remediation_steps": [
                "1. Go to GitHub repository Settings → Secrets",
                "2. Delete the compromised DEPLOY_KEY",
                "3. Generate a new secret and update the workflow to use ${{ secrets.NEW_KEY }}",
                "4. Verify the workflow no longer echoes the secret"
            ]
        }
    ],
    "false_positives_likely": []
}


def _build_prompt(findings: list[dict[str, Any]], topology: dict[str, Any] | None = None) -> str:
    topology_text = ""
    if topology:
        topology_text = f"\nAsset Topology:\n{json.dumps(topology, indent=2)}"
    prompt = f"""You are a DevSecOps expert. Analyze the findings below.
Example output structure:
{json.dumps(FEW_SHOT_EXAMPLE, indent=2)}

IMPORTANT:
- Each remediation must reference the exact 'id' of the finding.
- Identify multi-step attack chains.
- For each attack path, provide enrichment links (NIST NVD, GitHub Advisory) and indicate if a PoC is available.
- For each remediation, provide step-by-step instructions in `remediation_steps`.

Findings:
{json.dumps(findings, indent=2)}
{topology_text}

Respond ONLY with valid JSON in the same format as the example."""
    return prompt


class BaseAnalyzer:
    async def analyze(
        self, findings: list[dict[str, Any]], topology: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        raise NotImplementedError


def extract_json(text: str) -> dict[str, Any]:
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        match = re.search(r'\{.*\}', text, re.DOTALL)
        if match:
            try:
                return json.loads(match.group(0))
            except json.JSONDecodeError:
                pass
    return {"executive_summary": text, "attack_paths": [], "top_remediations": []}


def merge_analyses(analyses: list[dict[str, Any]]) -> dict[str, Any]:
    if not analyses:
        return {"executive_summary": "No analysis performed.", "attack_paths": [], "top_remediations": []}

    merged = {
        "executive_summary": "",
        "attack_paths": [],
        "top_remediations": [],
        "risk_score": 0
    }

    summaries = []
    max_risk = 0

    for a in analyses:
        if a.get("executive_summary"):
            summaries.append(a.get("executive_summary"))
        merged["attack_paths"].extend(a.get("attack_paths", []))
        merged["top_remediations"].extend(a.get("top_remediations", []))
        if a.get("risk_score", 0) > max_risk:
            max_risk = a.get("risk_score", 0)

    if len(summaries) > 1:
        merged["executive_summary"] = "Composite Summary: " + " | ".join(summaries[:3])
        if len(summaries) > 3:
            merged["executive_summary"] += " ... (multiple chunks analyzed)"
    elif summaries:
        merged["executive_summary"] = summaries[0]

    merged["risk_score"] = max_risk

    return merged


class OllamaAnalyzer(BaseAnalyzer):
    def __init__(self, model: str | None = None, endpoint: str | None = None):
        self.model = model or os.environ.get("PIPELINE_LLM_MODEL", "llama3.2:latest")
        self.endpoint = endpoint or os.environ.get("OPENAI_API_BASE", "http://localhost:11434/api/generate")
        self.timeout = float(ANALYZER_TIMEOUT)

    async def _analyze_chunk(self, chunk: list[dict[str, Any]], topology: dict[str, Any] | None) -> dict[str, Any]:
        prompt = _build_prompt(chunk, topology)
        try:
            timeout_config = httpx.Timeout(self.timeout, read=None)
            async with httpx.AsyncClient(timeout=timeout_config) as client:
                resp = await client.post(
                    self.endpoint,
                    json={"model": self.model, "prompt": prompt, "stream": False, "format": "json"},
                )
                resp.raise_for_status()
                result = resp.json()
                return extract_json(result.get("response", "{}"))
        except Exception as e:
            logger.error(f"Ollama chunk analysis failed: {e}")
            return {"executive_summary": "", "attack_paths": [], "top_remediations": []}

    async def analyze(
        self, findings: list[dict[str, Any]], topology: dict[str, Any] | None = None, chunk_size: int = 0
    ) -> dict[str, Any]:
        if not findings:
            return {"executive_summary": "No findings.", "attack_paths": [], "top_remediations": []}

        if chunk_size > 0 and len(findings) > chunk_size:
            logger.info(f"Chunking enabled: Splitting {len(findings)} findings into chunks of {chunk_size}")
            results = []
            for i in range(0, len(findings), chunk_size):
                chunk = findings[i:i + chunk_size]
                logger.info(f"Processing chunk {i//chunk_size + 1}/{(len(findings) + chunk_size - 1)//chunk_size}...")
                res = await self._analyze_chunk(chunk, topology)
                results.append(res)
            return merge_analyses(results)
        else:
            return await self._analyze_chunk(findings, topology)


class LiteLLMAnalyzer(BaseAnalyzer):
    def __init__(self, model: str | None = None):
        try:
            import litellm
            self.litellm = litellm
        except ImportError as err:
            raise ImportError("Install litellm: pip install litellm") from err
        self.model = model or os.environ.get("PIPELINE_LLM_MODEL", "gpt-4o-mini")

    async def _analyze_chunk(self, chunk: list[dict[str, Any]], topology: dict[str, Any] | None) -> dict[str, Any]:
        prompt = _build_prompt(chunk, topology)
        try:
            response = await self.litellm.acompletion(
                model=self.model,
                messages=[{"role": "user", "content": prompt}],
                temperature=0.1,
                response_format={"type": "json_object"}
            )
            return extract_json(response.choices[0].message.content)
        except Exception as e:
            logger.error(f"LiteLLM chunk analysis failed: {e}")
            return {"executive_summary": "", "attack_paths": [], "top_remediations": []}

    async def analyze(
        self, findings: list[dict[str, Any]], topology: dict[str, Any] | None = None, chunk_size: int = 0
    ) -> dict[str, Any]:
        if not findings:
            return {"executive_summary": "No findings.", "attack_paths": [], "top_remediations": []}

        if chunk_size > 0 and len(findings) > chunk_size:
            logger.info(f"Chunking enabled: Splitting {len(findings)} findings into chunks of {chunk_size}")
            results = []
            for i in range(0, len(findings), chunk_size):
                chunk = findings[i:i + chunk_size]
                logger.info(f"Processing chunk {i//chunk_size + 1}/{(len(findings) + chunk_size - 1)//chunk_size}...")
                res = await self._analyze_chunk(chunk, topology)
                results.append(res)
            return merge_analyses(results)
        else:
            return await self._analyze_chunk(findings, topology)


def get_analyzer(backend: str = "ollama", model: str | None = None) -> BaseAnalyzer:
    if backend == "litellm":
        return LiteLLMAnalyzer(model=model)
    return OllamaAnalyzer(model=model)
