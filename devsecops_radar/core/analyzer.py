import json
import os
import re
from typing import Any

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


def _session_with_retries(total=3, backoff_factor=0.5, status_forcelist=None):
    if status_forcelist is None:
        status_forcelist = [429, 500, 502, 503, 504]
    session = requests.Session()
    retries = Retry(
        total=total,
        backoff_factor=backoff_factor,
        status_forcelist=status_forcelist,
        allowed_methods=["POST"]
    )
    adapter = HTTPAdapter(max_retries=retries)
    session.mount('http://', adapter)
    session.mount('https://', adapter)
    return session


MAX_ANALYZER_FINDINGS = int(os.environ.get("ANALYZER_MAX_FINDINGS", "100"))

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
            "difficulty": "medium"
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
            )
        }
    ],
    "false_positives_likely": []
}


class BaseAnalyzer:
    def analyze(self, findings: list[dict[str, Any]], topology: dict[str, Any] | None = None) -> dict[str, Any]:
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


def select_findings_for_llm(findings: list[dict], max_items: int = MAX_ANALYZER_FINDINGS) -> list[dict]:
    if len(findings) <= max_items:
        return findings
    critical_high = [f for f in findings if f.get('severity') in ('CRITICAL', 'HIGH')]
    others = [f for f in findings if f not in critical_high]
    selected = critical_high[:max_items]
    remaining = max_items - len(selected)
    if remaining > 0:
        selected.extend(others[:remaining])
    return selected


class OllamaAnalyzer(BaseAnalyzer):
    def __init__(self, model: str | None = None, endpoint: str | None = None):
        self.model = model or os.environ.get("PIPELINE_LLM_MODEL", "llama3.2:latest")
        self.endpoint = endpoint or os.environ.get("OPENAI_API_BASE", "http://localhost:11434/api/generate")
        self.session = _session_with_retries()

    def analyze(self, findings: list[dict[str, Any]], topology: dict[str, Any] | None = None) -> dict[str, Any]:
        if not findings:
            return {"executive_summary": "No findings.", "attack_paths": [], "top_remediations": []}

        selected = select_findings_for_llm(findings)
        topology_text = ""
        if topology:
            topology_text = f"\nAsset Topology:\n{json.dumps(topology, indent=2)}"

        prompt = f"""You are a DevSecOps expert. Analyze the findings below.
Example output structure:
{json.dumps(FEW_SHOT_EXAMPLE, indent=2)}

IMPORTANT: Each remediation must reference the exact 'id' of the finding. Identify multi-step attack chains.

Findings:
{json.dumps(selected, indent=2)}
{topology_text}

Respond ONLY with valid JSON in the same format as the example."""

        try:
            resp = self.session.post(
                self.endpoint,
                json={"model": self.model, "prompt": prompt, "stream": False, "format": "json"},
                timeout=180
            )
            resp.raise_for_status()
            result = resp.json()
            return extract_json(result.get("response", "{}"))
        except Exception as e:
            return {"executive_summary": f"AI failed: {str(e)}", "attack_paths": [], "top_remediations": []}


class LiteLLMAnalyzer(BaseAnalyzer):
    def __init__(self, model: str | None = None):
        try:
            import litellm
            self.litellm = litellm
        except ImportError as err:
            raise ImportError("Install litellm: pip install litellm") from err
        self.model = model or os.environ.get("PIPELINE_LLM_MODEL", "gpt-4o-mini")

    def analyze(self, findings: list[dict[str, Any]], topology: dict[str, Any] | None = None) -> dict[str, Any]:
        if not findings:
            return {"executive_summary": "No findings.", "attack_paths": [], "top_remediations": []}

        selected = select_findings_for_llm(findings)
        topology_text = ""
        if topology:
            topology_text = f"\nAsset Topology:\n{json.dumps(topology, indent=2)}"

        prompt = f"""You are a DevSecOps expert. Example:
{json.dumps(FEW_SHOT_EXAMPLE, indent=2)}

Findings:
{json.dumps(selected, indent=2)}
{topology_text}

Respond ONLY with JSON like the example."""

        try:
            response = self.litellm.completion(
                model=self.model,
                messages=[{"role": "user", "content": prompt}],
                temperature=0.1,
                response_format={"type": "json_object"}
            )
            return extract_json(response.choices[0].message.content)
        except Exception as e:
            return {"executive_summary": f"AI failed: {str(e)}", "attack_paths": [], "top_remediations": []}


def get_analyzer(backend: str = "ollama", model: str | None = None) -> BaseAnalyzer:
    if backend == "litellm":
        return LiteLLMAnalyzer(model=model)
    return OllamaAnalyzer(model=model)
