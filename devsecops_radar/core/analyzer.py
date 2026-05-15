import json
import os
import hashlib
import requests
from typing import List, Dict, Any, Optional

class BaseAnalyzer:
    def analyze(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        raise NotImplementedError

class OllamaAnalyzer(BaseAnalyzer):
    def __init__(self, model: str = None, endpoint: str = None):
        self.model = model or os.environ.get("PIPELINE_LLM_MODEL", "llama3.2:latest")
        self.endpoint = endpoint or os.environ.get(
            "PIPELINE_LLM_ENDPOINT", "http://localhost:11434/api/generate"
        )

    def analyze(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        if not findings:
            return {"executive_summary": "No findings to analyze.", "attack_paths": [], "top_remediations": []}

        criticals = [f for f in findings if f.get("severity") == "CRITICAL"]
        highs = [f for f in findings if f.get("severity") == "HIGH"]
        mediums = [f for f in findings if f.get("severity") == "MEDIUM"]
        lows = [f for f in findings if f.get("severity") == "LOW"]

        findings_hash = hashlib.sha256(json.dumps(findings, sort_keys=True).encode()).hexdigest()

        prompt = f"""You are a senior DevSecOps security architect. Analyze the following aggregated security findings from CI/CD scanners (Trivy, Semgrep, Poutine, Zizmor).

Total findings: {len(findings)} (CRITICAL: {len(criticals)}, HIGH: {len(highs)}, MEDIUM: {len(mediums)}, LOW: {len(lows)})

Findings:
{json.dumps(findings, indent=2)}

Respond ONLY with valid JSON in this exact structure:
{{
  "executive_summary": "2-3 sentence summary of overall risk posture",
  "risk_score": 0-100,
  "attack_paths": [
    {{
      "name": "Short attack path name",
      "description": "How an attacker could chain multiple findings together",
      "involved_findings": ["id1", "id2"],
      "potential_impact": "What the attacker could achieve",
      "difficulty": "low|medium|high"
    }}
  ],
  "top_remediations": [
    {{
      "priority": 1,
      "finding_id": "id of the finding to fix",
      "action": "Specific, actionable step to remediate"
    }}
  ],
  "false_positives_likely": ["id of any finding that appears to be a false positive"]
}}

Important: Only include attack paths that are actually possible based on the findings. Do not invent scenarios. Base your analysis strictly on the provided data."""

        try:
            resp = requests.post(
                self.endpoint,
                json={"model": self.model, "prompt": prompt, "stream": False, "format": "json"},
                timeout=120
            )
            resp.raise_for_status()
            result = resp.json()
            response_text = result.get("response", "{}")
            try:
                return json.loads(response_text)
            except json.JSONDecodeError:
                return {"executive_summary": response_text, "attack_paths": [], "top_remediations": []}
        except Exception as e:
            return {"executive_summary": f"AI analysis failed: {str(e)}", "attack_paths": [], "top_remediations": []}

class LiteLLMAnalyzer(BaseAnalyzer):
    def __init__(self, model: str = None):
        try:
            import litellm
            self.litellm = litellm
        except ImportError:
            raise ImportError("Install litellm: pip install litellm")
        self.model = model or os.environ.get("PIPELINE_LLM_MODEL", "gpt-4o-mini")

    def analyze(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        if not findings:
            return {"executive_summary": "No findings to analyze.", "attack_paths": [], "top_remediations": []}

        prompt = f"""You are a senior DevSecOps security architect. Analyze these findings:
{json.dumps(findings, indent=2)}

Respond ONLY with JSON:
{{
  "executive_summary": "...",
  "risk_score": 0-100,
  "attack_paths": [...],
  "top_remediations": [...]
}}"""

        try:
            response = self.litellm.completion(
                model=self.model,
                messages=[{"role": "user", "content": prompt}],
                temperature=0.1,
                response_format={"type": "json_object"}
            )
            return json.loads(response.choices[0].message.content)
        except Exception as e:
            return {"executive_summary": f"AI analysis failed: {str(e)}", "attack_paths": [], "top_remediations": []}

def get_analyzer(backend: str = "ollama", model: str = None) -> BaseAnalyzer:
    if backend == "litellm":
        return LiteLLMAnalyzer(model=model)
    return OllamaAnalyzer(model=model)