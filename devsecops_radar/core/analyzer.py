import json
import os
import hashlib
import re
import requests
from typing import List, Dict, Any, Optional

class BaseAnalyzer:
    def analyze(self, findings: List[Dict[str, Any]], topology: Dict[str, Any] = None) -> Dict[str, Any]:
        raise NotImplementedError

def extract_json(text: str) -> Dict[str, Any]:
    """Try to extract a JSON object from a string that may contain extra text."""
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        # Attempt to find a JSON object using regex
        match = re.search(r'\{.*\}', text, re.DOTALL)
        if match:
            try:
                return json.loads(match.group(0))
            except:
                pass
    return {"executive_summary": text, "attack_paths": [], "top_remediations": []}

class OllamaAnalyzer(BaseAnalyzer):
    def __init__(self, model: str = None, endpoint: str = None):
        self.model = model or os.environ.get("PIPELINE_LLM_MODEL", "llama3.2:latest")
        self.endpoint = endpoint or os.environ.get(
            "PIPELINE_LLM_ENDPOINT", "http://localhost:11434/api/generate"
        )

    def analyze(self, findings: List[Dict[str, Any]], topology: Dict[str, Any] = None) -> Dict[str, Any]:
        if not findings:
            return {"executive_summary": "No findings to analyze.", "attack_paths": [], "top_remediations": []}

        # Build prompt
        topology_text = ""
        if topology:
            topology_text = f"\nAsset Topology:\n{json.dumps(topology, indent=2)}"

        prompt = f"""You are a senior DevSecOps security architect. Analyze the following security findings from CI/CD scanners.
Total findings: {len(findings)}
Findings:
{json.dumps(findings, indent=2)}
{topology_text}
Respond ONLY with valid JSON in this structure:
{{
  "executive_summary": "2-3 sentence summary",
  "risk_score": 0-100,
  "attack_paths": [
    {{
      "name": "Attack path name",
      "description": "How an attacker could chain findings across assets",
      "involved_findings": ["id1", "id2"],
      "potential_impact": "Result of successful attack",
      "difficulty": "low|medium|high",
      "mitre_tactics": ["TA0001", "TA0003"],
      "mitre_techniques": ["T1190", "T1059"]
    }}
  ],
  "top_remediations": [
    {{
      "priority": 1,
      "finding_id": "id",
      "action": "Specific fix step",
      "fix_diff": "unified diff to apply the fix (if applicable)"
    }}
  ],
  "false_positives_likely": ["id"]
}}"""

        try:
            resp = requests.post(
                self.endpoint,
                json={"model": self.model, "prompt": prompt, "stream": False, "format": "json"},
                timeout=180
            )
            resp.raise_for_status()
            result = resp.json()
            response_text = result.get("response", "{}")
            analysis = extract_json(response_text)
            return analysis
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

    def analyze(self, findings: List[Dict[str, Any]], topology: Dict[str, Any] = None) -> Dict[str, Any]:
        if not findings:
            return {"executive_summary": "No findings to analyze.", "attack_paths": [], "top_remediations": []}

        topology_text = ""
        if topology:
            topology_text = f"\nAsset Topology:\n{json.dumps(topology, indent=2)}"

        prompt = f"""You are a senior DevSecOps security architect. Analyze the following findings.
{json.dumps(findings, indent=2)}
{topology_text}
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
            return extract_json(response.choices[0].message.content)
        except Exception as e:
            return {"executive_summary": f"AI analysis failed: {str(e)}", "attack_paths": [], "top_remediations": []}

def get_analyzer(backend: str = "ollama", model: str = None) -> BaseAnalyzer:
    if backend == "litellm":
        return LiteLLMAnalyzer(model=model)
    return OllamaAnalyzer(model=model)