import json
import os
import re
import requests
from typing import List, Dict, Any, Optional

FEW_SHOT_EXAMPLE = {
    "executive_summary": "The pipeline shows a critical vulnerability in the web server...",
    "risk_score": 85,
    "attack_paths": [
        {
            "name": "Example Attack Path",
            "description": "...",
            "involved_findings": ["CVE-2026-1234"],
            "mitre_tactics": ["TA0001"],
            "mitre_techniques": ["T1190"]
        }
    ],
    "top_remediations": [
        {
            "priority": 1,
            "finding_id": "CVE-2026-1234",
            "action": "Upgrade package X to version Y",
            "fix_diff": "--- a/requirements.txt\n+++ b/requirements.txt\n-package==1.0\n+package==1.1"
        }
    ]
}

class BaseAnalyzer:
    def analyze(self, findings: List[Dict[str, Any]], topology: Dict[str, Any] = None) -> Dict[str, Any]:
        raise NotImplementedError

def extract_json(text: str) -> Dict[str, Any]:
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        match = re.search(r'\{.*\}', text, re.DOTALL)
        if match:
            try:
                return json.loads(match.group(0))
            except:
                pass
    return {"executive_summary": text, "attack_paths": [], "top_remediations": []}

def select_findings_for_llm(findings: List[Dict], max_items: int = 100) -> List[Dict]:
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
    def __init__(self, model: str = None, endpoint: str = None):
        self.model = model or os.environ.get("PIPELINE_LLM_MODEL", "llama3.2:latest")
        self.endpoint = endpoint or os.environ.get("OPENAI_API_BASE", "http://localhost:11434/api/generate")

    def analyze(self, findings: List[Dict[str, Any]], topology: Dict[str, Any] = None) -> Dict[str, Any]:
        if not findings:
            return {"executive_summary": "No findings.", "attack_paths": [], "top_remediations": []}

        selected = select_findings_for_llm(findings)
        topology_text = ""
        if topology:
            topology_text = f"\nAsset Topology:\n{json.dumps(topology, indent=2)}"

        prompt = f"""You are a DevSecOps expert. Analyze the findings below.
Example output structure:
{json.dumps(FEW_SHOT_EXAMPLE, indent=2)}

IMPORTANT: Each remediation must reference the exact 'id' of the finding.

Findings:
{json.dumps(selected, indent=2)}
{topology_text}

Respond ONLY with valid JSON in the same format as the example."""

        try:
            resp = requests.post(
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
    def __init__(self, model: str = None):
        try:
            import litellm
            self.litellm = litellm
        except ImportError:
            raise ImportError("Install litellm: pip install litellm")
        self.model = model or os.environ.get("PIPELINE_LLM_MODEL", "gpt-4o-mini")

    def analyze(self, findings: List[Dict[str, Any]], topology: Dict[str, Any] = None) -> Dict[str, Any]:
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

def get_analyzer(backend: str = "ollama", model: str = None) -> BaseAnalyzer:
    if backend == "litellm":
        return LiteLLMAnalyzer(model=model)
    return OllamaAnalyzer(model=model)