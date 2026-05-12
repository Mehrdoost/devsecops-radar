import json
import os
import requests
from typing import List, Dict, Any, Optional

class BaseAnalyzer:
    def analyze(self, findings: List[Dict[str, Any]]) -> str:
        raise NotImplementedError

class OllamaAnalyzer(BaseAnalyzer):
    def __init__(self, model: str = "llama3.2:latest", endpoint: str = "http://localhost:11434/api/generate"):
        self.model = model
        self.endpoint = endpoint

    def analyze(self, findings: List[Dict[str, Any]]) -> str:
        if not findings:
            return "No findings to analyze."

        criticals = [f for f in findings if f.get("severity") == "CRITICAL"]
        highs = [f for f in findings if f.get("severity") == "HIGH"]
        mediums = [f for f in findings if f.get("severity") == "MEDIUM"]
        lows = [f for f in findings if f.get("severity") == "LOW"]

        prompt = f"""You are a DevSecOps security expert. Analyze the following aggregated security findings from CI/CD scanners (Trivy, Semgrep, Poutine, Zizmor).
Total findings: {len(findings)} (CRITICAL: {len(criticals)}, HIGH: {len(highs)}, MEDIUM: {len(mediums)}, LOW: {len(lows)})

List of findings:
{json.dumps(findings, indent=2)}

Provide:
1. A short executive summary (2-3 sentences) of the overall risk.
2. Identify possible attack paths (e.g., "a vulnerable package combined with an exposed secret could lead to RCE").
3. Recommend the top 3 most critical actions to fix.
Keep the response concise and use bullet points."""
        try:
            resp = requests.post(
                self.endpoint,
                json={"model": self.model, "prompt": prompt, "stream": False},
                timeout=120
            )
            resp.raise_for_status()
            result = resp.json()
            return result.get("response", "No AI response.")
        except Exception as e:
            return f"AI analysis failed: {str(e)}"