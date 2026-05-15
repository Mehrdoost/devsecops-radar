import json
import os
import subprocess
from pathlib import Path
from typing import List, Dict, Any

class RuleFusion:
    """
    A hybrid rule engine that loads custom rules from local directories
    and can optionally pull community-curated rules from a git repository.
    """

    def __init__(self, local_rules_path: str = None, community_repo: str = None):
        self.local_rules_path = Path(local_rules_path) if local_rules_path else None
        self.community_repo = community_repo or "https://github.com/Mehrdoost/devsecops-radar-rules.git"
        self.findings: List[Dict[str, Any]] = []

    def load_all_rules(self) -> List[Dict[str, Any]]:
        """Load rules from both local and community sources."""
        if self.local_rules_path and self.local_rules_path.exists():
            self._load_from_directory(self.local_rules_path)

        community_dir = Path.home() / ".devsecops-radar" / "community-rules"
        if community_dir.exists():
            self._load_from_directory(community_dir)

        return self.findings

    def update_community_rules(self) -> None:
        """Clone or pull the latest community rules repository."""
        target_dir = Path.home() / ".devsecops-radar" / "community-rules"
        target_dir.parent.mkdir(parents=True, exist_ok=True)

        if (target_dir / ".git").exists():
            print("🔄 Updating community rules...")
            subprocess.run(["git", "-C", str(target_dir), "pull"], check=True)
        else:
            print("📥 Downloading community rules for the first time...")
            subprocess.run(["git", "clone", self.community_repo, str(target_dir)], check=True)

        print(f"✅ Community rules updated at {target_dir}")
        print(f"   To use them, run: devsecops-radar --trivy ... --rules {target_dir}")

    def _load_from_directory(self, directory: Path) -> None:
        """Recursively load all JSON files from a directory."""
        for json_file in sorted(directory.rglob("*.json")):
            try:
                with open(json_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                parsed = self._parse_scanner_output(data, json_file.name)
                self.findings.extend(parsed)
                print(f"📄 Loaded {len(parsed)} findings from {json_file.name}")
            except json.JSONDecodeError:
                print(f"⚠️ Skipping invalid JSON: {json_file.name}")
            except Exception as e:
                print(f"❌ Error loading {json_file.name}: {e}")

    def _parse_scanner_output(self, data: Any, filename: str) -> List[Dict[str, Any]]:
        """Parse any known scanner format."""
        findings = []

        if isinstance(data, list):
            for item in data:
                if isinstance(item, dict) and self._is_finding(item):
                    findings.append(self._normalize(item, filename))
            return findings

        if not isinstance(data, dict):
            return findings

        # Trivy format
        for result in data.get("Results", []):
            for vuln in result.get("Vulnerabilities", []):
                findings.append({
                    "tool": "Trivy",
                    "target": result.get("Target", filename),
                    "id": vuln.get("VulnerabilityID", ""),
                    "severity": vuln.get("Severity", "UNKNOWN").upper(),
                    "title": vuln.get("Title", ""),
                    "description": vuln.get("Description", ""),
                    "package": vuln.get("PkgName", ""),
                    "installed_version": vuln.get("InstalledVersion", ""),
                    "fixed_version": vuln.get("FixedVersion", ""),
                })

        # Semgrep format
        for result in data.get("results", []):
            findings.append({
                "tool": "Semgrep",
                "target": result.get("path", filename),
                "id": result.get("check_id", ""),
                "severity": (result.get("extra", {}).get("severity", "WARNING")).upper(),
                "title": result.get("check_id", ""),
                "description": result.get("extra", {}).get("message", ""),
                "line": (result.get("start", {}) or {}).get("line", 0),
            })

        # Poutine / Zizmor / Generic format
        for item in data.get("findings", []):
            if isinstance(item, dict):
                findings.append(self._normalize(item, filename))

        return findings

    def _is_finding(self, item: dict) -> bool:
        return any(k in item for k in ("severity", "Severity", "rule_id", "check_id", "VulnerabilityID"))

    def _normalize(self, raw: dict, filename: str) -> Dict[str, Any]:
        return {
            "tool": raw.get("tool", "Custom Rule"),
            "target": raw.get("target") or raw.get("path") or (raw.get("location") or {}).get("file") or filename,
            "id": raw.get("id") or raw.get("rule_id") or raw.get("check_id") or raw.get("VulnerabilityID") or "CUSTOM-001",
            "severity": (raw.get("severity") or raw.get("Severity") or "MEDIUM").upper(),
            "title": raw.get("title") or raw.get("message") or raw.get("Title") or "Custom Rule Finding",
            "description": raw.get("description") or raw.get("Description") or (raw.get("extra") or {}).get("message", ""),
            "line": raw.get("line") or (raw.get("location") or {}).get("line") or (raw.get("start") or {}).get("line"),
        }

    def generate_template(self, scanner_name: str) -> str:
        """Generate a sample rule file for the user to start with."""
        template = {
            "findings": [
                {
                    "tool": scanner_name,
                    "target": "path/to/target_file",
                    "id": "CUSTOM-2026-001",
                    "severity": "MEDIUM",
                    "title": "Short description of the finding",
                    "description": "Detailed description of the vulnerability and how to fix it.",
                    "line": 1
                }
            ]
        }
        return json.dumps(template, indent=2)