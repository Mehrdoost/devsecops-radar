import json
import os
import subprocess
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple


class RuleFusion:
    """
    A hybrid rule engine that loads custom rules from local directories
    and can optionally pull community-curated rules from a git repository.
    Also supports policy-as-code evaluation.
    """

    def __init__(
        self,
        local_rules_path: str = None,
        community_repo: str = None,
    ):
        self.local_rules_path = (
            Path(local_rules_path) if local_rules_path else None
        )
        self.community_repo = community_repo or os.environ.get(
            "COMMUNITY_RULES_REPO",
            "https://github.com/Mehrdoost/devsecops-radar-rules.git"
        )
        self.findings: List[Dict[str, Any]] = []

    # ── public API ──────────────────────────────────────────────

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
            subprocess.run(
                ["git", "-C", str(target_dir), "pull"], check=True
            )
        else:
            print("📥 Downloading community rules for the first time...")
            subprocess.run(
                ["git", "clone", self.community_repo, str(target_dir)],
                check=True,
            )

        print(f"✅ Community rules updated at {target_dir}")
        print(
            f"   To use them, run: "
            f"devsecops-radar --trivy ... --rules {target_dir}"
        )

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
                    "description": (
                        "Detailed description of the vulnerability "
                        "and how to fix it."
                    ),
                    "line": 1,
                }
            ]
        }
        return json.dumps(template, indent=2)

    # ── policy engine ─────────────────────────────────────────

    @staticmethod
    def evaluate_policy(
        findings: List[Dict[str, Any]], policy_file: str
    ) -> Tuple[bool, str]:
        """
        Evaluate a policy file against the findings.
        Returns (pass, message).
        The policy file is a JSON object with conditions.
        Example: {"max_critical": 5, "on_violation": "fail"}
        """
        if not os.path.exists(policy_file):
            return True, (
                f"Policy file '{policy_file}' not found. "
                "Skipping evaluation."
            )

        with open(policy_file, "r") as f:
            policy = json.load(f)

        critical_count = sum(
            1 for f in findings if f.get("severity") == "CRITICAL"
        )
        max_critical = policy.get("max_critical")
        if max_critical is not None and critical_count > max_critical:
            action = policy.get("on_violation", "fail")
            msg = (
                f"Policy violation: CRITICAL findings ({critical_count}) "
                f"exceeds maximum allowed ({max_critical})."
            )
            if action == "fail":
                return False, msg
            else:
                return True, f"WARNING: {msg}"

        return True, "Policy checks passed."

    # ── internal helpers ────────────────────────────────────────

    def _load_from_directory(self, directory: Path) -> None:
        """Recursively load all JSON files from a directory."""
        for json_file in sorted(directory.rglob("*.json")):
            try:
                with open(json_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
            except json.JSONDecodeError:
                print(f"⚠️ Skipping invalid JSON: {json_file.name}")
                continue
            except Exception as e:
                print(f"❌ Error reading {json_file.name}: {e}")
                continue

            if not self._validate_json(data, json_file.name):
                continue

            parsed = self._parse_scanner_output(data, json_file.name)
            self.findings.extend(parsed)
            print(f"📄 Loaded {len(parsed)} findings from {json_file.name}")

    def _validate_json(self, data: Any, filename: str) -> bool:
        """Structural validation with better list handling."""
        if isinstance(data, list):
            if len(data) == 0:
                print(f"[WARNING] {filename}: empty list, skipping")
                return False
            for item in data:
                if isinstance(item, dict) and self._is_finding(item):
                    return True
            print(
                f"[WARNING] {filename}: list items do not look like "
                "findings, skipping"
            )
            return False
        if isinstance(data, dict):
            known_keys = {"Results", "results", "findings"}
            if any(k in data for k in known_keys):
                return True
            print(
                f"[WARNING] {filename}: unrecognised JSON structure, "
                "skipping"
            )
            return False
        print(f"[WARNING] {filename}: unexpected JSON type, skipping")
        return False

    def _parse_scanner_output(
        self, data: Any, filename: str
    ) -> List[Dict[str, Any]]:
        """Parse any known scanner format."""
        findings: List[Dict[str, Any]] = []

        # Already a plain list of findings
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
                findings.append(
                    {
                        "tool": "Trivy",
                        "target": result.get("Target", filename),
                        "id": vuln.get("VulnerabilityID", ""),
                        "severity": vuln.get("Severity", "UNKNOWN").upper(),
                        "title": vuln.get("Title", ""),
                        "description": vuln.get("Description", ""),
                        "package": vuln.get("PkgName", ""),
                        "installed_version": vuln.get(
                            "InstalledVersion", ""
                        ),
                        "fixed_version": vuln.get("FixedVersion", ""),
                    }
                )

        # Semgrep format
        for result in data.get("results", []):
            findings.append(
                {
                    "tool": "Semgrep",
                    "target": result.get("path", filename),
                    "id": result.get("check_id", ""),
                    "severity": (
                        result.get("extra", {})
                        .get("severity", "WARNING")
                    ).upper(),
                    "title": result.get("check_id", ""),
                    "description": result.get("extra", {}).get(
                        "message", ""
                    ),
                    "line": (result.get("start", {}) or {}).get("line", 0),
                }
            )

        # Poutine / Zizmor / Generic format
        for item in data.get("findings", []):
            if isinstance(item, dict):
                findings.append(self._normalize(item, filename))

        return findings

    def _is_finding(self, item: dict) -> bool:
        return any(
            k in item
            for k in (
                "severity",
                "Severity",
                "rule_id",
                "check_id",
                "VulnerabilityID",
            )
        )

    def _normalize(self, raw: dict, filename: str) -> Dict[str, Any]:
        return {
            "tool": raw.get("tool", "Custom Rule"),
            "target": (
                raw.get("target")
                or raw.get("path")
                or (raw.get("location") or {}).get("file")
                or filename
            ),
            "id": (
                raw.get("id")
                or raw.get("rule_id")
                or raw.get("check_id")
                or raw.get("VulnerabilityID")
                or "CUSTOM-001"
            ),
            "severity": (
                raw.get("severity") or raw.get("Severity") or "MEDIUM"
            ).upper(),
            "title": (
                raw.get("title")
                or raw.get("message")
                or raw.get("Title")
                or "Custom Rule Finding"
            ),
            "description": (
                raw.get("description")
                or raw.get("Description")
                or (raw.get("extra") or {}).get("message", "")
            ),
            "line": (
                raw.get("line")
                or (raw.get("location") or {}).get("line")
                or (raw.get("start") or {}).get("line")
            ),
        }