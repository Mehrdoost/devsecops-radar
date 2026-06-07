import json
import os
import subprocess
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from loguru import logger
from pydantic import BaseModel, Field, ValidationError


# --- Strict Schemas for Input Validation ---
class CustomRuleSchema(BaseModel):
    """Pydantic model to enforce strict validation on custom JSON rules."""
    id: str = Field(..., description="Unique identifier for the rule")
    tool: str = Field(default="Custom Rule", description="Name of the scanning tool")
    target: str = Field(..., description="File path or target affected")
    severity: str = Field(..., description="Risk severity: CRITICAL, HIGH, MEDIUM, LOW")
    title: str = Field(..., description="Short title of the vulnerability")
    description: str = Field(default="", description="Detailed explanation")


class RuleFusionEngine:
    """
    Engine responsible for aggregating, validating, and merging custom security rules.
    It does NOT parse Trivy or Semgrep outputs (that is the Adapters' job).
    """

    def __init__(self, rules_dir: str = "custom_rules", max_file_size_mb: int = 10) -> None:
        self.rules_dir = Path(rules_dir).resolve()
        self.max_file_size_bytes = max_file_size_mb * 1024 * 1024
        self.findings: list[dict[str, Any]] = []

        # Ensure rules directory exists securely
        if not self.rules_dir.exists():
            self.rules_dir.mkdir(parents=True, exist_ok=True)

    def _is_safe_path(self, target_path: Path) -> bool:
        """Prevent Path Traversal and Symlink attacks."""
        try:
            resolved_target = target_path.resolve(strict=False)
            return resolved_target.is_relative_to(self.rules_dir)
        except Exception as e:
            logger.error(f"Path resolution error: {e}")
            return False

    def update_community_rules(self) -> None:
        """
        Securely clones community rules from a whitelisted GitHub repository.
        Prevents SSRF and Command Injection.
        """
        repo_url = os.environ.get("COMMUNITY_RULES_REPO", "")
        if not repo_url:
            logger.info("No community repository configured. Skipping update.")
            return

        # 1. URL Validation (SSRF Protection)
        parsed_url = urlparse(repo_url)
        if parsed_url.scheme != "https" or parsed_url.netloc != "github.com":
            logger.error("Security Error: Community repo must be a valid https://github.com URL.")
            return

        # 2. Path Validation (Ensure no dangerous characters)
        if not repo_url.endswith(".git") or ";" in repo_url or " " in repo_url:
            logger.error(f"Security Error: Invalid characters in repo URL: {repo_url}")
            return

        target_dir = self.rules_dir / "community"

        # Safe Cloning using subprocess with strict arguments
        try:
            if target_dir.exists():
                logger.info("Updating existing community rules...")
                subprocess.run(["git", "-C", str(target_dir), "pull", "origin", "main"],
                               check=True, capture_output=True, timeout=30)
            else:
                logger.info(f"Cloning community rules from {repo_url}...")
                subprocess.run(["git", "clone", "--depth", "1", repo_url, str(target_dir)],
                               check=True, capture_output=True, timeout=60)
        except subprocess.TimeoutExpired:
            logger.error("Git operation timed out.")
        except subprocess.CalledProcessError as e:
            logger.error(f"Git operation failed: {e.stderr.decode('utf-8', errors='ignore')}")
        except Exception as e:
            logger.error(f"Unexpected error during community rules update: {e}")

    def _load_and_validate_json(self, file_path: Path) -> None:
        """Reads a single JSON file with size limits and strict schema validation."""
        if not file_path.is_file():
            return

        # DoS Protection: Check file size before reading
        if file_path.stat().st_size > self.max_file_size_bytes:
            logger.warning(f"File {file_path.name} exceeds size limit. Skipping.")
            return

        try:
            with open(file_path, encoding='utf-8') as f:
                data = json.load(f)

            # Normalize to list
            if isinstance(data, dict):
                data = data.get("findings", data.get("results", [data]))

            if not isinstance(data, list):
                logger.warning(f"Invalid JSON structure in {file_path.name}: Expected a list.")
                return

            valid_count = 0
            for item in data:
                if not isinstance(item, dict):
                    continue
                try:
                    # Strict validation using Pydantic
                    valid_rule = CustomRuleSchema(**item)
                    self.findings.append(valid_rule.model_dump())
                    valid_count += 1
                except ValidationError as e:
                    logger.debug(f"Skipped invalid rule in {file_path.name}: {e.errors()[0]['msg']}")

            if valid_count > 0:
                logger.info(f"Loaded {valid_count} valid custom rules from {file_path.name}")

        except json.JSONDecodeError:
            logger.error(f"Malformed JSON in {file_path.name}. Skipping.")
        except Exception as e:
            logger.error(f"Error processing {file_path.name}: {e}")

    def load_all_rules(self) -> list[dict[str, Any]]:
        """Safely iterates through the rules directory and loads JSON findings."""
        if not self.rules_dir.exists():
            return self.findings

        # Limit total files to prevent DoS via directory traversing
        file_count = 0
        for json_file in self.rules_dir.rglob("*.json"):
            if file_count > 1000:
                logger.warning("File limit exceeded (1000). Stopping rule loading to prevent memory exhaustion.")
                break

            if self._is_safe_path(json_file):
                self._load_and_validate_json(json_file)
                file_count += 1
            else:
                logger.warning(f"Skipping unsafe path: {json_file}")

        return self.findings

    def evaluate_policy(self, policy_file: str) -> bool:
        """
        Evaluates findings against a simple JSON policy file securely.
        (OPA Rego logic is moved to a dedicated sandbox or adapter).
        """
        policy_path = Path(policy_file)
        if not self._is_safe_path(policy_path) or not policy_path.exists():
            logger.warning(f"Policy file not found or unsafe: {policy_file}. Policy evaluation skipped.")
            return True

        try:
            with open(policy_path, encoding='utf-8') as f:
                policy = json.load(f)

            max_critical = policy.get("max_critical")
            if max_critical is None:
                logger.warning("Policy file missing 'max_critical' threshold. Passing by default.")
                return True

            critical_count = sum(1 for f in self.findings if f.get("severity", "").upper() == "CRITICAL")

            if critical_count > max_critical:
                logger.error(f"Policy Violation! Found {critical_count} CRITICAL issues (Max allowed: {max_critical}).")
                return False

            logger.info("Security policy checks passed.")
            return True

        except Exception as e:
            logger.error(f"Policy evaluation failed: {e}")
            return False
