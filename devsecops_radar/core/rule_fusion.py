import json
import os
import subprocess
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from loguru import logger
from pydantic import BaseModel, Field, ValidationError

from devsecops_radar.core.utils import safe_subprocess_run


class CustomRuleSchema(BaseModel):
    """Pydantic model to enforce strict validation on custom JSON rules."""
    id: str = Field(..., description="Unique identifier for the rule")
    tool: str = Field(default="Custom Rule", description="Name of the scanning tool")
    target: str = Field(..., description="File path or target affected")
    severity: str = Field(
        ..., description="Risk severity: CRITICAL, HIGH, MEDIUM, LOW"
    )
    title: str = Field(..., description="Short title of the vulnerability")
    description: str = Field(default="", description="Detailed explanation")


class RuleFusionEngine:
    """
    Engine responsible for aggregating, validating, and merging custom security rules.
    Also provides policy evaluation (JSON and OPA Rego).
    """

    def __init__(
        self, rules_dir: str = "custom_rules", max_file_size_mb: int = 10
    ) -> None:
        self.rules_dir = Path(rules_dir).resolve()
        self.max_file_size_bytes = max_file_size_mb * 1024 * 1024
        self.findings: list[dict[str, Any]] = []
        self._loaded = False

        if not self.rules_dir.exists():
            self.rules_dir.mkdir(parents=True, exist_ok=True)

    def _is_safe_path(
        self, target_path: Path, base_dir: Path | None = None
    ) -> bool:
        if base_dir is None:
            base_dir = self.rules_dir
        try:
            resolved_target = target_path.resolve(strict=False)
            return resolved_target.is_relative_to(base_dir)
        except Exception as e:
            logger.error(f"Path resolution error: {e}")
            return False

    def add_findings(self, new_findings: list[dict[str, Any]]) -> None:
        """Safely append external findings without overwriting existing ones."""
        self.findings.extend(new_findings)

    def update_community_rules(self) -> None:
        repo_url = os.environ.get("COMMUNITY_RULES_REPO", "")
        if not repo_url:
            logger.info("No community repository configured. Skipping update.")
            return

        parsed_url = urlparse(repo_url)
        if parsed_url.scheme != "https" or parsed_url.netloc != "github.com":
            logger.error(
                "Security Error: Community repo must be a valid "
                "https://github.com URL."
            )
            return

        if not repo_url.endswith(".git") or ";" in repo_url or " " in repo_url:
            logger.error(
                f"Security Error: Invalid characters in repo URL: {repo_url}"
            )
            return

        target_dir = self.rules_dir / "community"

        try:
            if target_dir.exists():
                logger.info("Updating existing community rules...")
                safe_subprocess_run(
                    ["git", "-C", str(target_dir), "pull", "origin", "main"],
                    check=True, capture_output=True, timeout=30
                )
            else:
                logger.info(f"Cloning community rules from {repo_url}...")
                safe_subprocess_run(
                    ["git", "clone", "--depth", "1", repo_url, str(target_dir)],
                    check=True, capture_output=True, timeout=60
                )
        except subprocess.TimeoutExpired:
            logger.error("Git operation timed out.")
        except subprocess.CalledProcessError as e:
            logger.error(
                f"Git operation failed: {e.stderr.decode('utf-8', errors='ignore')}"
            )
        except Exception as e:
            logger.error(
                f"Unexpected error during community rules update: {e}"
            )

    def _load_and_validate_json(self, file_path: Path) -> None:
        if not file_path.is_file():
            return

        if file_path.stat().st_size > self.max_file_size_bytes:
            logger.warning(
                f"File {file_path.name} exceeds size limit. Skipping."
            )
            return

        try:
            with open(file_path, encoding='utf-8') as f:
                data = json.load(f)

            if isinstance(data, dict):
                data = data.get("findings", data.get("results", [data]))

            if not isinstance(data, list):
                logger.warning(
                    f"Invalid JSON structure in {file_path.name}: Expected a list."
                )
                return

            valid_count = 0
            for item in data:
                if not isinstance(item, dict):
                    continue
                try:
                    valid_rule = CustomRuleSchema(**item)
                    self.findings.append(valid_rule.model_dump())
                    valid_count += 1
                except ValidationError as e:
                    logger.debug(
                        f"Skipped invalid rule in {file_path.name}: "
                        f"{e.errors()[0]['msg']}"
                    )

            if valid_count > 0:
                logger.info(
                    f"Loaded {valid_count} valid custom rules from "
                    f"{file_path.name}"
                )

        except json.JSONDecodeError:
            logger.error(f"Malformed JSON in {file_path.name}. Skipping.")
        except Exception as e:
            logger.error(f"Error processing {file_path.name}: {e}")

    def load_all_rules(self) -> list[dict[str, Any]]:
        if self._loaded:
            return self.findings

        if not self.rules_dir.exists():
            return self.findings

        self.findings.clear()

        file_count = 0
        for json_file in self.rules_dir.rglob("*.json"):
            if file_count > 1000:
                logger.warning(
                    "File limit exceeded (1000). Stopping rule loading to "
                    "prevent memory exhaustion."
                )
                break

            if self._is_safe_path(json_file):
                self._load_and_validate_json(json_file)
                file_count += 1
            else:
                logger.warning(f"Skipping unsafe path: {json_file}")

        self._loaded = True
        return self.findings

    def evaluate_policy(self, policy_file: str) -> bool:
        policy_path = Path(policy_file)
        if not self._is_safe_path(policy_path, base_dir=Path.cwd()):
            logger.warning(
                f"Policy file is outside the allowed base directory: "
                f"{policy_file}. Policy evaluation skipped."
            )
            return True

        if not policy_path.exists():
            logger.warning(
                f"Policy file not found: {policy_file}. "
                "Policy evaluation skipped."
            )
            return True

        try:
            with open(policy_path, encoding='utf-8') as f:
                policy = json.load(f)

            max_critical = policy.get("max_critical")
            if max_critical is None:
                logger.warning(
                    "Policy file missing 'max_critical' threshold. "
                    "Passing by default."
                )
                return True

            critical_count = sum(
                1 for f in self.findings
                if f.get("severity", "").upper() == "CRITICAL"
            )

            if critical_count > max_critical:
                action = str(policy.get("on_violation", "fail")).lower()
                if action == "warn":
                    logger.warning(
                        f"Policy warning: Found {critical_count} CRITICAL "
                        f"issues (max allowed: {max_critical}). "
                        "Continuing per 'on_violation: warn' setting."
                    )
                    return True
                else:
                    logger.error(
                        f"Policy Violation! Found {critical_count} CRITICAL "
                        f"issues (Max allowed: {max_critical})."
                    )
                    return False

            logger.info("Security policy checks passed.")
            return True

        except Exception as e:
            logger.error(f"Policy evaluation failed: {e}")
            return False

    def evaluate_rego_policy(self, rego_file: str) -> bool:
        """
        Evaluate findings against an OPA Rego policy file.
        Requires 'opa' binary in PATH.
        """
        if not os.path.isfile(rego_file):
            logger.error(f"Rego policy file not found: {rego_file}")
            return True

        try:
            # Create a temporary JSON input for OPA
            input_data = {"findings": self.findings}
            input_json = json.dumps(input_data)

            result = safe_subprocess_run(
                [
                    "opa", "eval",
                    "--input", "-",
                    "--data", rego_file,
                    "data.pipeline_sentinel.deny",
                ],
                input=input_json,
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
            # If OPA returns any denial reasons, policy fails
            if result.stdout.strip() and "[]" not in result.stdout:
                logger.error("OPA Rego policy violation detected.")
                return False
            return True
        except FileNotFoundError:
            logger.error("OPA executable not found. Skipping Rego policy evaluation.")
            return True
        except subprocess.TimeoutExpired:
            logger.error("OPA evaluation timed out.")
            return True
        except Exception as e:
            logger.error(f"OPA Rego evaluation failed: {e}")
            return True
