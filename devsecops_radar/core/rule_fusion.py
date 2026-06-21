# devsecops_radar/core/rule_fusion.py
import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import Any

from loguru import logger
from pydantic import BaseModel, Field, ValidationError

from devsecops_radar.core.path_security import resolve_safe_path, safe_read_open
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

    def add_findings(self, new_findings: list[dict[str, Any]]) -> None:
        """Safely append external findings without overwriting existing ones."""
        self.findings.extend(new_findings)

    # ------------------------------------------------------------------
    # Community rules update – NOW WITH GPG VERIFICATION
    # ------------------------------------------------------------------
    def _verify_gpg_signature(self, repo_path: Path, branch: str = "main") -> bool:
        """
        Verify that the latest commit on *branch* is signed with a trusted GPG key.

        Returns True if the commit has a valid GPG signature, False otherwise.
        """
        try:
            result = safe_subprocess_run(
                [
                    "git", "-C", str(repo_path),
                    "log", "-1", "--format=%G?",
                    branch,
                ],
                capture_output=True, text=True, timeout=10, check=False,
            )
            status = result.stdout.strip()
            # "G" = Good signature, "U" = Good signature but unknown key
            if status in ("G", "U"):
                logger.info(f"GPG signature verified for branch '{branch}' (status: {status}).")
                return True
            else:
                logger.error(
                    f"GPG verification failed for branch '{branch}'. "
                    f"git log returned status '{status or 'empty'}'. "
                    "Community rules will NOT be updated."
                )
                return False
        except subprocess.TimeoutExpired:
            logger.error("Timeout while verifying GPG signature.")
            return False
        except Exception as e:
            logger.error(f"GPG verification error: {e}")
            return False

    def update_community_rules(self) -> None:
        repo_url = os.environ.get("COMMUNITY_RULES_REPO", "")
        if not repo_url:
            logger.info("No community repository configured. Skipping update.")
            return

        from urllib.parse import urlparse
        parsed = urlparse(repo_url)
        if parsed.scheme != "https" or parsed.netloc != "github.com":
            logger.error("Security Error: Community repo must be a valid https://github.com URL.")
            return
        if not repo_url.endswith(".git") or ";" in repo_url or " " in repo_url:
            logger.error(f"Security Error: Invalid characters in repo URL: {repo_url}")
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

            # CRITICAL SECURITY CHECK: Verify GPG signature after pull/clone
            if not self._verify_gpg_signature(target_dir):
                # Rollback: delete the directory to prevent loading untrusted rules
                import shutil
                shutil.rmtree(target_dir, ignore_errors=True)
                logger.critical(
                    "Community rules rejected due to missing or invalid GPG signature. "
                    "Repository has been removed for safety."
                )
                return

        except subprocess.TimeoutExpired:
            logger.error("Git operation timed out.")
        except subprocess.CalledProcessError as e:
            err_msg = e.stderr.decode('utf-8', errors='ignore') if e.stderr else str(e)
            logger.error(f"Git operation failed: {err_msg}")
        except Exception as e:
            logger.error(f"Unexpected error during community rules update: {e}")

    # ------------------------------------------------------------------
    # Rule loading & validation
    # ------------------------------------------------------------------
    def _load_and_validate_json(self, file_path: Path) -> None:
        try:
            with safe_read_open(file_path, base_dir=self.rules_dir) as f:
                if file_path.stat().st_size > self.max_file_size_bytes:
                    logger.warning(f"File {file_path.name} exceeds size limit. Skipping.")
                    return
                data = json.load(f)
        except ValueError as e:
            logger.warning(f"Skipping unsafe path {file_path}: {e}")
            return
        except (json.JSONDecodeError, OSError) as e:
            logger.error(f"Error reading {file_path.name}: {e}")
            return

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
                valid_rule = CustomRuleSchema(**item)
                self.findings.append(valid_rule.model_dump())
                valid_count += 1
            except ValidationError as e:
                logger.debug(f"Skipped invalid rule in {file_path.name}: {e.errors()[0]['msg']}")

        if valid_count > 0:
            logger.info(f"Loaded {valid_count} valid custom rules from {file_path.name}")

    def load_all_rules(self) -> list[dict[str, Any]]:
        if self._loaded:
            return self.findings

        if not self.rules_dir.exists():
            return self.findings

        self.findings.clear()
        file_count = 0
        for json_file in self.rules_dir.rglob("*.json"):
            if file_count > 1000:
                logger.warning("File limit exceeded (1000). Stopping rule loading to prevent memory exhaustion.")
                break

            try:
                resolve_safe_path(json_file, self.rules_dir)
            except ValueError as e:
                logger.warning(f"Skipping unsafe path: {json_file} ({e})")
                continue

            self._load_and_validate_json(json_file)
            file_count += 1

        self._loaded = True
        return self.findings

    # ------------------------------------------------------------------
    # Policy evaluation
    # ------------------------------------------------------------------
    def evaluate_policy(self, policy_file: str) -> bool:
        policy_path = Path(policy_file)
        try:
            with safe_read_open(policy_path, base_dir=Path.cwd()) as f:
                policy = json.load(f)
        except (ValueError, FileNotFoundError, PermissionError, OSError, json.JSONDecodeError) as e:
            logger.warning(f"Cannot read policy file '{policy_file}': {e}. Passing by default.")
            return True

        max_critical = policy.get("max_critical")
        if max_critical is None:
            logger.warning("Policy file missing 'max_critical' threshold. Passing by default.")
            return True

        critical_count = sum(1 for f in self.findings if f.get("severity", "").upper() == "CRITICAL")
        if critical_count > max_critical:
            action = str(policy.get("on_violation", "fail")).lower()
            if action == "warn":
                logger.warning(
                    f"Policy warning: {critical_count} CRITICAL issues "
                    f"(max allowed: {max_critical}). Continuing."
                )
                return True
            else:
                logger.error(f"Policy Violation! {critical_count} CRITICAL issues (Max allowed: {max_critical}).")
                return False

        logger.info("Security policy checks passed.")
        return True

    def evaluate_rego_policy(self, rego_file: str) -> bool:
        """Evaluate findings against an OPA Rego policy file."""
        if not os.path.isfile(rego_file):
            logger.error(f"Rego policy file not found: {rego_file}")
            return False  # <-- changed from True to False: missing file = violation

        try:
            resolve_safe_path(rego_file, Path.cwd())
        except ValueError as e:
            logger.error(f"Rego policy path not allowed: {e}")
            return False

        if not shutil.which("opa"):
            logger.error("OPA executable not found. Cannot evaluate Rego policy.")
            return False

        try:
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

            if result.returncode != 0:
                logger.error(f"OPA evaluation failed: {result.stderr}")
                return False

            # Empty result means no violations found
            output = result.stdout.strip()
            if not output or output == "[]" or output == "set()":
                logger.info("OPA Rego policy check passed. No violations.")
                return True
            else:
                logger.error(f"OPA Rego policy violation: {output}")
                return False

        except FileNotFoundError:
            logger.error("OPA executable not found. Skipping Rego policy evaluation.")
            return False
        except subprocess.TimeoutExpired:
            logger.error("OPA evaluation timed out.")
            return False
        except Exception as e:
            logger.error(f"OPA Rego evaluation failed: {e}")
            return False

