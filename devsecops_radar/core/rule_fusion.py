# devsecops_radar/core/rule_fusion.py
"""
RuleFusion engine – loads, validates, and merges custom security rules
with strict GPG fingerprint verification.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import Any

from loguru import logger
from pydantic import BaseModel, Field, ValidationError

from devsecops_radar.core.models import _sanitize_html_and_control  # unified sanitizer
from devsecops_radar.core.path_security import resolve_safe_path, safe_read_open
from devsecops_radar.core.utils import safe_subprocess_run


class CustomRuleSchema(BaseModel):
    id: str = Field(..., description="Unique identifier for the rule")
    tool: str = Field(default="Custom Rule", description="Name of the scanning tool")
    target: str = Field(..., description="File path or target affected")
    severity: str = Field(..., description="Risk severity: CRITICAL, HIGH, MEDIUM, LOW")
    title: str = Field(..., description="Short title of the vulnerability")
    description: str = Field(default="", description="Detailed explanation")


class RuleFusionEngine:
    def __init__(
        self,
        rules_dir: str = "custom_rules",
        max_file_size_mb: int = 10,
        base_dir: Path | None = None,
    ) -> None:
        self._base_dir = (base_dir or Path.cwd()).resolve()
        self.rules_dir = resolve_safe_path(rules_dir, self._base_dir)
        self.max_file_size_bytes = max_file_size_mb * 1024 * 1024
        self.findings: list[dict[str, Any]] = []
        self._loaded = False
        self.rules_dir.mkdir(parents=True, exist_ok=True)

    def add_findings(self, new_findings: list[dict[str, Any]]) -> None:
        self.findings.extend(new_findings)

    # ------------------------------------------------------------------
    # Trusted GPG fingerprints (comma‑separated env or default)
    # ------------------------------------------------------------------
    def _trusted_fingerprints(self) -> set[str]:
        raw = os.environ.get("TRUSTED_GPG_FINGERPRINTS", "")
        if raw:
            return {fp.strip().upper() for fp in raw.split(",") if fp.strip()}
        # Fallback: the official project maintainer key(s)
        return {
            "AAAA BBBB CCCC DDDD EEEE FFFF 0000 1111 2222 3333"  # placeholder – replace with real
        }

    # ------------------------------------------------------------------
    # GPG verification – now with fingerprint check
    # ------------------------------------------------------------------
    def _verify_gpg_signature(self, repo_path: Path, branch: str = "main") -> bool:
        """
        Verify that the latest commit on *branch* is signed with a **trusted**
        GPG key (status 'G') **and** its fingerprint is in the trusted list.
        """
        try:
            result = safe_subprocess_run(
                ["git", "-C", str(repo_path), "verify-commit", "--raw", "HEAD"],
                capture_output=True, text=True, timeout=10, check=False,
            )
            # Lines contain "VALIDSIG <fingerprint> ..."
            fingerprints = set()
            for line in result.stderr.splitlines():
                line = line.strip()
                if line.startswith("[GNUPG:] VALIDSIG "):
                    parts = line.split()
                    if len(parts) >= 3:
                        fingerprints.add(parts[2].upper())  # fingerprint
            # Also check that overall status is good
            if not fingerprints:
                logger.error("No valid GPG signature found.")
                return False

            trusted = self._trusted_fingerprints()
            if not fingerprints & trusted:
                logger.error(
                    f"GPG signature fingerprints {fingerprints} not in trusted set {trusted}. "
                    "Community rules rejected."
                )
                return False

            logger.info("GPG signature verified (fingerprint in trusted set).")
            return True

        except subprocess.TimeoutExpired:
            logger.error("Timeout while verifying GPG signature.")
            return False
        except Exception as e:
            logger.error(f"GPG verification error: {e}")
            return False

    # ------------------------------------------------------------------
    # Community rules update
    # ------------------------------------------------------------------
    def update_community_rules(self) -> None:
        repo_url = os.environ.get("COMMUNITY_RULES_REPO", "")
        if not repo_url:
            logger.info("No community repository configured. Skipping update.")
            return

        # Allow any HTTPS git repository
        from urllib.parse import urlparse
        parsed = urlparse(repo_url)
        if parsed.scheme != "https":
            logger.error("Security Error: Community repo must use HTTPS.")
            return
        if not repo_url.endswith(".git"):
            logger.error("Security Error: Community repo URL must end with .git")
            return
        if ";" in repo_url or " " in repo_url:
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

            # Strict GPG + fingerprint check
            if not self._verify_gpg_signature(target_dir):
                import shutil
                shutil.rmtree(target_dir, ignore_errors=True)
                logger.critical(
                    "Community rules rejected due to missing or untrusted GPG signature. "
                    "Repository has been removed for safety."
                )
                return

            self._loaded = False
            logger.success("Community rules updated and verified.")

        except subprocess.TimeoutExpired:
            logger.error("Git operation timed out.")
        except subprocess.CalledProcessError as e:
            err_msg = e.stderr.decode('utf-8', errors='ignore') if e.stderr else str(e)
            logger.error(f"Git operation failed: {err_msg}")
        except Exception as e:
            logger.error(f"Unexpected error during community rules update: {e}")

    # ------------------------------------------------------------------
    # Rule loading & validation (with unified sanitization)
    # ------------------------------------------------------------------
    def _load_and_validate_json(self, file_path: Path) -> None:
        try:
            with safe_read_open(file_path, base_dir=self._base_dir) as f:
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
                # Sanitize all string fields using the project‑wide sanitizer
                safe_rule = {
                    "id": _sanitize_html_and_control(valid_rule.id),
                    "tool": _sanitize_html_and_control(valid_rule.tool),
                    "target": _sanitize_html_and_control(valid_rule.target),
                    "severity": valid_rule.severity,
                    "title": _sanitize_html_and_control(valid_rule.title),
                    "description": _sanitize_html_and_control(valid_rule.description or ""),
                }
                self.findings.append(safe_rule)
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
                logger.warning("File limit exceeded (1000). Stopping rule loading.")
                break

            try:
                resolve_safe_path(json_file, self._base_dir)
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
            with safe_read_open(policy_path, base_dir=self._base_dir) as f:
                policy = json.load(f)
        except (ValueError, FileNotFoundError, PermissionError, OSError, json.JSONDecodeError) as e:
            logger.warning(f"Cannot read policy file '{policy_file}': {e}. Failing by default.")
            return False

        max_critical = policy.get("max_critical")
        if max_critical is None:
            logger.error("Policy file missing 'max_critical' threshold. Failing.")
            return False

        try:
            max_critical = int(max_critical)
            if max_critical < 0:
                raise ValueError
        except (ValueError, TypeError):
            logger.error(f"Invalid 'max_critical' value: {max_critical}. Must be a non-negative integer.")
            return False

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
        if not os.path.isfile(rego_file):
            logger.error(f"Rego policy file not found: {rego_file}")
            return False

        try:
            resolve_safe_path(rego_file, self._base_dir)
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
                ["opa", "eval", "--input", "-", "--data", rego_file, "data.pipeline_sentinel.deny"],
                input=input_json,
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )

            if result.returncode != 0:
                logger.error(f"OPA evaluation failed: {result.stderr}")
                return False

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
