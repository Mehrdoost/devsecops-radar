import argparse
import asyncio
import json
import os
import platform
import shutil
import sys
import time
from importlib.metadata import entry_points
from pathlib import Path
from typing import Any

import psutil
from loguru import logger

from devsecops_radar.core.analyzer import get_analyzer
from devsecops_radar.core.database import save_scan
from devsecops_radar.core.remediation import auto_fix, generate_pr, generate_remediation_guide
from devsecops_radar.core.reporting import generate_pdf_report
from devsecops_radar.core.rule_fusion import RuleFusionEngine
from devsecops_radar.core.utils import safe_subprocess_run
from devsecops_radar.core.valuation import compute_dynamic_risk_score
from devsecops_radar.scanners.adapter import ScannerAdapter


def get_system_ram_gb() -> float:
    try:
        return round(psutil.virtual_memory().total / (1024 ** 3), 1)
    except Exception as e:
        logger.debug(f"Failed to read system RAM: {e}")
        return 4.0


def get_gpu_status() -> bool:
    try:
        sys_os = platform.system()
        if sys_os in ["Windows", "Linux"]:
            result = safe_subprocess_run(
                ['nvidia-smi'], capture_output=True, text=True, check=False
            )
            return result.returncode == 0
        elif sys_os == "Darwin":
            result = safe_subprocess_run(
                ['sysctl', '-n', 'machdep.cpu.brand_string'],
                capture_output=True, text=True, check=False
            )
            return 'apple' in result.stdout.lower()
    except Exception as e:
        logger.debug(f"GPU check failed (non-critical): {e}")
    return False


def estimate_analysis(
    findings_count: int, model: str, backend: str, force_ai: bool = False
) -> tuple[bool, float, int, str]:
    ram = get_system_ram_gb()
    has_gpu = get_gpu_status()
    cores = psutil.cpu_count(logical=False) or 4

    can_run = True
    warnings = []
    chunk_size = 5

    if backend == 'litellm':
        total_seconds = 5.0 + (findings_count * 0.5)
        hardware_type = "Cloud Engine"
        chunk_size = 10
    else:
        hardware_type = "Local GPU (Accelerated)" if has_gpu else "Local CPU (Standard)"
        base_time = 2.0 if has_gpu else 8.0

        if not has_gpu:
            warnings.append(
                "WARNING: No GPU detected. Local AI analysis will be slow. "
                "Consider using --llm-backend litellm."
            )

        if ram < 4.0:
            if not force_ai:
                warnings.append(
                    "FATAL: System RAM < 4GB. Aborting local LLM to prevent "
                    "system crash. Use --force-ai to override."
                )
                can_run = False
            else:
                warnings.append("WARNING: Force AI active on low RAM. Risk of freezing.")
                chunk_size = 2
                base_time *= 3.0
        elif ram < 8.0:
            chunk_size = 3
            base_time *= 1.5

        total_seconds = findings_count * base_time

    dashboard = f"""
    ╭────────────────────────────────────────────────────────────╮
    │ 🧠 PIPELINE SENTINEL: AI HARDWARE PROFILER                 │
    ├────────────────────────────────────────────────────────────┤
    │  Target Model     : {model} ({backend.upper()})
    │  Execution Engine : {hardware_type}
    │  System Resources : {ram} GB RAM | {cores} Physical Cores
    │  Input Load       : {findings_count} Security Findings
    │  Chunking Strategy: {chunk_size} items per batch
    ╰────────────────────────────────────────────────────────────╯
    """
    logger.info(dashboard)

    for w in warnings:
        if "FATAL" in w:
            logger.error(w)
        else:
            logger.warning(w)

    return can_run, total_seconds, chunk_size, hardware_type


def discover_plugins() -> dict[str, Any]:
    plugins = {}
    try:
        for ep in entry_points(group='devsecops_radar.plugins'):
            cls = ep.load()
            plugins[cls.name] = cls()
    except Exception as e:
        logger.error(f"Failed to load plugins: {e}")
    return plugins


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description='Pipeline Sentinel - Unified CI/CD Security Dashboard'
    )
    parser.add_argument('--trivy', type=str)
    parser.add_argument('--semgrep', type=str)
    parser.add_argument('--poutine', type=str)
    parser.add_argument('--zizmor', type=str)
    parser.add_argument('--gitleaks', type=str)
    parser.add_argument('--rules', type=str, help='Path to custom JSON rules directory')
    parser.add_argument('--topology', type=str, help='Path to infrastructure topology JSON')

    parser.add_argument('--output', type=str, default='findings.json')
    parser.add_argument('--analyze', action='store_true', help='Run AI analysis on findings')
    parser.add_argument('--force-ai', action='store_true', help='Force AI execution bypassing limits')
    parser.add_argument(
        '--llm-backend', type=str, default='ollama', choices=['ollama', 'litellm']
    )
    parser.add_argument('--llm-model', type=str, default='llama3.2')

    parser.add_argument('--policy', type=str, help='Path to strict JSON policy limits')
    parser.add_argument('--fix', action='store_true', help='Auto-apply AI suggested patches')
    parser.add_argument(
        '--review', action='store_true',
        help='Interactively review each patch before applying'
    )
    parser.add_argument('--report', type=str, help='Generate PDF report to specified path')
    parser.add_argument('--wizard', action='store_true', help='Safe interactive first-time setup')

    parser.add_argument('--export-sarif', type=str, help='Export findings as SARIF to the given path')
    parser.add_argument('--export-cyclonedx', type=str, help='Export findings as CycloneDX to the given path')
    parser.add_argument('--compliance', type=str, choices=['CIS', 'PCI-DSS', 'ISO27001'],
                        help='Compliance framework for reporting')
    parser.add_argument('--notify-jira', action='store_true', help='Create Jira issues for CRITICAL findings')
    parser.add_argument('--notify-asana', action='store_true', help='Create Asana tasks for CRITICAL findings')
    parser.add_argument('--update-rules', action='store_true', help='Download/update community rules')
    parser.add_argument('--rego-policy', type=str, help='Path to OPA Rego policy file (beta)')

    return parser.parse_args()


async def run_scanner_async(
    name: str, target: str, adapter: ScannerAdapter
) -> list[dict[str, Any]]:
    try:
        if Path(target).is_file():
            logger.info(f"Parsing {name} report: {target}")
            validated = await asyncio.to_thread(adapter.parse, target)
        else:
            logger.info(f"Running {name} scan on: {target}")
            validated = await asyncio.to_thread(adapter.run, target)
        return [
            v.model_dump() if hasattr(v, 'model_dump') else v.dict() for v in validated
        ]
    except Exception as e:
        logger.error(f"{name} plugin execution failed: {e}")
        return []


async def run_all_scanners(
    args: argparse.Namespace, plugins: dict[str, Any]
) -> list[dict[str, Any]]:
    scanner_targets = {
        'trivy': args.trivy,
        'semgrep': args.semgrep,
        'poutine': args.poutine,
        'zizmor': args.zizmor,
        'gitleaks': args.gitleaks,
    }

    tasks = []
    for name, target in scanner_targets.items():
        if target and name in plugins:
            adapter = ScannerAdapter(plugins[name])
            tasks.append(run_scanner_async(name, target, adapter))

    results = await asyncio.gather(*tasks, return_exceptions=True)

    all_findings = []
    for res in results:
        if isinstance(res, Exception):
            logger.error(f"Scanner task failed: {res}")
        elif isinstance(res, list):
            all_findings.extend(res)

    return all_findings


def sort_findings_by_risk(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    severity_rank = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "UNKNOWN": 0}
    return sorted(
        findings,
        key=lambda x: (
            severity_rank.get(str(x.get("severity")).upper(), 0),
            x.get("dynamic_risk_score", 0.0)
        ),
        reverse=True
    )


async def execute_ai_analysis(
    args: argparse.Namespace, findings: list[dict[str, Any]], topology: dict[str, Any]
) -> dict[str, Any]:
    if not args.analyze or not findings:
        return {}

    sorted_findings = sort_findings_by_risk(findings)
    base_max = int(os.environ.get("ANALYZER_MAX_FINDINGS", "100"))
    selected_findings = sorted_findings[:base_max]

    can_run, est_seconds, chunk_size, hw_type = estimate_analysis(
        len(selected_findings), args.llm_model, args.llm_backend, args.force_ai
    )

    out_path = Path(args.output)
    summary_file = out_path.parent / f"{out_path.stem}_ai_summary.json"

    if not can_run:
        fallback = {
            "executive_summary": (
                "Analysis aborted due to low system resources. "
                "Use --force-ai to bypass."
            ),
            "risk_score": 0.0,
            "hardware_profile": hw_type
        }
        with open(summary_file, 'w', encoding='utf-8') as fh:
            json.dump(fallback, fh, indent=2)
        return fallback

    logger.info("Initializing AI Security Engine...")
    start_time = time.time()

    try:
        analyzer = get_analyzer(backend=args.llm_backend, model=args.llm_model)
        analysis = await analyzer.run(selected_findings, topology, chunk_size=chunk_size)
    except Exception as e:
        logger.error(f"AI Engine crashed during analysis: {e}")
        return {}

    elapsed = int(time.time() - start_time)
    analysis["execution_time"] = elapsed     # integer seconds
    analysis["hardware_profile"] = hw_type

    with open(summary_file, 'w', encoding='utf-8') as fh:
        json.dump(analysis, fh, indent=2)

    logger.success(f"✅ AI analysis completed in {elapsed}s and saved to {summary_file}")
    return analysis


def interactive_remediation(
    findings: list[dict[str, Any]], ai_summary: dict[str, Any]
) -> None:
    if not sys.stdin.isatty():
        logger.warning(
            "No TTY detected; interactive review disabled. "
            "Use --fix without --review for non-interactive auto-fix."
        )
        return

    remediations = ai_summary.get('top_remediations', [])
    if not remediations:
        logger.info("No AI remediations available to apply.")
        return

    logger.info("\n" + generate_remediation_guide(remediations))

    approved_fixes = []

    for rem in remediations:
        fid = rem.get('finding_id', 'UNKNOWN')
        patch = rem.get('patch_content')

        if not patch:
            logger.info(f"Skipping {fid}: Only manual steps provided.")
            continue

        logger.info(f"\n--- Proposed Patch for {fid} ---")
        logger.info(patch)

        try:
            choice = input("Apply this patch securely? [y/N/q(uit)]: ").strip().lower()
        except EOFError:
            logger.warning("Input stream closed; aborting interactive review.")
            break

        if choice == 'q':
            logger.warning("Aborting interactive review.")
            break
        elif choice == 'y':
            approved_fixes.append(rem)
            logger.success(f"Patch {fid} queued.")
        else:
            logger.info(f"Patch {fid} rejected.")

    if approved_fixes:
        tailored_summary = {"top_remediations": approved_fixes}
        modified_files = auto_fix(findings, tailored_summary)
        if modified_files:
            generate_pr(modified_files)


def safe_wizard() -> None:
    logger.info("Welcome to Pipeline Sentinel Setup")

    if not shutil.which("ollama"):
        logger.warning("Ollama is not installed.")
        sys_os = platform.system()
        if sys_os == "Darwin":
            logger.info("Please install via Homebrew: brew install ollama")
        elif sys_os == "Linux":
            logger.info("Please follow official instructions at: https://ollama.com/download/linux")
        elif sys_os == "Windows":
            logger.info("Please download the installer from: https://ollama.com/download/windows")
        return

    logger.info("Ollama is installed. Verifying core AI model...")
    try:
        safe_subprocess_run(['ollama', 'pull', 'llama3.2:latest'], check=True)
        logger.success("Setup complete! You are ready to scan.")
    except Exception as e:
        logger.error(f"Failed to pull AI model: {e}")


async def run_app() -> None:
    args = parse_args()

    if args.wizard:
        safe_wizard()
        return

    logger.remove()
    logger.add(
        sys.stderr,
        format="<green>{time:HH:mm:ss}</green> | <level>{level: <8}</level> | {message}"
    )

    plugins = discover_plugins()

    # Community rules update (before scan)
    if args.update_rules:
        RuleFusionEngine().update_community_rules()
        logger.success("Community rules updated.")
        return

    findings = await run_all_scanners(args, plugins)

    rule_engine: RuleFusionEngine | None = None
    if args.rules:
        rule_engine = RuleFusionEngine(rules_dir=args.rules)
        rule_engine.load_all_rules()
        findings.extend(rule_engine.findings)

    if not findings:
        logger.info("No findings were discovered or loaded. Exiting gracefully.")
        return

    topology = {}
    if args.topology:
        topo_path = Path(args.topology)
        if topo_path.exists() and topo_path.is_file():
            try:
                with open(topo_path, encoding='utf-8') as fh:
                    topology = json.load(fh)
            except Exception as e:
                logger.error(f"Failed to parse topology JSON: {e}")

    for finding in findings:
        finding['dynamic_risk_score'] = compute_dynamic_risk_score(finding, topology)

    # Policy evaluation (JSON)
    if args.policy:
        if rule_engine is None:
            rule_engine = RuleFusionEngine(rules_dir=".")
        rule_engine.findings = findings
        if not rule_engine.evaluate_policy(args.policy):
            logger.error("Build failed due to strict policy violations.")
            sys.exit(1)

    # Rego policy placeholder (future full OPA integration)
    if args.rego_policy:
        logger.warning("OPA Rego policy evaluation is not yet implemented. Ignoring --rego-policy.")

    # Save to file and database
    try:
        out_path = Path(args.output).resolve()
        if not out_path.is_relative_to(Path.cwd()):
            logger.error("Output file must be inside the current working directory.")
            sys.exit(1)
        with open(out_path, 'w', encoding='utf-8') as fh:
            json.dump(findings, fh, indent=2)
        save_scan(findings)
        logger.success(f"Aggregated {len(findings)} findings into {args.output}")
    except Exception as e:
        logger.error(f"Database/File save error: {e}")

    ai_summary = await execute_ai_analysis(args, findings, topology)

    # Auto-fix / review
    if args.fix and ai_summary:
        if args.review:
            interactive_remediation(findings, ai_summary)
        else:
            logger.warning("Executing Auto-Fix for ALL AI suggestions without review!")
            modified = auto_fix(findings, ai_summary)
            if modified:
                generate_pr(modified)

    # Export reports
    if args.report:
        generate_pdf_report(findings, ai_summary, args.report)
        logger.success(f"PDF report generated: {args.report}")

    if args.export_sarif:
        from devsecops_radar.core.sarif_export import export_sarif
        export_sarif(findings, args.export_sarif)
        logger.success(f"SARIF report exported to {args.export_sarif}")

    if args.export_cyclonedx:
        from devsecops_radar.core.sarif_export import export_cyclonedx
        export_cyclonedx(findings, args.export_cyclonedx)
        logger.success(f"CycloneDX report exported to {args.export_cyclonedx}")

    # Notifications
    if args.notify_jira:
        jira_url = os.environ.get("JIRA_URL")
        jira_token = os.environ.get("JIRA_TOKEN")
        if jira_url and jira_token:
            from devsecops_radar.core.notifier import notify_jira
            await notify_jira(findings, jira_url, jira_token)
        else:
            logger.error("JIRA_URL and JIRA_TOKEN must be set in environment for --notify-jira.")

    if args.notify_asana:
        asana_token = os.environ.get("ASANA_TOKEN")
        asana_workspace = os.environ.get("ASANA_WORKSPACE")
        if asana_token and asana_workspace:
            from devsecops_radar.core.notifier import notify_asana
            await notify_asana(findings, asana_token, asana_workspace)
        else:
            logger.error("ASANA_TOKEN and ASANA_WORKSPACE must be set in environment for --notify-asana.")


def main() -> None:
    try:
        asyncio.run(run_app())
    except KeyboardInterrupt:
        logger.warning("Execution interrupted by user.")
        sys.exit(130)


if __name__ == '__main__':
    main()