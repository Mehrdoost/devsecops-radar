import argparse
import asyncio
import json
import os
import platform
import subprocess
import sys
import time
from importlib.metadata import entry_points

from loguru import logger

from devsecops_radar.core.analyzer import get_analyzer
from devsecops_radar.core.database import save_scan
from devsecops_radar.core.remediation import auto_fix, generate_pr
from devsecops_radar.core.reporting import generate_pdf_report
from devsecops_radar.core.rule_fusion import RuleFusion
from devsecops_radar.core.valuation import compute_dynamic_risk_score
from devsecops_radar.scanners.adapter import ScannerAdapter


def get_system_ram_gb():
    try:
        sys_os = platform.system()
        if sys_os == "Windows":
            try:
                output = subprocess.check_output(
                    ['wmic', 'computersystem', 'get', 'TotalPhysicalMemory'],
                    stderr=subprocess.STDOUT
                ).decode('utf-8')
                bytes_mem = int(output.split('\n')[1].strip())
                return round(bytes_mem / (1024**3), 1)
            except Exception:
                pass
        elif sys_os == "Darwin":
            try:
                output = subprocess.check_output(
                    ['sysctl', '-n', 'hw.memsize'],
                    stderr=subprocess.STDOUT
                ).decode('utf-8')
                return round(int(output.strip()) / (1024**3), 1)
            except Exception:
                pass
        elif sys_os == "Linux":
            try:
                with open('/proc/meminfo') as f:
                    for line in f:
                        if 'MemTotal' in line:
                            kb_mem = int(line.split()[1])
                            return round(kb_mem / (1024**2), 1)
            except Exception:
                pass
    except Exception:
        pass
    return None


def get_gpu_status():
    try:
        sys_os = platform.system()
        if sys_os in ["Windows", "Linux"]:
            try:
                subprocess.check_output(['nvidia-smi'], stderr=subprocess.STDOUT)
                return True
            except Exception:
                pass
        elif sys_os == "Darwin":
            try:
                out = subprocess.check_output(
                    ['sysctl', '-n', 'machdep.cpu.brand_string'],
                    stderr=subprocess.STDOUT
                ).decode('utf-8').lower()
                if 'apple' in out:
                    return True
            except Exception:
                pass
    except Exception:
        pass
    return False


def get_safe_chunk_size(ram, has_gpu, total_findings, backend):
    if backend == 'litellm':
        return 0

    if ram is None:
        return 5

    if ram < 4.0:
        return 2
    elif ram < 8.0:
        return 5
    elif ram < 16.0 and not has_gpu:
        return 10
    else:
        return 0


def estimate_analysis(findings_count, model, backend, force_ai=False):
    ram = get_system_ram_gb()
    has_gpu = get_gpu_status()
    cores = os.cpu_count() or 4

    can_run = True
    warnings = []
    chunk_size = get_safe_chunk_size(ram, has_gpu, findings_count, backend)

    if backend == 'litellm':
        total_seconds = 5.0 + (findings_count * 0.5)
        hardware_type = "Cloud Engine"
    else:
        hardware_type = "Local GPU (Accelerated)" if has_gpu else "Local CPU (Standard)"

        if has_gpu:
            base_time_per_finding = 2.5
        else:
            base_time_per_finding = 15.0
            warnings.append("WARNING: No GPU detected. Falling back to CPU. Execution will be significantly slower.")

        if ram is not None:
            if ram < 4.0:
                if force_ai:
                    warnings.append(
                        f"WARNING: System RAM ({ram}GB) is below 4GB. Forced execution active. "
                        f"Applying strict chunking (size={chunk_size})."
                    )
                    base_time_per_finding *= 5.0
                else:
                    warnings.append(
                        f"FATAL: System RAM ({ram}GB) is below 4GB. Aborting to prevent freeze. "
                        f"Use --force-ai to execute in isolated chunks."
                    )
                    can_run = False
            elif ram < 8.0:
                warnings.append(
                    f"WARNING: Low RAM ({ram}GB). Activating memory-safe chunking (size={chunk_size}) "
                    f"to prevent swapping."
                )
                base_time_per_finding *= 2.5
            elif ram < 16.0 and not has_gpu:
                if chunk_size > 0 and findings_count > chunk_size:
                    warnings.append(f"INFO: Activating moderate chunking (size={chunk_size}) for CPU stability.")
                base_time_per_finding *= 1.2

        total_seconds = findings_count * base_time_per_finding

    minutes = int(total_seconds // 60)
    seconds = int(total_seconds % 60)

    ram_display = f"{ram} GB" if ram else "Unknown"
    strategy_display = f"Memory-Safe Chunking (Size: {chunk_size})" if chunk_size > 0 else "Full In-Memory Analysis"

    dashboard = f"""
    ╭────────────────────────────────────────────────────────────╮
    │ 🧠 PIPELINE SENTINEL: AI HARDWARE & PERFORMANCE PROFILER   │
    ├────────────────────────────────────────────────────────────┤
    │  Target Model      : {model} ({backend.upper()})
    │  Execution Engine  : {hardware_type}
    │  System Resources  : {ram_display} RAM | {cores} CPU Cores
    │  Input Load        : {findings_count} Security Findings
    │  Processing Config : {strategy_display}
    │  Dynamic ETA       : ~{minutes}m {seconds}s
    ╰────────────────────────────────────────────────────────────╯
    """

    logger.info(dashboard)

    for w in warnings:
        if "FATAL" in w:
            logger.error(w)
        elif "WARNING" in w:
            logger.warning(w)
        else:
            logger.info(w)

    return can_run, total_seconds, chunk_size, hardware_type


def discover_plugins():
    plugins = {}
    for ep in entry_points(group='devsecops_radar.plugins'):
        cls = ep.load()
        plugins[cls.name] = cls()
    return plugins


def parse_args():
    parser = argparse.ArgumentParser(description='Pipeline Sentinel - Unified CI/CD Security Dashboard')
    parser.add_argument('--trivy', type=str)
    parser.add_argument('--semgrep', type=str)
    parser.add_argument('--poutine', type=str)
    parser.add_argument('--zizmor', type=str)
    parser.add_argument('--gitleaks', type=str)
    parser.add_argument('--rules', type=str)
    parser.add_argument('--output', type=str, default='findings.json')
    parser.add_argument('--analyze', action='store_true')
    parser.add_argument('--force-ai', action='store_true', help='Force AI execution bypassing hardware limits')
    parser.add_argument('--llm-backend', type=str, default='ollama', choices=['ollama', 'litellm'])
    parser.add_argument('--llm-model', type=str)
    parser.add_argument('--policy', type=str)
    parser.add_argument('--rego-policy', type=str, help='Path to an OPA Rego policy file')
    parser.add_argument('--fix', action='store_true')
    parser.add_argument('--review', action='store_true', help='Review each AI fix before applying')
    parser.add_argument('--report', type=str)
    parser.add_argument('--topology', type=str)
    parser.add_argument('--compliance', type=str, choices=['CIS', 'PCI-DSS', 'ISO27001'])
    parser.add_argument('--wizard', action='store_true', help='Interactive first-time setup wizard')
    return parser.parse_args()


async def run_scanner_async(name, target, adapter):
    try:
        if os.path.isfile(target):
            logger.info(f"Parsing {name} JSON file: {target}")
            validated = await asyncio.to_thread(adapter.parse, target)
        else:
            logger.info(f"Running {name} on: {target}")
            validated = await asyncio.to_thread(adapter.run, target)
        return [v.dict() for v in validated]
    except Exception as e:
        logger.error(f"{name} failed: {e}")
        return []


async def run_scans(args, plugins):
    scanner_targets = {
        'trivy': args.trivy,
        'semgrep': args.semgrep,
        'poutine': args.poutine,
        'zizmor': args.zizmor,
        'gitleaks': getattr(args, 'gitleaks', None),
    }
    tasks = []
    for name, target in scanner_targets.items():
        if target:
            plugin = plugins.get(name)
            if plugin:
                adapter = ScannerAdapter(plugin)
                tasks.append(run_scanner_async(name, target, adapter))
    results = await asyncio.gather(*tasks, return_exceptions=True)
    all_findings = []
    for res in results:
        if isinstance(res, list):
            all_findings.extend(res)
        elif isinstance(res, Exception):
            logger.error(f"Scan task failed with exception: {res}")
    return all_findings


def load_custom_rules(args):
    if args.rules:
        try:
            engine = RuleFusion(local_rules_path=args.rules)
            custom = engine.load_all_rules()
            logger.info(f"Loaded {len(custom)} findings from custom rules")
            return custom
        except Exception as e:
            logger.error(f"Failed to load rules: {e}")
    return []


def run_policy_check(args, findings):
    if args.policy:
        passed, msg = RuleFusion.evaluate_policy(findings, args.policy)
        logger.info(f"Policy: {msg}")
        if not passed:
            logger.error("Policy check failed.")
            sys.exit(1)
    if args.rego_policy:
        passed, msg = RuleFusion.evaluate_rego_policy(findings, args.rego_policy)
        logger.info(f"Rego Policy: {msg}")
        if not passed:
            logger.error("Rego policy check failed.")
            sys.exit(1)


def save_results(args, findings):
    with open(args.output, 'w') as f:
        json.dump(findings, f, indent=2)
    logger.success(f"Merged {len(findings)} findings into {args.output}")
    try:
        save_scan(findings)
    except Exception as e:
        logger.warning(f"Could not save scan history: {e}")


async def run_analysis(args, findings, topology=None):
    if not args.analyze:
        return {}

    base_max = int(os.environ.get("ANALYZER_MAX_FINDINGS", "100"))
    num_selected = min(len(findings), base_max)

    ram = get_system_ram_gb()
    if ram is not None and ram < 8.0 and args.llm_backend != 'litellm':
        safe_limit = 10 if ram >= 4.0 else 3
        if num_selected > safe_limit:
            logger.warning(f"Downgrading context size from {num_selected} to top {safe_limit} findings to save memory.")
            num_selected = safe_limit

    target_model = args.llm_model or os.environ.get("PIPELINE_LLM_MODEL", "llama3.2:latest")

    can_run, est_seconds, chunk_size, hardware_type = estimate_analysis(
        num_selected, target_model, args.llm_backend, args.force_ai
    )

    if not can_run:
        fallback_analysis = {
            "executive_summary": (
                "AI analysis was automatically aborted. Your system does not meet "
                "the minimum hardware requirements to run local LLMs safely. "
                "Run with --force-ai if you wish to bypass this safety check."
            ),
            "attack_paths": [],
            "top_remediations": [],
            "execution_time": "0s",
            "hardware_profile": hardware_type
        }
        summary_file = args.output.replace('.json', '_ai_summary.json')
        with open(summary_file, 'w') as f:
            json.dump(fallback_analysis, f, indent=2)
        return fallback_analysis

    logger.info("Initializing AI engine. Please wait...")

    stop_event = asyncio.Event()
    start_time = time.time()

    async def progress_tracker():
        while not stop_event.is_set():
            for _ in range(15):
                if stop_event.is_set():
                    return
                await asyncio.sleep(1)

            elapsed = time.time() - start_time
            if elapsed < est_seconds:
                remaining = int(est_seconds - elapsed)
                logger.info(f"⏳ Processing... Elapsed: {int(elapsed)}s | Estimated remaining: ~{remaining}s")
            else:
                overtime = int(elapsed - est_seconds)
                logger.warning(
                    f"⚠️ Heavy load detected! Complex attack chain analysis is "
                    f"taking longer than expected... (+{overtime}s over ETA)"
                )

    tracker_task = asyncio.create_task(progress_tracker())

    try:
        analyzer = get_analyzer(backend=args.llm_backend, model=args.llm_model)

        limited_findings = findings[:num_selected]
        analysis = await analyzer.analyze(limited_findings, topology, chunk_size=chunk_size)
    finally:
        stop_event.set()
        await tracker_task

    end_time = time.time()
    total_elapsed = end_time - start_time
    minutes = int(total_elapsed // 60)
    seconds = int(total_elapsed % 60)

    exec_time_str = f"{minutes}m {seconds}s" if minutes > 0 else f"{seconds}s"

    analysis["execution_time"] = exec_time_str
    analysis["hardware_profile"] = hardware_type

    summary_file = args.output.replace('.json', '_ai_summary.json')
    with open(summary_file, 'w') as f:
        json.dump(analysis, f, indent=2)

    logger.success(f"✅ AI analysis completed successfully in {exec_time_str}.")
    logger.success(f"AI summary saved to {summary_file}. Dashboard is ready.")
    return analysis


def wizard():
    logger.info("Welcome to Pipeline Sentinel - Quick Setup Wizard")
    logger.info("This will install necessary components.")
    import subprocess
    try:
        subprocess.run(['ollama', '--version'], capture_output=True, check=True)
        logger.info("Ollama found.")
    except FileNotFoundError:
        logger.warning("Ollama not found. Installing...")
        subprocess.run('curl -fsSL https://ollama.com/install.sh | sh', shell=True)
    except subprocess.CalledProcessError:
        logger.warning("Could not verify Ollama. Please install manually.")
    logger.info("Pulling AI model (llama3.2)...")
    subprocess.run(['ollama', 'pull', 'llama3.2:latest'])
    logger.info("Setup complete! You can now run:")
    logger.info("   devsecops-radar --trivy sample_trivy.json --semgrep sample_semgrep.json")
    logger.info("   devsecops-radar-web")
    logger.info("Then open http://localhost:8080 in your browser.")


def main():
    try:
        sys.stdout.reconfigure(encoding='utf-8')
        sys.stderr.reconfigure(encoding='utf-8')
    except AttributeError:
        pass

    args = parse_args()
    if args.wizard:
        wizard()
        return
    logger.remove()
    logger.add(sys.stderr, format="<green>{time:HH:mm:ss}</green> | <level>{level: <8}</level> | {message}")

    plugins = discover_plugins()
    findings = asyncio.run(run_scans(args, plugins))
    findings.extend(load_custom_rules(args))

    if not findings:
        logger.warning("No findings loaded.")

    run_policy_check(args, findings)
    save_results(args, findings)

    topology = {}
    if args.topology and os.path.exists(args.topology):
        with open(args.topology) as f:
            topology = json.load(f)

    ai_summary = asyncio.run(run_analysis(args, findings, topology))

    if findings and topology:
        for f in findings:
            f['dynamic_risk_score'] = compute_dynamic_risk_score(f, topology)

    if args.fix and ai_summary:
        if args.review:
            from devsecops_radar.core.remediation import generate_fix_commands
            cmds = generate_fix_commands(findings, ai_summary)
            logger.info("Proposed fixes:\n{}", cmds)
            for rem in ai_summary.get('top_remediations', []):
                fid = rem.get('finding_id')
                steps = rem.get('remediation_steps', [])
                if steps:
                    logger.info(f"\n--- Fix for {fid} ---")
                    for step in steps:
                        logger.info(step)
                        input("Press Enter after completing this step...")
            confirm = input("Apply all remaining fixes? (y/N): ")
            if confirm.lower() != 'y':
                logger.info("Fixes skipped.")
                return
        fixed = auto_fix(findings, ai_summary)
        if fixed:
            logger.success(f"Applied fixes: {fixed}")
            generate_pr(args.output)

    if args.report:
        generate_pdf_report(findings, ai_summary, args.report)


if __name__ == '__main__':
    main()
