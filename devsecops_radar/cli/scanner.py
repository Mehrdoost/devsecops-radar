import argparse
import asyncio
import json
import os
import sys
from importlib.metadata import entry_points

from loguru import logger

from devsecops_radar.core.analyzer import get_analyzer
from devsecops_radar.core.database import save_scan
from devsecops_radar.core.remediation import auto_fix, generate_pr
from devsecops_radar.core.reporting import generate_pdf_report
from devsecops_radar.core.rule_fusion import RuleFusion
from devsecops_radar.core.valuation import compute_dynamic_risk_score
from devsecops_radar.scanners.adapter import ScannerAdapter


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
    logger.info("Running AI analysis...")
    logger.info(f"This may take several minutes depending on the model and number of findings ({len(findings)}).")
    logger.info(f"Findings sent to LLM: {min(len(findings), 100)} (prioritizing CRITICAL/HIGH)")

    analyzer = get_analyzer(backend=args.llm_backend, model=args.llm_model)
    analysis = await analyzer.analyze(findings, topology)

    summary_file = args.output.replace('.json', '_ai_summary.json')
    with open(summary_file, 'w') as f:
        json.dump(analysis, f, indent=2)
    logger.success(f"AI analysis saved to {summary_file}")
    return analysis


def wizard():
    """Interactive setup wizard for first-time users."""
    logger.info("Welcome to Pipeline Sentinel – Quick Setup Wizard")
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
            # Interactive step-by-step
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
