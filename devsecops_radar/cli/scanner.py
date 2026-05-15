import argparse
import json
import os
import sys
from importlib.metadata import entry_points
from loguru import logger
from devsecops_radar.core.analyzer import get_analyzer
from devsecops_radar.core.database import save_scan
from devsecops_radar.core.rule_fusion import RuleFusion
from devsecops_radar.core.remediation import auto_fix, generate_pr
from devsecops_radar.core.reporting import generate_pdf_report

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
    parser.add_argument('--rules', type=str)
    parser.add_argument('--output', type=str, default='findings.json')
    parser.add_argument('--analyze', action='store_true')
    parser.add_argument('--llm-backend', type=str, default='ollama', choices=['ollama', 'litellm'])
    parser.add_argument('--llm-model', type=str)
    parser.add_argument('--policy', type=str)
    parser.add_argument('--fix', action='store_true')
    parser.add_argument('--report', type=str)
    parser.add_argument('--topology', type=str)
    parser.add_argument('--compliance', type=str, choices=['CIS', 'PCI-DSS', 'ISO27001'])
    return parser.parse_args()

def run_scans(args, plugins):
    all_findings = []
    scanner_targets = {
        'trivy': args.trivy,
        'semgrep': args.semgrep,
        'poutine': args.poutine,
        'zizmor': args.zizmor,
    }
    for name, target in scanner_targets.items():
        if target:
            scanner = plugins.get(name)
            if scanner:
                try:
                    if os.path.isfile(target):
                        logger.info(f"Parsing {name} JSON file: {target}")
                        all_findings.extend(scanner.parse(target))
                    else:
                        logger.info(f"Running {name} on: {target}")
                        all_findings.extend(scanner.run(target))
                except Exception as e:
                    logger.error(f"{name} failed: {e}")
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

def save_results(args, findings):
    with open(args.output, 'w') as f:
        json.dump(findings, f, indent=2)
    logger.success(f"Merged {len(findings)} findings into {args.output}")
    try:
        save_scan(findings)
    except Exception as e:
        logger.warning(f"Could not save scan history: {e}")

def run_analysis(args, findings, topology=None):
    if not args.analyze:
        return {}
    logger.info("Running AI analysis...")
    analyzer = get_analyzer(backend=args.llm_backend, model=args.llm_model)
    analysis = analyzer.analyze(findings, topology)
    summary_file = args.output.replace('.json', '_ai_summary.json')
    with open(summary_file, 'w') as f:
        json.dump(analysis, f, indent=2)
    logger.success(f"AI summary saved to {summary_file}")
    return analysis

def main():
    args = parse_args()
    logger.remove()
    logger.add(sys.stderr, format="<green>{time:HH:mm:ss}</green> | <level>{level: <8}</level> | {message}")

    plugins = discover_plugins()
    findings = []
    findings.extend(run_scans(args, plugins))
    findings.extend(load_custom_rules(args))

    if not findings:
        logger.warning("No findings loaded.")

    run_policy_check(args, findings)
    save_results(args, findings)

    topology = {}
    if args.topology and os.path.exists(args.topology):
        with open(args.topology) as f:
            topology = json.load(f)

    ai_summary = run_analysis(args, findings, topology)

    if args.fix and ai_summary:
        fixed = auto_fix(findings, ai_summary)
        if fixed:
            logger.success(f"Applied fixes: {fixed}")
            generate_pr(args.output)

    if args.report:
        generate_pdf_report(findings, ai_summary, args.report)

if __name__ == '__main__':
    main()