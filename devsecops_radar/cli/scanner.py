import argparse
import json
import os
import sys
from loguru import logger
from devsecops_radar.scanners.trivy import TrivyScanner
from devsecops_radar.scanners.semgrep import SemgrepScanner
from devsecops_radar.scanners.poutine import PoutineScanner
from devsecops_radar.scanners.zizmor import ZizmorScanner
from devsecops_radar.core.analyzer import get_analyzer
from devsecops_radar.core.database import save_scan
from devsecops_radar.core.rule_fusion import RuleFusion
from devsecops_radar.core.remediation import auto_fix, generate_pr
from devsecops_radar.core.reporting import generate_pdf_report

SCANNER_REGISTRY = {
    'trivy': TrivyScanner,
    'semgrep': SemgrepScanner,
    'poutine': PoutineScanner,
    'zizmor': ZizmorScanner,
}

def run_scanner(scanner_name: str, target: str):
    if scanner_name not in SCANNER_REGISTRY:
        logger.error(f"Unknown scanner: {scanner_name}. Available: {list(SCANNER_REGISTRY.keys())}")
        return []
    scanner_class = SCANNER_REGISTRY[scanner_name]
    scanner = scanner_class()
    try:
        if os.path.isfile(target):
            logger.info(f"Parsing {scanner_name} JSON file: {target}")
            return scanner.parse(target)
        else:
            logger.info(f"Running {scanner_name} on: {target}")
            return scanner.run(target)
    except FileNotFoundError:
        logger.error(f"File not found: {target}")
    except Exception as e:
        logger.exception(f"{scanner_name} failed: {e}")
    return []

def main():
    parser = argparse.ArgumentParser(description='Pipeline Sentinel - Unified CI/CD Security Dashboard')
    parser.add_argument('--trivy', type=str, help='Trivy JSON file or image name')
    parser.add_argument('--semgrep', type=str, help='Semgrep JSON file or target directory')
    parser.add_argument('--poutine', type=str, help='Poutine JSON file or repository path')
    parser.add_argument('--zizmor', type=str, help='Zizmor JSON file or repository path')
    parser.add_argument('--rules', type=str, help='Path to directory with custom JSON rule files')
    parser.add_argument('--output', type=str, default='findings.json', help='Output file for merged findings')
    parser.add_argument('--analyze', action='store_true', help='Enable LLM analysis')
    parser.add_argument('--llm-backend', type=str, default='ollama', choices=['ollama', 'litellm'])
    parser.add_argument('--llm-model', type=str, help='LLM model name')
    parser.add_argument('--policy', type=str, help='Path to policy JSON file')
    parser.add_argument('--fix', action='store_true', help='Automatically apply AI-suggested fixes')
    parser.add_argument('--report', type=str, help='Generate PDF report (output filename)')
    parser.add_argument('--topology', type=str, help='Path to topology JSON file')
    parser.add_argument('--compliance', type=str, choices=['CIS','PCI-DSS','ISO27001'], help='Compliance framework')
    args = parser.parse_args()

    # Setup loguru
    logger.remove()
    logger.add(sys.stderr, format="<green>{time:HH:mm:ss}</green> | <level>{level: <8}</level> | {message}")

    all_findings = []

    scanner_targets = {
        'trivy': args.trivy,
        'semgrep': args.semgrep,
        'poutine': args.poutine,
        'zizmor': args.zizmor,
    }
    for name, target in scanner_targets.items():
        if target:
            all_findings.extend(run_scanner(name, target))

    if args.rules:
        try:
            engine = RuleFusion(local_rules_path=args.rules)
            custom_findings = engine.load_all_rules()
            all_findings.extend(custom_findings)
            logger.info(f"Loaded {len(custom_findings)} findings from custom rules")
        except Exception as e:
            logger.error(f"Failed to load rules: {e}")

    if not all_findings:
        logger.warning("No findings were loaded.")

    # Policy check
    if args.policy:
        passed, msg = RuleFusion.evaluate_policy(all_findings, args.policy)
        logger.info(f"Policy: {msg}")
        if not passed:
            logger.error("Policy check failed. Exiting.")
            sys.exit(1)

    # Save findings
    with open(args.output, 'w') as f:
        json.dump(all_findings, f, indent=2)
    logger.success(f"Merged {len(all_findings)} findings into {args.output}")

    save_scan(all_findings)

    # Topology and analysis
    topology = {}
    if args.topology:
        with open(args.topology) as f:
            topology = json.load(f)

    ai_summary = {}
    if args.analyze:
        logger.info("Running AI analysis...")
        try:
            analyzer = get_analyzer(backend=args.llm_backend, model=args.llm_model)
            ai_summary = analyzer.analyze(all_findings, topology)
            summary_file = args.output.replace('.json', '_ai_summary.json')
            with open(summary_file, 'w') as s:
                json.dump(ai_summary, s, indent=2)
            logger.success(f"AI summary saved to {summary_file}")
        except Exception as e:
            logger.error(f"AI analysis failed: {e}")

    # Auto-fix
    if args.fix and ai_summary:
        fixed_ids = auto_fix(all_findings, ai_summary)
        if fixed_ids:
            logger.success(f"Applied fixes for: {fixed_ids}")
            generate_pr(args.output)

    # PDF Report
    if args.report:
        generate_pdf_report(all_findings, ai_summary, args.report)

    if args.compliance:
        # Mapping to compliance would require integration with the LLM analysis; for now, print note.
        logger.info(f"Compliance mapping ({args.compliance}) would be included in the report.")

if __name__ == '__main__':
    main()