import argparse
import json
import os
import sys
from devsecops_radar.scanners.trivy import TrivyScanner
from devsecops_radar.scanners.semgrep import SemgrepScanner
from devsecops_radar.scanners.poutine import PoutineScanner
from devsecops_radar.scanners.zizmor import ZizmorScanner
from devsecops_radar.core.analyzer import get_analyzer
from devsecops_radar.core.database import save_scan
from devsecops_radar.core.rule_fusion import RuleFusion

SCANNER_REGISTRY = {
    'trivy': TrivyScanner,
    'semgrep': SemgrepScanner,
    'poutine': PoutineScanner,
    'zizmor': ZizmorScanner,
}

def run_scanner(scanner_name: str, target: str):
    if scanner_name not in SCANNER_REGISTRY:
        print(f"[ERROR] Unknown scanner: {scanner_name}. Available: {list(SCANNER_REGISTRY.keys())}")
        return []
    scanner_class = SCANNER_REGISTRY[scanner_name]
    scanner = scanner_class()
    try:
        if os.path.isfile(target):
            print(f"[INFO] Parsing {scanner_name} JSON file: {target}")
            return scanner.parse(target)
        else:
            print(f"[INFO] Running {scanner_name} on: {target}")
            return scanner.run(target)
    except FileNotFoundError:
        print(f"[ERROR] File not found: {target}")
    except Exception as e:
        print(f"[ERROR] {scanner_name} failed: {e}")
    return []

def main():
    parser = argparse.ArgumentParser(
        description='Pipeline Sentinel - Unified CI/CD Security Dashboard'
    )
    parser.add_argument('--trivy', type=str, help='Trivy JSON file or image name to scan directly')
    parser.add_argument('--semgrep', type=str, help='Semgrep JSON file or target directory')
    parser.add_argument('--poutine', type=str, help='Poutine JSON file or repository path')
    parser.add_argument('--zizmor', type=str, help='Zizmor JSON file or repository path')
    parser.add_argument('--rules', type=str, help='Path to directory with custom JSON rule files')
    parser.add_argument('--output', type=str, default='findings.json', help='Output file for merged findings')
    parser.add_argument('--analyze', action='store_true', help='Enable LLM analysis')
    parser.add_argument('--llm-backend', type=str, default='ollama', choices=['ollama', 'litellm'],
                        help='LLM backend')
    parser.add_argument('--llm-model', type=str, help='LLM model name')
    parser.add_argument('--policy', type=str, help='Path to policy JSON file')
    args = parser.parse_args()

    all_findings = []

    scanner_targets = {
        'trivy': args.trivy,
        'semgrep': args.semgrep,
        'poutine': args.poutine,
        'zizmor': args.zizmor,
    }

    for name, target in scanner_targets.items():
        if target:
            findings = run_scanner(name, target)
            all_findings.extend(findings)

    if args.rules:
        try:
            engine = RuleFusion(local_rules_path=args.rules)
            custom_findings = engine.load_all_rules()
            all_findings.extend(custom_findings)
            print(f"[INFO] Loaded {len(custom_findings)} findings from custom rules in {args.rules}")
        except Exception as e:
            print(f"[ERROR] Failed to load rules from {args.rules}: {e}")

    if not all_findings:
        print("[WARNING] No findings were loaded. The dashboard will be empty.")

    # Evaluate policy (if provided)
    if args.policy:
        passed, msg = RuleFusion.evaluate_policy(all_findings, args.policy)
        print(f"[POLICY] {msg}")
        if not passed:
            print("[FATAL] Policy check failed. Use '--no-policy' or fix the violations.")
            sys.exit(1)

    try:
        with open(args.output, 'w') as f:
            json.dump(all_findings, f, indent=2)
        print(f"[OK] Merged {len(all_findings)} findings into {args.output}")
    except Exception as e:
        print(f"[FATAL] Could not write output file {args.output}: {e}")
        sys.exit(1)

    try:
        save_scan(all_findings)
    except Exception as e:
        print(f"[WARNING] Could not save scan history: {e}")

    if args.analyze:
        print("[INFO] Running AI analysis...")
        try:
            analyzer = get_analyzer(backend=args.llm_backend, model=args.llm_model)
            analysis = analyzer.analyze(all_findings)
            summary_file = args.output.replace('.json', '_ai_summary.json')
            with open(summary_file, 'w', encoding='utf-8') as s:
                json.dump(analysis, s, indent=2)
            print(f"[OK] AI analysis saved to {summary_file}")
        except Exception as e:
            print(f"[ERROR] AI analysis failed: {e}")

if __name__ == '__main__':
    main()