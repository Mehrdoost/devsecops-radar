import argparse
import json
import os
from devsecops_radar.scanners.trivy import TrivyScanner
from devsecops_radar.scanners.semgrep import SemgrepScanner
from devsecops_radar.scanners.poutine import PoutineScanner
from devsecops_radar.scanners.zizmor import ZizmorScanner
from devsecops_radar.core.analyzer import OllamaAnalyzer
from devsecops_radar.core.database import save_scan
from devsecops_radar.core.rule_fusion import RuleFusion  # <-- موتور جدید


def main():
    parser = argparse.ArgumentParser(
        description='Pipeline Sentinel - Unified CI/CD Security Dashboard'
    )
    # Scanner inputs
    parser.add_argument('--trivy', type=str, help='Trivy JSON file or image name')
    parser.add_argument('--semgrep', type=str, help='Semgrep JSON file or target directory')
    parser.add_argument('--poutine', type=str, help='Poutine JSON file or repository path')
    parser.add_argument('--zizmor', type=str, help='Zizmor JSON file or repository path')
    # Rule Engine inputs
    parser.add_argument('--rules', type=str, help='Path to directory with custom JSON rule files')
    parser.add_argument('--update-rules', action='store_true', help='Download/update community rules from GitHub')
    parser.add_argument('--generate-template', type=str, help='Generate a starter JSON template for a scanner (e.g., "my-tool")')
    # Other
    parser.add_argument('--output', type=str, default='findings.json', help='Output file for merged findings')
    parser.add_argument('--analyze', action='store_true', help='Enable LLM analysis (requires Ollama)')
    args = parser.parse_args()

    # Handle --generate-template first
    if args.generate_template:
        engine = RuleFusion()
        template = engine.generate_template(args.generate_template)
        output_file = f"rule_template_{args.generate_template}.json"
        with open(output_file, 'w') as f:
            f.write(template)
        print(f"📝 Rule template saved to {output_file}")
        return

    # Handle --update-rules
    if args.update_rules:
        engine = RuleFusion()
        engine.update_community_rules()
        return

    all_findings = []

    # Built-in scanners
    if args.trivy:
        trivy = TrivyScanner()
        all_findings.extend(trivy.parse(args.trivy) if os.path.isfile(args.trivy) else trivy.run(args.trivy))
    if args.semgrep:
        semgrep = SemgrepScanner()
        all_findings.extend(semgrep.parse(args.semgrep) if os.path.isfile(args.semgrep) else semgrep.run(args.semgrep))
    if args.poutine:
        poutine = PoutineScanner()
        all_findings.extend(poutine.parse(args.poutine) if os.path.isfile(args.poutine) else poutine.run(args.poutine))
    if args.zizmor:
        zizmor = ZizmorScanner()
        all_findings.extend(zizmor.parse(args.zizmor) if os.path.isfile(args.zizmor) else zizmor.run(args.zizmor))

    # Custom rule engine (Offline + Online)
    if args.rules:
        engine = RuleFusion(local_rules_path=args.rules)
        custom_findings = engine.load_all_rules()
        all_findings.extend(custom_findings)

    # Save results
    with open(args.output, 'w') as f:
        json.dump(all_findings, f, indent=2)
    print(f"📊 Merged {len(all_findings)} findings into {args.output}")
    save_scan(all_findings)

    # AI Analysis
    if args.analyze:
        print("🧠 Running AI analysis...")
        analyzer = OllamaAnalyzer()
        summary = analyzer.analyze(all_findings)
        summary_file = args.output.replace('.json', '_ai_summary.md')
        with open(summary_file, 'w', encoding='utf-8') as s:
            s.write(f"# 🛡️ Pipeline Sentinel AI Analysis\n\n{summary}")
        print(f"💡 AI summary saved to {summary_file}")


if __name__ == '__main__':
    main()