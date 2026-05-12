import argparse
import json
import os
from devsecops_radar.scanners.trivy import TrivyScanner
from devsecops_radar.scanners.semgrep import SemgrepScanner
from devsecops_radar.scanners.poutine import PoutineScanner
from devsecops_radar.scanners.zizmor import ZizmorScanner
from devsecops_radar.core.analyzer import OllamaAnalyzer
from devsecops_radar.core.database import save_scan

def main():
    parser = argparse.ArgumentParser(description='DevSecOps Radar - Collect and view security findings.')
    parser.add_argument('--trivy', type=str, help='Path to Trivy JSON output file or image name to scan directly (e.g., nginx:latest)')
    parser.add_argument('--semgrep', type=str, help='Path to Semgrep JSON output file or target directory to scan directly')
    parser.add_argument('--poutine', type=str, help='Path to Poutine JSON output file or repository path to scan directly')
    parser.add_argument('--zizmor', type=str, help='Path to Zizmor JSON output file or repository path to scan directly')
    parser.add_argument('--output', type=str, default='findings.json', help='Output file for merged findings')
    parser.add_argument('--analyze', action='store_true', help='Enable LLM analysis (requires Ollama running locally)')
    args = parser.parse_args()

    all_findings = []

    if args.trivy:
        trivy = TrivyScanner()
        if os.path.isfile(args.trivy):
            all_findings.extend(trivy.parse(args.trivy))
        else:
            print(f"Scanning image: {args.trivy}")
            all_findings.extend(trivy.run(args.trivy))

    if args.semgrep:
        semgrep = SemgrepScanner()
        if os.path.isfile(args.semgrep):
            all_findings.extend(semgrep.parse(args.semgrep))
        else:
            print(f"Scanning directory: {args.semgrep}")
            all_findings.extend(semgrep.run(args.semgrep))

    if args.poutine:
        poutine = PoutineScanner()
        if os.path.isfile(args.poutine):
            all_findings.extend(poutine.parse(args.poutine))
        else:
            print(f"Scanning repository: {args.poutine}")
            all_findings.extend(poutine.run(args.poutine))

    if args.zizmor:
        zizmor = ZizmorScanner()
        if os.path.isfile(args.zizmor):
            all_findings.extend(zizmor.parse(args.zizmor))
        else:
            print(f"Scanning repository: {args.zizmor}")
            all_findings.extend(zizmor.run(args.zizmor))

    with open(args.output, 'w') as f:
        json.dump(all_findings, f, indent=2)
    print(f"Merged {len(all_findings)} findings into {args.output}")

    # Save to scan history database
    save_scan(all_findings)

    if args.analyze:
        print("Running AI analysis...")
        analyzer = OllamaAnalyzer()
        summary = analyzer.analyze(all_findings)
        summary_file = args.output.replace('.json', '_ai_summary.md')
        with open(summary_file, 'w', encoding='utf-8') as s:
            s.write(f"# 🛡️ Pipeline Sentinel AI Analysis\n\n{summary}")
        print(f"AI summary saved to {summary_file}")

if __name__ == '__main__':
    main()