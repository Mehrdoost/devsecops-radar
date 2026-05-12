import argparse
import json
import os
from devsecops_radar.scanners.trivy import TrivyScanner
from devsecops_radar.scanners.semgrep import SemgrepScanner
from devsecops_radar.scanners.poutine import PoutineScanner

def main():
    parser = argparse.ArgumentParser(description='DevSecOps Radar - Collect and view security findings.')
    parser.add_argument('--trivy', type=str, help='Path to Trivy JSON output file or image name to scan directly')
    parser.add_argument('--semgrep', type=str, help='Path to Semgrep JSON output file or target directory to scan directly')
    parser.add_argument('--poutine', type=str, help='Path to Poutine JSON output file or repository path to scan directly')
    parser.add_argument('--output', type=str, default='findings.json', help='Output file for merged findings')
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

    with open(args.output, 'w') as f:
        json.dump(all_findings, f, indent=2)
    print(f"Merged {len(all_findings)} findings into {args.output}")

if __name__ == '__main__':
    main()