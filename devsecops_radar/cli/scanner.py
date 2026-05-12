import argparse
import json
import subprocess
import tempfile
import os
from devsecops_radar.core.parser import parse_trivy_json, parse_semgrep_json, merge_findings

def run_trivy(target):
    with tempfile.NamedTemporaryFile(suffix='.json', delete=False) as tmp:
        outfile = tmp.name
    try:
        subprocess.run(['trivy', 'image', '--format', 'json', '--output', outfile, target], check=True)
        return parse_trivy_json(outfile)
    finally:
        if os.path.exists(outfile):
            os.unlink(outfile)

def run_semgrep(target_dir):
    with tempfile.NamedTemporaryFile(suffix='.json', delete=False) as tmp:
        outfile = tmp.name
    try:
        subprocess.run(['semgrep', '--config=auto', '--json', '--output', outfile, target_dir], check=True)
        return parse_semgrep_json(outfile)
    finally:
        if os.path.exists(outfile):
            os.unlink(outfile)

def main():
    parser = argparse.ArgumentParser(description='DevSecOps Radar - Collect and view security findings.')
    parser.add_argument('--trivy', type=str, help='Path to Trivy JSON output file or image name to scan directly (e.g., nginx:latest)')
    parser.add_argument('--semgrep', type=str, help='Path to Semgrep JSON output file or target directory to scan directly')
    parser.add_argument('--output', type=str, default='findings.json', help='Output file for merged findings')
    args = parser.parse_args()

    all_findings = []
    if args.trivy:
        if os.path.isfile(args.trivy):
            all_findings.append(parse_trivy_json(args.trivy))
        else:
            print(f"Scanning image: {args.trivy}")
            all_findings.append(run_trivy(args.trivy))
    if args.semgrep:
        if os.path.isfile(args.semgrep):
            all_findings.append(parse_semgrep_json(args.semgrep))
        else:
            print(f"Scanning directory: {args.semgrep}")
            all_findings.append(run_semgrep(args.semgrep))

    merged = merge_findings(*all_findings)
    with open(args.output, 'w') as f:
        json.dump(merged, f, indent=2)
    print(f"Merged {len(merged)} findings into {args.output}")

if __name__ == '__main__':
    main()