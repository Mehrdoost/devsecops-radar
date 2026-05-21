import json
import os
import sys


def main():
    file_path = sys.argv[1]
    if not os.path.exists(file_path):
        print("No findings file found")
        return

    with open(file_path) as f:
        data = json.load(f)

    criticals = [f for f in data if f.get('severity') == 'CRITICAL']
    highs = [f for f in data if f.get('severity') == 'HIGH']
    mediums = [f for f in data if f.get('severity') == 'MEDIUM']
    lows = [f for f in data if f.get('severity') == 'LOW']

    lines = [
        "## 🛡️ Pipeline Sentinel Scan Results",
        "",
        "| Severity | Count |",
        "| --- | --- |",
        f"| 🔴 CRITICAL | {len(criticals)} |",
        f"| 🟠 HIGH     | {len(highs)} |",
        f"| 🟡 MEDIUM   | {len(mediums)} |",
        f"| 🔵 LOW      | {len(lows)} |",
    ]

    if criticals:
        lines.append("\n### 🚨 Critical Findings\n")
        for f in criticals:
            lines.append(f"- **[{f['tool']}]** {f['id']}: {f.get('title','')} (`{f.get('target','')}`)")

    summary = os.environ.get('GITHUB_STEP_SUMMARY')
    if summary:
        with open(summary, 'a') as s:
            s.write('\n'.join(lines))

    if 'GITHUB_OUTPUT' in os.environ:
        with open(os.environ['GITHUB_OUTPUT'], 'a') as out:
            out.write(f"critical_count={len(criticals)}\n")
            out.write(f"high_count={len(highs)}\n")


if __name__ == '__main__':
    main()
