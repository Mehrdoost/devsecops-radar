import json
import os
import sys
from pathlib import Path


def _is_safe_path(file_path: str) -> bool:
    """Ensure the file is inside the current working directory."""
    try:
        cwd = Path.cwd().resolve()
        target = (cwd / file_path).resolve()
        return target.is_relative_to(cwd)
    except Exception:
        return False


def _load_findings(file_path: str) -> list[dict]:
    """Safely load and return findings from a JSON file."""
    if not _is_safe_path(file_path):
        print(f"::error file={file_path} is outside the allowed directory")
        return []

    path = Path(file_path)
    if not path.is_file():
        print(f"::warning file={file_path} not found")
        return []

    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, list):
            return data
        if isinstance(data, dict):
            return data.get("findings", [])
        return []
    except json.JSONDecodeError as e:
        print(f"::error Invalid JSON in {file_path}: {e}")
        return []
    except OSError as e:
        print(f"::error Cannot read {file_path}: {e}")
        return []


def _count_by_severity(findings: list[dict]) -> dict[str, int]:
    """Count findings per severity level."""
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}
    for f in findings:
        sev = str(f.get("severity", "UNKNOWN")).upper()
        if sev in counts:
            counts[sev] += 1
        else:
            counts["UNKNOWN"] += 1
    return counts


def _generate_summary_table(counts: dict[str, int]) -> list[str]:
    """Build the Markdown summary table."""
    return [
        "## 🛡️ Pipeline Sentinel Scan Results",
        "",
        "| Severity | Count |",
        "| --- | --- |",
        f"| 🔴 CRITICAL | {counts['CRITICAL']} |",
        f"| 🟠 HIGH     | {counts['HIGH']} |",
        f"| 🟡 MEDIUM   | {counts['MEDIUM']} |",
        f"| 🔵 LOW      | {counts['LOW']} |",
    ]


def _generate_critical_details(findings: list[dict]) -> list[str]:
    """List critical findings."""
    criticals = [f for f in findings if f.get("severity") == "CRITICAL"]
    if not criticals:
        return []
    lines = ["\n### 🚨 Critical Findings\n"]
    for f in criticals:
        tool = f.get("tool", "UNKNOWN")
        fid = f.get("id", "UNKNOWN")
        title = f.get("title", "")
        target = f.get("target", "")
        lines.append(f"- **[{tool}]** {fid}: {title} (`{target}`)")
    return lines


def _write_github_output(counts: dict[str, int]) -> None:
    """Export counts as GitHub Action outputs."""
    output_file = os.environ.get("GITHUB_OUTPUT")
    if not output_file:
        return
    with open(output_file, "a", encoding="utf-8") as out:
        out.write(f"critical_count={counts['CRITICAL']}\n")
        out.write(f"high_count={counts['HIGH']}\n")
        total = sum(counts.values())
        out.write(f"total_count={total}\n")


def _write_step_summary(lines: list[str]) -> None:
    """Append lines to the GitHub Step Summary."""
    summary_file = os.environ.get("GITHUB_STEP_SUMMARY")
    if not summary_file:
        return
    with open(summary_file, "a", encoding="utf-8") as s:
        s.write("\n".join(lines) + "\n")


def main() -> None:
    if len(sys.argv) < 2:
        print("::error Usage: comment_on_pr.py <findings.json>")
        sys.exit(1)

    file_path = sys.argv[1]
    findings = _load_findings(file_path)
    if not findings:
        return

    counts = _count_by_severity(findings)

    lines = _generate_summary_table(counts)
    lines.extend(_generate_critical_details(findings))

    _write_github_output(counts)
    _write_step_summary(lines)


if __name__ == "__main__":
    main()