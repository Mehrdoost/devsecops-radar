import json
import os
import sys
from pathlib import Path

from loguru import logger

from devsecops_radar.core.models import FindingSchema
from devsecops_radar.core.path_security import safe_read_open


def _load_findings(file_path: str) -> list[dict]:
    """Safely load and validate findings from a JSON file."""
    try:
        with safe_read_open(file_path, base_dir=Path.cwd()) as f:
            data = json.load(f)
    except ValueError as e:
        print(f"::error file={file_path} is outside the allowed directory – {e}")
        return []
    except (FileNotFoundError, PermissionError, OSError) as e:
        print(f"::warning file={file_path} not found or not accessible – {e}")
        return []
    except json.JSONDecodeError as e:
        print(f"::error Invalid JSON in {file_path}: {e}")
        return []

    if isinstance(data, list):
        raw_findings = data
    elif isinstance(data, dict):
        raw_findings = data.get("findings", [])
    else:
        print(f"::error Unexpected JSON structure in {file_path}")
        return []

    validated = []
    for item in raw_findings:
        if not isinstance(item, dict):
            continue
        try:
            validated.append(FindingSchema(**item).model_dump())
        except Exception:
            logger.debug("Skipping invalid entry in comment_on_pr", exc_info=True)
    return validated


def _escape_markdown(text: str) -> str:
    return text.replace("`", "\\`").replace("|", "\\|")


def _count_by_severity(findings: list[dict]) -> dict[str, int]:
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}
    for f in findings:
        sev = str(f.get("severity", "UNKNOWN")).upper()
        counts[sev] = counts.get(sev, 0) + 1
    return counts


def _generate_summary_table(counts: dict[str, int]) -> list[str]:
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
    criticals = [f for f in findings if f.get("severity") == "CRITICAL"]
    if not criticals:
        return []
    lines = ["\n### 🚨 Critical Findings\n"]
    for f in criticals:
        tool = _escape_markdown(str(f.get("tool", "UNKNOWN")))
        fid = _escape_markdown(str(f.get("id", "UNKNOWN")))
        title = _escape_markdown(str(f.get("title", "")))
        target = _escape_markdown(str(f.get("target", "")))
        lines.append(f"- **[{tool}]** {fid}: {title} (`{target}`)")
    return lines


def _write_github_output(counts: dict[str, int]) -> None:
    output_file = os.environ.get("GITHUB_OUTPUT")
    if not output_file:
        return
    with open(output_file, "a", encoding="utf-8") as out:
        out.write(f"critical_count={counts['CRITICAL']}\n")
        out.write(f"high_count={counts['HIGH']}\n")
        total = sum(counts.values())
        out.write(f"total_count={total}\n")


def _write_step_summary(lines: list[str]) -> None:
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
