# 🛡️ Pipeline Sentinel

**Unified CI/CD Security Observability — Offline‑Ready, AI‑Enhanced, Extensible**

Pipeline Sentinel is an open‑source DevSecOps command center. It **aggregates, correlates, and visualises** security findings from **Trivy, Semgrep, Poutine, Zizmor** and any custom scanner you plug in. It works **fully offline**, can optionally pull **community‑curated rules**, and now includes:

- 🧠 **LLM‑powered analysis** (Ollama & LiteLLM) with auto‑remediation
- 🕸️ **Deep attack‑path visualisation** with MITRE ATT&CK mapping
- 📊 **Compliance reports** (PDF) aligned to CIS, PCI‑DSS, ISO 27001
- 🛡️ **Policy‑as‑Code** engine to enforce security gates
- 🐳 **Production‑ready Docker** (multi‑stage, non‑root)

[![GitHub stars](https://img.shields.io/github/stars/Mehrdoost/devsecops-radar?style=social)](https://github.com/Mehrdoost/devsecops-radar/stargazers)
[![License](https://img.shields.io/github/license/Mehrdoost/devsecops-radar)](LICENSE)
[![PyPI version](https://img.shields.io/pypi/v/devsecops-radar.svg)](https://pypi.org/project/devsecops-radar/)
[![GitHub release](https://img.shields.io/github/v/release/Mehrdoost/devsecops-radar?include_prereleases)](https://github.com/Mehrdoost/devsecops-radar/releases)
[![CI](https://github.com/Mehrdoost/devsecops-radar/actions/workflows/test-action.yml/badge.svg)](https://github.com/Mehrdoost/devsecops-radar/actions/workflows/test-action.yml)

> 📖 **Read this in:** [Русский](README_ru.md) | [中文](README_zh.md)

---

## 📸 Dashboard Preview

![Pipeline Sentinel Dashboard](docs/Demo.gif)
*(Severity doughnut, trend line chart, attack‑path graph, topology view, executive summary — all fully offline.)*

---

## 🚀 Quick Start (3 Commands)

```bash
pip install devsecops-radar
devsecops-radar --trivy sample_trivy.json --semgrep sample_semgrep.json
devsecops-radar-web
```

Open http://localhost:8080 – your unified dashboard is live with sample data.

---

## 📖 What Is Pipeline Sentinel?

Pipeline Sentinel is a security observability platform for CI/CD pipelines.
It takes the fragmented JSON output from popular open‑source scanners — Trivy (containers & dependencies), Semgrep (static code analysis), Poutine (GitLab CI security), and Zizmor (GitHub Actions security) — and merges them into a single, dark‑mode dashboard.

### Why It Matters
In 2026, the DevSecOps community witnessed multiple supply‑chain attacks (CVE‑2026‑33634, Mini Shai‑Hulud, TeamPCP) that compromised scanner tools and CI/CD pipelines themselves.
Scanning your code is no longer enough — **you must also scan your pipeline**.
Pipeline Sentinel unifies container scanning, static analysis, and pipeline security checks under one roof, giving you full visibility.

### Who Should Use It

| Persona | Benefit |
| :--- | :--- |
| **DevSecOps Engineers** | One dashboard for Trivy, Semgrep, Poutine, and Zizmor. Correlate findings, track trends, and enforce policies. |
| **Penetration Testers** | Feed custom tool JSON, generate AI‑powered attack graphs with MITRE ATT&CK mapping, and create professional reports. |
| **Security Teams (air‑gapped)** | Works 100% offline. No CDN, no external API calls. All assets embedded. |
| **Compliance Officers** | Generate PDF reports aligned to CIS, PCI‑DSS, or ISO 27001. |
| **CI/CD Pipeline Owners** | Integrate via GitHub Action to get a security summary on every PR. |

---

## ✨ What's New in v0.3.0

| Capability | Description |
| :--- | :--- |
| 🧠 **Auto‑Remediation (`--fix`)** | AI‑suggested fixes applied automatically; creates a git branch for review. |
| 🕸️ **Deep Attack‑Path Visualisation** | Topology‑aware attack graphs with MITRE ATT&CK tactics/techniques. |
| 📊 **Compliance Reports** | PDF reports mapped to CIS, PCI‑DSS, and ISO 27001 controls. |
| 🛡️ **Policy‑as‑Code (`--policy`)** | Enforce rules like “fail if CRITICAL > 5”. |
| 🔒 **Input Validation** | All scanner targets are sanitised against command injection. |
| 🪵 **Structured Logging** | Loguru for clear, coloured, and timestamped logs. |
| 🔐 **API Key Protection** | Simple API key authentication for the web dashboard. |
| 🐳 **Improved Docker Image** | Multi‑stage build, non‑root user, smaller size. |

---

## 📦 Installation

### Option 1 – PyPI (Recommended)
```bash
pip install devsecops-radar
```

### Option 2 – From Source
```bash
git clone [https://github.com/Mehrdoost/devsecops-radar.git](https://github.com/Mehrdoost/devsecops-radar.git)
cd devsecops-radar
pip install -e .
```

### Option 3 – Docker
```bash
docker pull ghcr.io/mehrdoost/devsecops-radar:latest
docker run -p 8080:8080 ghcr.io/mehrdoost/devsecops-radar:latest
```

**With a custom findings file:**
```bash
docker run -p 8080:8080 -v $(pwd)/findings.json:/data/findings.json ghcr.io/mehrdoost/devsecops-radar:latest
```

---

## 📋 Complete Command Reference

### `devsecops-radar` – CLI Flags

| Flag | Description | Example |
| :--- | :--- | :--- |
| `--trivy` | Trivy JSON file or image name | `--trivy results.json` or `--trivy nginx:latest` |
| `--semgrep` | Semgrep JSON file or directory | `--semgrep results.json` or `--semgrep ./src` |
| `--poutine` | Poutine JSON file or repository path | `--poutine results.json` or `--poutine ./repo` |
| `--zizmor` | Zizmor JSON file or repository path | `--zizmor results.json` or `--zizmor ./repo` |
| `--rules` | Directory with custom JSON rule files | `--rules ~/my-security-rules/` |
| `--policy` | Policy JSON file for gating | `--policy policy.json` |
| `--analyze` | Enable LLM analysis (Ollama required) | `--analyze` |
| `--llm-backend` | `ollama` (default) or `litellm` | `--llm-backend litellm` |
| `--llm-model` | Model name | `--llm-model gpt-4o-mini` |
| `--fix` | Auto‑apply AI‑suggested fixes and create a git branch | `--fix` |
| `--topology` | Path to topology JSON file | `--topology topology.json` |
| `--compliance` | Compliance framework: `CIS`, `PCI-DSS`, `ISO27001` | `--compliance CIS` |
| `--report` | Generate PDF report (output filename) | `--report security_report.pdf` |
| `--output` | Output JSON file (default: findings.json) | `--output merged.json` |

### `devsecops-radar-web` – Web Server

```bash
devsecops-radar-web                        # http://localhost:8080
FINDINGS_FILE=my.json devsecops-radar-web  # custom findings file
PIPELINE_API_KEY=secret devsecops-radar-web  # enable API authentication
```

---

## 🧭 How to Use Pipeline Sentinel – Step by Step

### 1. Run Your Security Scanners
Generate JSON output from your tools:

```bash
trivy image --format json -o trivy.json nginx:latest
semgrep --config=auto --json --output semgrep.json .
poutine scan ./repo --format json --output poutine.json
zizmor scan ./repo --output zizmor.json --format json
```

### 2. Merge Findings with the CLI

```bash
devsecops-radar --trivy trivy.json --semgrep semgrep.json --poutine poutine.json --zizmor zizmor.json
```

### 3. View the Dashboard

```bash
devsecops-radar-web
```
Open http://localhost:8080. The dashboard shows:
*   **Severity Breakdown** (doughnut chart)
*   **Trend Over Time** (line chart from scan history)
*   **Pipeline Security** (Poutine + Zizmor statistics)
*   **Attack Path Graph** (if AI analysis enabled)
*   **Executive Summary** (risk score, AI summary)
*   **Findings Table** (searchable & filterable)

### 4. Enable AI Analysis (Optional)

```bash
ollama pull llama3.2:latest
devsecops-radar --trivy trivy.json --analyze
devsecops-radar-web
```
The LLM generates `findings_ai_summary.json` containing:
*   `executive_summary`, `risk_score`
*   `attack_paths` with MITRE ATT&CK tactics
*   `top_remediations` (some with `fix_diff`)
*   `false_positives_likely`

*(The dashboard automatically renders the attack graph and executive summary.)*

### 5. Deep Attack Visualisation with Topology
Create a `topology.json` describing your assets and connections (see `sample_topology.json`). Then run:

```bash
devsecops-radar --trivy trivy.json --analyze --topology topology.json
```
The LLM will map findings onto your topology, producing attack paths that reflect lateral movement across servers and subnets.

### 6. Auto‑Remediation (`--fix`)

```bash
devsecops-radar --trivy trivy.json --analyze --fix
```
The tool will:
1.  Apply AI‑suggested fixes to vulnerable files.
2.  Create a new git branch `auto-fix` and push it.
3.  Print a message to open a Pull Request.

### 7. Policy Enforcement (`--policy`)
Create a `policy.json` file:

```json
{
  "max_critical": 5, 
  "on_violation": "fail"
}
```

Run:
```bash
devsecops-radar --trivy trivy.json --policy policy.json
```
If critical findings exceed 5, the command exits with code 1 – suitable for CI/CD gates.

### 8. Generate Compliance Reports (`--report`)

```bash
devsecops-radar --trivy trivy.json --analyze --compliance CIS --report cis-report.pdf
```
A PDF report is created with an executive summary, risk score, findings table, and compliance mapping (CIS, PCI‑DSS, or ISO 27001).

---

## 🔌 Offline + Online: Hybrid RuleFusion Engine

Pipeline Sentinel is designed for both air‑gapped and connected environments.

### Offline – Local Rules Directory
```bash
devsecops-radar --trivy scan.json --rules ~/my-rules/
```
Place any JSON file in the folder. The engine auto‑detects Trivy, Semgrep, Poutine, Zizmor, or plain‑list formats.

### Online – Community Rules (Optional)
```bash
devsecops-radar --update-rules
```
Clones (or pulls) the `devsecops-radar-rules` repository to `~/.devsecops-radar/community-rules/`.

---

## 🏗️ Architecture

```text
devsecops_radar/
├── cli/            # CLI entry – plugin registry, policy, remediation
├── core/           # RuleFusion, DB, analysers, reporting
├── scanners/       # Pluggable scanner classes (BaseScanner)
└── web/            # Flask dashboard (embedded HTML)
```

*Adding a new scanner is as simple as extending `BaseScanner` and implementing `parse()`.*

---

## 🔒 Security

*   **Input validation** – scanner targets are sanitised.
*   **Offline‑first** – no data leaves your network.
*   **LLM privacy** – Ollama runs locally; optional LiteLLM for cloud models.
*   **API authentication** – optional API key for dashboard access.
*   **Non‑root Docker** – container runs as unprivileged user.
*   **Policy‑as‑Code** – enforce gates before deployment.

---

## 🤖 GitHub Action

```yaml
- name: Pipeline Sentinel
  uses: Mehrdoost/devsecops-radar/action@main
  with:
    trivy_report: trivy-results.json
    semgrep_report: semgrep-results.json
    poutine_report: poutine-results.json
    zizmor_report: zizmor-results.json
```
*Merges findings, creates a job summary, and outputs CRITICAL/HIGH counts.*

---

## 🗺️ Roadmap

- [x] Multi‑scanner plugin engine
- [x] LLM analysis (Ollama + LiteLLM) with auto‑remediation
- [x] Scan history, trend chart, scan diff
- [x] Attack‑path visualisation with MITRE ATT&CK & topology
- [x] Policy‑as‑Code engine
- [x] Compliance reports (PDF)
- [x] GitHub Action
- [x] Docker image (multi‑stage, non‑root)
- [ ] Jira / Slack integration
- [ ] SARIF & CycloneDX support

---

## 👨‍💻 Author

**Mehrdoost**

[![GitHub](https://img.shields.io/badge/GitHub-Mehrdoost-181717?logo=github)](https://github.com/Mehrdoost)


---

## 📜 License

MIT – see [LICENSE](LICENSE).

⭐ **If this project helps your team ship safer software, drop a star — it makes a real difference.**