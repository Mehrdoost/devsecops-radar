<!-- markdownlint-disable MD033 MD041 -->
<div align="center">

# 🛡️ Pipeline Sentinel
**The Open‑Source DevSecOps Command Center — Unify, Analyse, Remediate.**

[![PyPI version](https://img.shields.io/pypi/v/devsecops-radar?style=flat-square&color=blue)](https://pypi.org/project/devsecops-radar/)
[![License](https://img.shields.io/github/license/Mehrdoost/devsecops-radar?style=flat-square)](LICENSE)
[![GitHub release](https://img.shields.io/github/v/release/Mehrdoost/devsecops-radar?include_prereleases&style=flat-square)](https://github.com/Mehrdoost/devsecops-radar/releases)
[![CI](https://img.shields.io/github/actions/workflow/status/Mehrdoost/devsecops-radar/test-action.yml?branch=main&style=flat-square)](https://github.com/Mehrdoost/devsecops-radar/actions)
[![Stars](https://img.shields.io/github/stars/Mehrdoost/devsecops-radar?style=flat-square)](https://github.com/Mehrdoost/devsecops-radar/stargazers)

</div>

> 📖 **Read this in:** [Русский](README_ru.md) | [中文](README_zh.md)

---

## 📖 Table of Contents
1. [What Is Pipeline Sentinel? (Simple Explanation)](#-what-is-pipeline-sentinel-simple-explanation)
2. [Why You Need It](#-why-you-need-it)
3. [Where to Run It in Your Network](#-where-to-run-it-in-your-network)
4. [Dashboard Preview](#-dashboard-preview)
5. [Quick Start](#-quick-start)
6. [Installation](#-installation)
7. [How to Use (Step‑by‑Step)](#-how-to-use-stepbystep)
8. [Complete Command Reference](#-complete-command-reference)
9. [Core Capabilities](#-core-capabilities)
10. [Architecture](#️-architecture)
11. [Roadmap](#️-roadmap)
12. [GitHub Action](#-github-action)
13. [Contributing](#-contributing)
14. [Author](#-author)
15. [License](#-license)

---

## 👨‍👩‍👧 What Is Pipeline Sentinel? (Simple Explanation)

Imagine you have several security guards, each watching a different door of a building. They all shout their findings in different languages, and you have to run around to understand what’s going on.

**Pipeline Sentinel** puts them all in one room, translates their reports, and shows you a single, clear screen with the full picture. It connects to tools like **Trivy** (checks your containers), **Semgrep** (scans your code), **Poutine** (audits your GitLab pipelines), **Zizmor** (secures your GitHub Actions), and **Gitleaks** (finds secrets). Instead of digging through multiple JSON files, you get a **beautiful, dark‑mode dashboard** that tells you what’s critical, how risks are trending, and even how an attacker might chain several small issues into a big problem.

Think of it as a **security camera system for your entire CI/CD pipeline** — it watches everything, alerts you, and even suggests fixes, all without needing internet access if you want.

---

## 💥 Why You Need It

In 2026, **supply chain attacks** have become the #1 threat. Tools like Trivy themselves were compromised, and attackers now inject malicious code directly into build pipelines. **You can no longer just scan your code; you must scan your pipeline.**

Pipeline Sentinel gives you:
*   **One screen for all scanners** – stop juggling log files.
*   **AI that understands attack chains** – “A leaked secret + an old library = a disaster.”
*   **Automatic fixes** – with a single flag, it patches files and opens a pull request.
*   **Human review mode** – inspect each fix before applying.
*   **Compliance reports** – generate a PDF for your boss or auditor.
*   **100% offline capable** – works in air‑gapped environments where security matters most.
*   **Interactive wizard** – one command to get everything running.

---

## 📍 Where to Run It in Your Network

Pipeline Sentinel is designed to be **flexible** — you decide where it fits best:

| Deployment | Description |
| :--- | :--- |
| 🖥️ **Local Developer Machine** | Run the CLI and dashboard right on your laptop. Perfect for individual pentesters or developers who want instant feedback. |
| 🔧 **CI/CD Runner** | Use the GitHub Action or call `devsecops-radar` directly in your Jenkins/GitLab CI scripts. It can fail the build if critical vulnerabilities exceed your policy (`--policy`). |
| 🏢 **Central Security Server** | Install on a dedicated server (via Docker or pip) that collects scan results from multiple teams. The dashboard becomes a shared security operations console. |
| 🌐 **Air‑Gapped Networks** | Copy the Docker image and sample data to an offline server. The dashboard works with zero external calls — all assets are embedded. |

### Typical Network Flow

```text
[Trivy scan] ──┐
[Semgrep scan] ─┤
[Poutine scan] ─┼──> devsecops-radar (CLI) ──> findings.json ──> Dashboard (Flask) ──> Browser
[Zizmor scan] ─┘
[Gitleaks scan] ┘
```

> **📌 Diagram Placeholder:**  
![Network Flow Diagram](docs/architecture.png)

---

## 📸 Dashboard Preview

![Pipeline Sentinel Dashboard](docs/Demo.gif)
*(Severity doughnut, trend line chart, attack‑path graph (clickable nodes), topology view, executive summary — all fully offline.)*

---

## 🚀 Quick Start

```bash
# 1. Install from PyPI
pip install devsecops-radar

# 2. Feed scanner data (sample data is included in the repo)
devsecops-radar --trivy sample_trivy.json --semgrep sample_semgrep.json

# 3. Launch the dashboard
devsecops-radar-web
```

Open http://localhost:8080 — your unified dashboard is live with sample findings.

🧙 **Want a fully guided setup? Run the wizard:**
```bash
devsecops-radar --wizard
```

---

## 📦 Installation

### Option 1 — PyPI (Recommended)
```bash
pip install devsecops-radar
```

### Option 2 — From Source
```bash
git clone [https://github.com/Mehrdoost/devsecops-radar.git](https://github.com/Mehrdoost/devsecops-radar.git)
cd devsecops-radar
pip install -e .
```

### Option 3 — Docker
```bash
docker pull ghcr.io/mehrdoost/devsecops-radar:latest
docker run -p 8080:8080 ghcr.io/mehrdoost/devsecops-radar:latest
```

**Mount your own findings file:**
```bash
docker run -p 8080:8080 -v $(pwd)/findings.json:/data/findings.json ghcr.io/mehrdoost/devsecops-radar:latest
```

**Or use Docker Compose:**
```bash
docker compose up
```

### 🧙 One‑Command Install (curl)
```bash
curl -fsSL [https://raw.githubusercontent.com/Mehrdoost/devsecops-radar/main/install.sh](https://raw.githubusercontent.com/Mehrdoost/devsecops-radar/main/install.sh) | bash
```
*This script installs Python dependencies, Ollama, pulls the AI model, and starts the wizard.*

---

## 🧭 How to Use (Step‑by‑Step)

### 1. Run Your Security Scanners
Generate JSON output from your tools:

```bash
trivy image --format json -o trivy.json nginx:latest
semgrep --config=auto --json --output semgrep.json .
poutine scan ./repo --format json --output poutine.json
zizmor scan ./repo --output zizmor.json --format json
gitleaks detect --source . --report-format json --report-path gitleaks.json
```

### 2. Merge Findings with the CLI
```bash
devsecops-radar --trivy trivy.json --semgrep semgrep.json --poutine poutine.json --zizmor zizmor.json --gitleaks gitleaks.json
```
This produces a single `findings.json` with all findings merged and normalised.

### 3. View the Dashboard
```bash
devsecops-radar-web
```
The dashboard shows:
*   **Severity Breakdown** – Doughnut chart
*   **Trend Over Time** – Line chart from scan history
*   **Pipeline Security** – Poutine + Zizmor statistics card
*   **Attack Path Graph** – Interactive D3.js graph (click nodes for details)
*   **Executive Summary** – Risk score and AI‑generated summary
*   **Findings Table** – Searchable, filterable, paginated

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

### 5. Auto‑Remediation (with Human Review)
```bash
# Apply fixes automatically
devsecops-radar --trivy trivy.json --analyze --fix

# Review each fix before applying
devsecops-radar --trivy trivy.json --analyze --fix --review
```
The tool creates a new git branch `auto-fix` and pushes it for review.

### 6. Policy Enforcement
Create a `policy.json` file:
```json
{
  "max_critical": 5, 
  "on_violation": "fail"
}
```

```bash
devsecops-radar --trivy trivy.json --policy policy.json
```
If critical findings exceed 5, the command exits with code 1 — perfect for CI/CD gates.

### 7. Generate Compliance Reports
```bash
devsecops-radar --trivy trivy.json --analyze --compliance CIS --report cis-report.pdf
```
A PDF report is created with an executive summary, risk score, findings table, and compliance mapping. Sensitive data can be redacted automatically.

### 8. Security Badge for Your Project
After running a scan, you can embed a dynamic security badge in your `README`:
```markdown
[![Security Status](https://your-server/badge/1.svg)](https://github.com/Mehrdoost/devsecops-radar)
```
The badge color changes based on the number of critical findings (green/yellow/red).

---

## 📋 Complete Command Reference

### `devsecops-radar` — CLI Flags

| Flag | Description | Example |
| :--- | :--- | :--- |
| `--trivy` | Trivy JSON file or image name | `--trivy results.json` or `--trivy nginx:latest` |
| `--semgrep` | Semgrep JSON file or directory | `--semgrep results.json` or `--semgrep ./src` |
| `--poutine` | Poutine JSON file or repo path | `--poutine results.json` or `--poutine ./repo` |
| `--zizmor` | Zizmor JSON file or repo path | `--zizmor results.json` or `--zizmor ./repo` |
| `--gitleaks` | Gitleaks JSON file or repo path | `--gitleaks results.json` or `--gitleaks ./repo` |
| `--rules` | Directory with custom JSON rule files | `--rules ~/my-security-rules/` |
| `--policy` | Policy JSON file for gating | `--policy policy.json` |
| `--analyze` | Enable LLM analysis (Ollama required) | `--analyze` |
| `--llm-backend` | `ollama` (default) or `litellm` | `--llm-backend litellm` |
| `--llm-model` | Model name | `--llm-model gpt-4o-mini` |
| `--fix` | Auto‑apply AI‑suggested fixes | `--fix` |
| `--review` | Review each AI fix before applying | `--review` |
| `--topology` | Path to topology JSON file | `--topology topology.json` |
| `--compliance` | Framework: `CIS`, `PCI-DSS`, `ISO27001` | `--compliance CIS` |
| `--report` | Generate PDF report (output filename) | `--report security_report.pdf` |
| `--output` | Output JSON file (default: findings.json) | `--output merged.json` |
| `--wizard` | Interactive first‑time setup wizard | `--wizard` |

### `devsecops-radar-web` — Web Server

```bash
devsecops-radar-web                          # Launch on http://localhost:8080
FINDINGS_FILE=my.json devsecops-radar-web    # Use a custom findings file
PIPELINE_API_KEY=secret devsecops-radar-web  # Enable API authentication
```

---

## ✨ Core Capabilities

### 🔌 Multi‑Scanner Plugin Architecture
Built‑in support for five scanners with a real plugin system. Third‑party scanners can be installed as separate packages and discovered automatically via Python entry points. An adapter pattern validates all findings with Pydantic.

| Scanner | What It Scans | Flag |
| :--- | :--- | :--- |
| **Trivy** | Container images & dependencies | `--trivy` |
| **Semgrep** | Static Code Analysis (SAST) | `--semgrep` |
| **Poutine** | GitLab CI/CD configuration security | `--poutine` |
| **Zizmor** | GitHub Actions workflow security | `--zizmor` |
| **Gitleaks**| Secrets detection | `--gitleaks` |

### 🧩 Hybrid RuleFusion Engine
*   **Offline** – Load custom JSON rules from any local directory (`--rules ~/my-rules/`)
*   **Online** – Pull community‑curated rules from a configurable Git repository (`--update-rules`)
*   Auto‑detects Trivy, Semgrep, Poutine, Zizmor, and plain‑list formats
*   Policy evaluation built directly into the engine
*   Community rules repo: `devsecops-radar-rules` (configurable via `COMMUNITY_RULES_REPO`)

### 🧠 LLM‑Powered Analysis
*   Retry logic with exponential backoff for unstable endpoints
*   Few‑shot examples covering real‑world supply chain attack chains
*   Token‑aware selection (max items configurable via `ANALYZER_MAX_FINDINGS`)
*   Structured JSON output: `executive_summary`, `risk_score`, `attack_paths` (MITRE ATT&CK), `top_remediations`, `false_positives_likely`
*   Ollama (local, offline) and LiteLLM (OpenAI, Anthropic, etc.) support

### 🕸️ Multi‑Step Attack Path Visualization
Interactive D3.js force graph that chains findings into realistic attack scenarios. Click any node to see detailed finding information. Accepts a topology file to map findings onto your actual infrastructure, showing lateral movement across servers and subnets.

### 🛡️ Policy‑as‑Code
Define security gates as simple JSON:
```json
{
  "max_critical": 5, 
  "on_violation": "fail"
}
```
*If critical findings exceed the threshold, the CLI exits with code 1 — perfect for failing CI/CD pipelines.*

### 🛠️ Auto‑Remediation with Human‑in‑the‑Loop
AI‑suggested fixes can be applied automatically (`--fix`) or reviewed one‑by‑one (`--review`). The tool creates a new git branch and pushes it for review. A `fix.sh` script is also generated for manual commands.

### 📊 Compliance & Executive Reports (with Redaction)
Generate professional PDF reports (`--report report.pdf`) with:
*   Executive summary and risk score
*   Findings table (first 50 items)
*   Compliance mapping (CIS, PCI‑DSS, ISO 27001)
*   Automatic redaction of passwords, tokens, JWTs

### 📈 Scan History & Trends (with Pagination)
SQLAlchemy‑backed database with server‑side pagination (`/api/findings?page=1&per_page=50`). Scan history is stored efficiently, enabling fast trend charts and historical comparisons.

### 🧪 SBOM & Dependency Confusion Detection
*   Generate a CycloneDX SBOM from your project using `syft`
*   Detect dependency confusion risks in `package.json` and `requirements.txt` — internal packages that could be impersonated by public registries

### 🔍 RAG‑Powered Security Search
Ask natural language questions about your scan history: *“When was the last Log4j vulnerability found?”* The built‑in RAG endpoint (`/api/rag?q=...`) searches stored findings and returns matches.

### ⚔️ Attack Simulation (Sandbox)
Generate a simple proof‑of‑concept script for any finding and execute it inside a disposable Docker container to demonstrate the risk without harming your system.

### 📉 Dynamic Risk Scoring
Beyond CVSS, each finding gets a dynamic risk score based on asset exposure (from topology) and exploit availability — helping teams prioritise what to fix first.

### 🧙 Interactive Wizard
A `--wizard` flag walks new users through installing dependencies, pulling AI models, and running their first scan — all in one go.

### 🔒 Privacy & Offline‑First
*   All assets (CSS, JS) are embedded — zero CDN calls
*   LLM analysis runs locally with Ollama; no data leaves your network
*   Optional API key authentication for the dashboard
*   Docker image runs as non‑root user

---

## 🏗️ Architecture

```text
devsecops_radar/
├── cli/            # CLI entry point – plugin discovery, policy, remediation
├── core/           # RuleFusion engine, DB (SQLAlchemy), LLM analysers
├── scanners/       # Pluggable scanner classes (extend ScannerPlugin)
├── plugins/        # ScannerPlugin abstract base class & entry points
└── web/            # Flask dashboard (modular Blueprints)
    ├── dashboard/  # Main dashboard routes & embedded HTML
    ├── attack_paths/
    ├── topology/
    ├── summary/
    └── sentry/     # Live webhook agent for CI/CD
```

> **📌 Diagram Placeholder:**  
![Architecture Diagram](docs/architecture.png)

---

## 🗺️ Roadmap

| Phase | Feature | Status |
| :--- | :--- | :--- |
| ✅ **Phase 1** | Multi‑scanner engine (Trivy, Semgrep, Poutine, Zizmor) | Done |
| ✅ **Phase 1** | LLM analysis (Ollama + LiteLLM) | Done |
| ✅ **Phase 1** | Scan history, trend chart, scan diff | Done |
| ✅ **Phase 1** | GitHub Action (composite) | Done |
| ✅ **Phase 1** | Docker image (multi‑stage, non‑root) | Done |
| ✅ **Phase 2** | Attack‑path visualization with MITRE ATT&CK & topology | Done |
| ✅ **Phase 2** | Policy‑as‑Code engine (`--policy`) | Done |
| ✅ **Phase 2** | Auto‑remediation engine (`--fix`) | Done |
| ✅ **Phase 2** | Compliance reports (PDF) with redaction | Done |
| ✅ **Phase 2** | Hybrid RuleFusion engine (local + community rules) | Done |
| ✅ **Phase 3** | Web dashboard Blueprint refactor (modular Flask) | Done |
| ✅ **Phase 3** | Real scanner plugin system with entry points | Done |
| ✅ **Phase 3** | SQLAlchemy ORM with pagination | Done |
| ✅ **Phase 3** | SBOM & Dependency Confusion Detection | Done |
| ✅ **Phase 3** | RAG‑powered security search | Done |
| ✅ **Phase 3** | Attack Simulation (sandbox) | Done |
| ✅ **Phase 3** | Dynamic Risk Scoring | Done |
| ✅ **Phase 3** | Interactive wizard (`--wizard`) | Done |
| ✅ **Phase 3** | Human review mode (`--review`) | Done |
| ✅ **Phase 3** | Gitleaks secret scanner | Done |
| ✅ **Phase 3** | Security badge endpoint | Done |
| 🔲 **Phase 4** | Jira / Slack integration | Planned |
| 🔲 **Phase 4** | SARIF & CycloneDX support | Planned |
| 🔲 **Phase 4** | Rule Marketplace (community YAML rules) | Planned |
| 🔲 **Phase 4** | Pull Request assistant (GitHub App) | Planned |

> See the [open issues](https://github.com/Mehrdoost/devsecops-radar/issues) for a full list of proposed features.

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
    gitleaks_report: gitleaks-results.json
```
*The action merges findings, creates a job summary, and outputs CRITICAL/HIGH counts.*

---

## 🤝 Contributing

Pull requests and issues are warmly welcome!
If you would like to integrate a new scanner, open an issue with a sample of its JSON output.
For permanent scanner plugins, extend the `ScannerPlugin` class and register it via entry points.

---

## 👨‍💻 Author

**Mehrdoost** 

[![GitHub](https://img.shields.io/badge/GitHub-Mehrdoost-181717?logo=github)](https://github.com/Mehrdoost)


---

## 📜 License

MIT — see [LICENSE](LICENSE).

<div align="center">
⭐ If this project helps your team ship safer software, drop a star — it makes a real difference.
</div>
