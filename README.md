<div align="center">

# 🛡️ Pipeline Sentinel

[cite_start]**The Open‑Source DevSecOps Command Center — Unify, Analyse, Remediate.** [cite: 1]

[cite_start][![PyPI version](https://img.shields.io/pypi/v/devsecops-radar?style=flat-square&color=blue)](https://pypi.org/project/devsecops-radar/) [cite: 1]
[cite_start][![License](https://img.shields.io/github/license/Mehrdoost/devsecops-radar?style=flat-square)](LICENSE) [cite: 1]
[cite_start][![GitHub release](https://img.shields.io/github/v/release/Mehrdoost/devsecops-radar?include_prereleases&style=flat-square)](https://github.com/Mehrdoost/devsecops-radar/releases) [cite: 1]
[cite_start][![CI](https://img.shields.io/github/actions/workflow/status/Mehrdoost/devsecops-radar/ci.yml?branch=main&style=flat-square)](https://github.com/Mehrdoost/devsecops-radar/actions) [cite: 1]
[cite_start][![Stars](https://img.shields.io/github/stars/Mehrdoost/devsecops-radar?style=flat-square)](https://github.com/Mehrdoost/devsecops-radar/stargazers) [cite: 1]

</div>

> 📖 **Read this in:** [Русский](README_ru.md) | [cite_start][中文](README_zh.md) [cite: 1, 2]

---

## 📖 Table of Contents

1. [What Is Pipeline Sentinel? (Simple Explanation)[cite_start]](#-what-is-pipeline-sentinel-simple-explanation) [cite: 2]
2. [cite_start][Why You Need It](#-why-you-need-it) [cite: 2]
3. [cite_start][Where to Run It in Your Network](#-where-to-run-it-in-your-network) [cite: 2]
4. [cite_start][Dashboard Preview](#-dashboard-preview) [cite: 2]
5. [cite_start][Quick Start](#-quick-start) [cite: 2]
6. [cite_start][Prerequisites](#-prerequisites) [cite: 2]
7. [cite_start][Installation](#-installation) [cite: 2]
8. [cite_start][How to Use (Step‑by‑Step)](#-how-to-use-stepbystep) [cite: 2]
9. [cite_start][Complete Command Reference](#-complete-command-reference) [cite: 2]
10. [cite_start][Core Capabilities](#-core-capabilities) [cite: 2]
11. [cite_start][Community Rules & Online Updates](#-community-rules--online-updates) [cite: 2]
12. [cite_start][Architecture](#-architecture) [cite: 2]
13. [cite_start][Roadmap](#-roadmap) [cite: 2]
14. [cite_start][Testing & CI](#-testing--ci) [cite: 2]
15. [cite_start][Contributing](#-contributing) [cite: 2]
16. [cite_start][Author](#-author) [cite: 2]
17. [cite_start][License](#-license) [cite: 2]

---

## 👨‍👩‍👧 What Is Pipeline Sentinel? (Simple Explanation) [cite_start][cite: 3]

[cite_start]Imagine you have several security guards, each watching a different door of a building. [cite: 3] [cite_start]They all shout their findings in different languages, and you have to run around to understand what’s going on. [cite: 4] [cite_start]**Pipeline Sentinel** puts them all in one room, translates their reports, and shows you a single, clear screen with the full picture. [cite: 5] 

[cite_start]It connects to tools like **Trivy** (checks your containers), **Semgrep** (scans your code), **Poutine** (audits your GitLab pipelines), **Zizmor** (secures your GitHub Actions), and **Gitleaks** (finds secrets). [cite: 6] [cite_start]Instead of digging through multiple JSON files, you get a **beautiful, dark‑mode dashboard** that tells you what’s critical, how risks are trending, and even how an attacker might chain several small issues into a big problem. [cite: 7] 

[cite_start]Think of it as a **security camera system for your entire CI/CD pipeline** — it watches everything, alerts you, and even suggests fixes, all without needing internet access if you want. [cite: 8]

---

## 💥 Why You Need It

[cite_start]In 2026, **supply chain attacks** have become the #1 threat. [cite: 9] [cite_start]Tools like Trivy themselves were compromised, and attackers now inject malicious code directly into build pipelines. [cite: 10] [cite_start]**You can no longer just scan your code; you must scan your pipeline.** [cite: 11]

Pipeline Sentinel gives you:
* [cite_start]**One screen for all scanners** – stop juggling log files. [cite: 11]
* [cite_start]**AI that understands attack chains** – “A leaked secret + an old library = a disaster.” [cite: 12]
* [cite_start]**Automatic fixes** – with a single flag, it patches files and opens a pull request. [cite: 13]
* [cite_start]**Human review mode** – inspect each fix before applying. [cite: 14]
* [cite_start]**Compliance reports** – generate a PDF for your boss or auditor. [cite: 15]
* [cite_start]**100% offline capable** – works in air‑gapped environments where security matters most. [cite: 16]
* [cite_start]**Interactive wizard** – one command to get everything running. [cite: 17]

---

## 📍 Where to Run It in Your Network

[cite_start]Pipeline Sentinel is designed to be **flexible** — you decide where it fits best: [cite: 18]

| Deployment | Description |
| :--- | :--- |
| 🖥️ **Local Developer Machine** | [cite_start]Run the CLI and dashboard right on your laptop. [cite: 19] [cite_start]Perfect for individual pentesters or developers who want instant feedback. [cite: 20] |
| 🔧 **CI/CD Runner** | [cite_start]Use the GitHub Action or call `devsecops-radar` directly in your Jenkins/GitLab CI scripts. [cite: 21] [cite_start]It can fail the build if critical vulnerabilities exceed your policy (`--policy`). [cite: 22] |
| 🏢 **Central Security Server** | [cite_start]Install on a dedicated server (via Docker or pip) that collects scan results from multiple teams. [cite: 23] [cite_start]The dashboard becomes a shared security operations console. [cite: 24] |
| 🌐 **Air‑Gapped Networks** | [cite_start]Copy the Docker image and sample data to an offline server. [cite: 25] [cite_start]The dashboard works with zero external calls — all assets are embedded. [cite: 26] |

### [cite_start]Typical Network Flow [cite: 27]

```text
[Trivy scan] ──┐
[Semgrep scan] ─┤
[Poutine scan] ─┼──> devsecops-radar (CLI) ──> findings.json ──> Dashboard (Flask) ──> Browser
[Zizmor scan] ─┘
[Gitleaks scan] ┘
```
[cite_start][cite: 27]

> [cite_start]**📌 Diagram Placeholder:** Add your network flow diagram here as `docs/network_flow.png`. [cite: 27]
> [cite_start]`![Network Flow Diagram](docs/network_flow.png)` [cite: 28]

---

## 📸 Dashboard Preview

[cite_start]![Pipeline Sentinel Dashboard](docs/Demo.gif) [cite: 28]

[cite_start]*Severity doughnut, trend line chart, attack‑path graph (clickable nodes), topology view, executive summary — all fully offline.* [cite: 28]

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
[cite_start][cite: 28]
[cite_start]Open http://localhost:8080 — your unified dashboard is live with sample findings. [cite: 28]

🧙 **Want a fully guided setup? [cite_start]Run the wizard:** [cite: 29]
```bash
devsecops-radar --wizard
```
[cite_start][cite: 29]

---

## 📋 Prerequisites

[cite_start]Pipeline Sentinel relies on external security tools to produce the JSON reports it consumes. [cite: 29] [cite_start]You must install these tools separately according to your needs. [cite: 30]

[cite_start]**Required for offline scanning:** [cite: 31]
* [cite_start]Trivy (installation) [cite: 31]
* Semgrep (installation) [cite: 31]
* [cite_start]Poutine (installation) [cite: 31]
* [cite_start]Zizmor (installation) [cite: 31]
* Gitleaks (installation) [cite: 31]

**Optional (for AI analysis):** [cite: 31]
* [cite_start]Ollama (installation) [cite: 31]

> [cite_start]📖 **See `PREREQUISITES.md` for more details.** [cite: 31]

---

## [cite_start]📦 Installation [cite: 32]

### [cite_start]Option 1 — PyPI (Recommended) [cite: 32]
```bash
pip install devsecops-radar
```
[cite_start][cite: 32]

### [cite_start]Option 2 — From Source [cite: 32]
```bash
git clone [https://github.com/Mehrdoost/devsecops-radar.git](https://github.com/Mehrdoost/devsecops-radar.git)
cd devsecops-radar
pip install -e .
```
[cite_start][cite: 32]

### [cite_start]Option 3 — Docker [cite: 33]
```bash
docker pull ghcr.io/mehrdoost/devsecops-radar:latest
docker run -p 8080:8080 ghcr.io/mehrdoost/devsecops-radar:latest
```
[cite_start][cite: 33]

[cite_start]**Mount your own findings file:** [cite: 33]
```bash
docker run -p 8080:8080 -v $(pwd)/findings.json:/data/findings.json ghcr.io/mehrdoost/devsecops-radar:latest
```
[cite_start][cite: 33]

[cite_start]**Or use Docker Compose:** [cite: 33]
```bash
docker compose up
```
[cite_start][cite: 33]

### [cite_start]🧙 One‑Command Install (curl) [cite: 33]
```bash
curl -fsSL [https://raw.githubusercontent.com/Mehrdoost/devsecops-radar/main/install.sh](https://raw.githubusercontent.com/Mehrdoost/devsecops-radar/main/install.sh) | bash
```
[cite_start][cite: 33, 34]
[cite_start]*This script installs Python dependencies, Ollama, pulls the AI model, and starts the wizard.* [cite: 34]

---

## [cite_start]🧭 How to Use (Step‑by‑Step) [cite: 35]

### [cite_start]1. Run Your Security Scanners [cite: 35]
[cite_start]Generate JSON output from your tools: [cite: 35]

```bash
trivy image --format json -o trivy.json nginx:latest
semgrep --config=auto --json --output semgrep.json .
poutine scan ./repo --format json --output poutine.json
zizmor scan ./repo --output zizmor.json --format json
gitleaks detect --source . --report-format json --report-path gitleaks.json
```
[cite_start][cite: 35, 36, 37]

### [cite_start]2. Merge Findings with the CLI [cite: 37]
```bash
devsecops-radar --trivy trivy.json --semgrep semgrep.json --poutine poutine.json --zizmor zizmor.json --gitleaks gitleaks.json
```
[cite_start][cite: 37]
[cite_start]*This produces a single `findings.json` with all findings merged and normalised.* [cite: 37]

### [cite_start]3. View the Dashboard [cite: 38]
```bash
devsecops-radar-web
```
[cite_start][cite: 38]
[cite_start]The dashboard shows: [cite: 38]
* [cite_start]**Severity Breakdown** – Doughnut chart [cite: 38]
* **Trend Over Time** – Line chart from scan history [cite: 38]
* [cite_start]**Pipeline Security** – Poutine + Zizmor statistics card [cite: 38]
* [cite_start]**Attack Path Graph** – Interactive D3.js graph (click nodes for details) [cite: 38]
* **Executive Summary** – Risk score and AI‑generated summary [cite: 38]
* [cite_start]**Findings Table** – Searchable, filterable, paginated [cite: 38]

### [cite_start]4. Enable AI Analysis (Optional) [cite: 38]
```bash
ollama pull llama3.2:latest
devsecops-radar --trivy trivy.json --analyze
devsecops-radar-web
```
[cite_start][cite: 38]
[cite_start]The LLM generates `findings_ai_summary.json` containing: [cite: 38]
* [cite_start]`executive_summary`, `risk_score` [cite: 38]
* `attack_paths` with MITRE ATT&CK tactics [cite: 38]
* [cite_start]`top_remediations` (some with `fix_diff`) [cite: 38]
* [cite_start]`false_positives_likely` [cite: 38]

### [cite_start]5. Auto‑Remediation (with Human Review) [cite: 38]
```bash
# Apply fixes automatically
devsecops-radar --trivy trivy.json --analyze --fix

# Review each fix before applying
devsecops-radar --trivy trivy.json --analyze --fix --review
```
[cite_start][cite: 38]
[cite_start]*The tool creates a new git branch `auto-fix` and pushes it for review.* [cite: 38, 39]

### [cite_start]6. Policy Enforcement [cite: 39]
[cite_start]Create a `policy.json` file: [cite: 39]
```json
{"max_critical": 5, "on_violation": "fail"}
```
[cite_start][cite: 39]
```bash
devsecops-radar --trivy trivy.json --policy policy.json
```
[cite_start][cite: 39]
[cite_start]*If critical findings exceed 5, the command exits with code 1 — perfect for CI/CD gates.* [cite: 39]

### [cite_start]7. Generate Compliance Reports [cite: 40]
```bash
devsecops-radar --trivy trivy.json --analyze --compliance CIS --report cis-report.pdf
```
[cite_start][cite: 40]
[cite_start]A PDF report is created with an executive summary, risk score, findings table, and compliance mapping. [cite: 40] [cite_start]Sensitive data can be redacted automatically. [cite: 41]

### [cite_start]8. Security Badge for Your Project [cite: 41]
[cite_start]After running a scan, you can embed a dynamic security badge in your `README`: [cite: 41]

```markdown
[![Security Status](https://your-server/badge/1.svg)](https://github.com/Mehrdoost/devsecops-radar)
```
[cite_start][cite: 41]
[cite_start]The badge color changes based on the number of critical findings (green/yellow/red). [cite: 41]

---

## [cite_start]📋 Complete Command Reference [cite: 42]

### [cite_start]`devsecops-radar` — CLI Flags [cite: 42]

| Flag | Description | Example |
| :--- | :--- | :--- |
| `--trivy` | [cite_start]Trivy JSON file or image name [cite: 42] | [cite_start]`--trivy results.json` or `--trivy nginx:latest` [cite: 42] |
| `--semgrep` | [cite_start]Semgrep JSON file or directory [cite: 42] | [cite_start]`--semgrep results.json` or `--semgrep ./src` [cite: 42] |
| `--poutine` | [cite_start]Poutine JSON file or repo path [cite: 42] | [cite_start]`--poutine results.json` or `--poutine ./repo` [cite: 42] |
| `--zizmor` | [cite_start]Zizmor JSON file or repo path [cite: 42] | [cite_start]`--zizmor results.json` or `--zizmor ./repo` [cite: 42] |
| `--gitleaks` | [cite_start]Gitleaks JSON file or repo path [cite: 42] | [cite_start]`--gitleaks results.json` or `--gitleaks ./repo` [cite: 42] |
| `--rules` | [cite_start]Directory with custom JSON rule files [cite: 42] | [cite_start]`--rules ~/my-security-rules/` [cite: 42] |
| `--policy` | [cite_start]Policy JSON file for gating [cite: 42] | [cite_start]`--policy policy.json` [cite: 42] |
| `--analyze` | [cite_start]Enable LLM analysis (Ollama required) [cite: 42] | [cite_start]`--analyze` [cite: 42] |
| `--llm-backend` | [cite_start]`ollama` (default) or `litellm` [cite: 42] | [cite_start]`--llm-backend litellm` [cite: 42] |
| `--llm-model` | [cite_start]Model name [cite: 42] | [cite_start]`--llm-model gpt-4o-mini` [cite: 42] |
| `--fix` | [cite_start]Auto‑apply AI‑suggested fixes [cite: 42] | [cite_start]`--fix` [cite: 42] |
| `--review` | [cite_start]Review each AI fix before applying [cite: 42] | [cite_start]`--review` [cite: 42] |
| `--topology` | [cite_start]Path to topology JSON file [cite: 42] | [cite_start]`--topology topology.json` [cite: 42] |
| `--compliance` | [cite_start]Framework: `CIS`, `PCI-DSS`, `ISO27001` [cite: 42] | [cite_start]`--compliance CIS` [cite: 42] |
| `--report` | [cite_start]Generate PDF report (output filename) [cite: 42] | [cite_start]`--report security_report.pdf` [cite: 42] |
| `--output` | [cite_start]Output JSON file (default: findings.json) [cite: 42] | [cite_start]`--output merged.json` [cite: 42] |
| `--wizard` | [cite_start]Interactive first‑time setup wizard [cite: 42, 43] | [cite_start]`--wizard` [cite: 43] |

### [cite_start]`devsecops-radar-web` — Web Server [cite: 43]

```bash
devsecops-radar-web                       # Launch on http://localhost:8080
FINDINGS_FILE=my.json devsecops-radar-web # Use a custom findings file
PIPELINE_API_KEY=secret devsecops-radar-web  # Enable API authentication
```
[cite_start][cite: 43]

---

## [cite_start]✨ Core Capabilities [cite: 43]

### [cite_start]🔌 Multi‑Scanner Plugin Architecture [cite: 43]
[cite_start]Built‑in support for five scanners with a real plugin system. [cite: 43] [cite_start]Third‑party scanners can be installed as separate packages and discovered automatically via Python entry points. [cite: 44] [cite_start]An adapter pattern validates all findings with Pydantic. [cite: 45]

| Scanner | What It Scans | Flag |
| :--- | :--- | :--- |
| **Trivy** | [cite_start]Container images & dependencies [cite: 45] | [cite_start]`--trivy` [cite: 45] |
| **Semgrep** | [cite_start]Static Code Analysis (SAST) [cite: 45] | [cite_start]`--semgrep` [cite: 45] |
| **Poutine** | [cite_start]GitLab CI/CD configuration security [cite: 45] | [cite_start]`--poutine` [cite: 45] |
| **Zizmor** | [cite_start]GitHub Actions workflow security [cite: 45] | [cite_start]`--zizmor` [cite: 45] |
| **Gitleaks**| [cite_start]Secrets detection [cite: 45] | [cite_start]`--gitleaks` [cite: 45] |

### [cite_start]🧩 Hybrid RuleFusion Engine [cite: 45]
* **Offline** – Load custom JSON rules from any local directory (`--rules ~/my-rules/`) [cite: 45]
* [cite_start]**Online** – Pull community‑curated rules from a configurable Git repository (`--update-rules`) [cite: 45]
* [cite_start]Auto‑detects Trivy, Semgrep, Poutine, Zizmor, and plain‑list formats [cite: 45]
* Policy evaluation built directly into the engine [cite: 45]
* [cite_start]Community rules repo: `devsecops-radar-rules` (configurable via `COMMUNITY_RULES_REPO`) [cite: 45]

### [cite_start]🧠 LLM‑Powered Analysis [cite: 45]
* Retry logic with exponential backoff for unstable endpoints [cite: 45]
* [cite_start]Few‑shot examples covering real‑world supply chain attack chains [cite: 45]
* [cite_start]Token‑aware selection (max items configurable via `ANALYZER_MAX_FINDINGS`) [cite: 45]
* Structured JSON output: `executive_summary`, `risk_score`, `attack_paths` (MITRE ATT&CK), `top_remediations`, `false_positives_likely` [cite: 45]
* [cite_start]Ollama (local, offline) and LiteLLM (OpenAI, Anthropic, etc.) support [cite: 45, 46]

### [cite_start]🕸️ Multi‑Step Attack Path Visualization [cite: 46]
[cite_start]Interactive D3.js force graph that chains findings into realistic attack scenarios. [cite: 46] Click any node to see detailed finding information. [cite_start]Accepts a topology file to map findings onto your actual infrastructure, showing lateral movement across servers and subnets. [cite: 47]

### [cite_start]🛡️ Policy‑as‑Code [cite: 48]
[cite_start]Define security gates as simple JSON: [cite: 48]
```json
{"max_critical": 5, "on_violation": "fail"}
```
[cite_start][cite: 48]
[cite_start]*If critical findings exceed the threshold, the CLI exits with code 1 — perfect for failing CI/CD pipelines.* [cite: 48]

### [cite_start]🛠️ Auto‑Remediation with Human‑in‑the‑Loop [cite: 49]
[cite_start]AI‑suggested fixes can be applied automatically (`--fix`) or reviewed one‑by‑one (`--review`). [cite: 49] [cite_start]The tool creates a new git branch and pushes it for review. [cite: 50] [cite_start]A `fix.sh` script is also generated for manual commands. [cite: 51]

### [cite_start]📊 Compliance & Executive Reports (with Redaction) [cite: 51]
[cite_start]Generate professional PDF reports (`--report report.pdf`) with: [cite: 51]
* [cite_start]Executive summary and risk score [cite: 51]
* Findings table (first 50 items) [cite: 51]
* [cite_start]Compliance mapping (CIS, PCI‑DSS, ISO 27001) [cite: 51]
* [cite_start]Automatic redaction of passwords, tokens, JWTs [cite: 51]

### [cite_start]📈 Scan History & Trends (with Pagination) [cite: 51]
[cite_start]SQLAlchemy‑backed database with server‑side pagination (`/api/findings?page=1&per_page=50`). [cite: 51] [cite_start]Scan history is stored efficiently, enabling fast trend charts and historical comparisons. [cite: 52]

### [cite_start]🧪 SBOM & Dependency Confusion Detection [cite: 53]
* [cite_start]Generate a CycloneDX SBOM from your project using `syft` [cite: 53]
* Detect dependency confusion risks in `package.json` and `requirements.txt` — internal packages that could be impersonated by public registries [cite: 53]

### 🔍 RAG‑Powered Security Search [cite: 53]
Ask natural language questions about your scan history: *“When was the last Log4j vulnerability found?”* [cite: 53] The built‑in RAG endpoint (`/api/rag?q=...`) searches stored findings and returns matches. [cite: 54]

### ⚔️ Attack Simulation (Sandbox) [cite: 55]
Generate a simple proof‑of‑concept script for any finding and execute it inside a disposable Docker container to demonstrate the risk without harming your system. [cite: 55]

### 📉 Dynamic Risk Scoring [cite: 56]
Beyond CVSS, each finding gets a dynamic risk score based on asset exposure (from topology) and exploit availability — helping teams prioritise what to fix first. [cite: 56]

### 🧙 Interactive Wizard [cite: 57]
A `--wizard` flag walks new users through installing dependencies, pulling AI models, and running their first scan — all in one go. [cite: 57]

### 🔒 Privacy & Offline‑First [cite: 58]
* [cite_start]All assets (CSS, JS) are embedded — zero CDN calls [cite: 58]
* [cite_start]LLM analysis runs locally with Ollama; no data leaves your network [cite: 58, 59]
* Optional API key authentication for the dashboard (JWT supported) [cite: 59]
* [cite_start]Docker image runs as non‑root user [cite: 59]

---

## [cite_start]🌍 Community Rules & Online Updates [cite: 59]

[cite_start]Pipeline Sentinel features a community‑driven rule marketplace housed in a separate repository: `devsecops-radar-rules`. [cite: 59]

### [cite_start]How It Works [cite: 60]
[cite_start]The repository contains curated JSON rule files for all supported scanners (Trivy, Semgrep, Poutine, Zizmor, Gitleaks) and generic compliance checks. [cite: 60] [cite_start]Anyone can contribute by submitting a Pull Request with new or improved rules. [cite: 61] [cite_start]Users can pull the latest rules with a single command: [cite: 62]

```bash
devsecops-radar --update-rules
```
[cite_start][cite: 62]
[cite_start]Rules are stored locally in `~/.devsecops-radar/community-rules/`. [cite: 62] [cite_start]To use them alongside your scanner results: [cite: 63]

```bash
devsecops-radar --trivy scan.json --rules ~/.devsecops-radar/community-rules/
```
[cite_start][cite: 63]
[cite_start]You can even point to your own fork or a private repository by setting the `COMMUNITY_RULES_REPO` environment variable. [cite: 63] [cite_start]This turns Pipeline Sentinel into a living, community‑improved security platform — just like Nuclei Templates or Semgrep Registry. [cite: 64]

### [cite_start]Contributing a Rule [cite: 65]
1.  [cite_start]Fork the `devsecops-radar-rules` repository. [cite: 65]
2.  [cite_start]Add a new JSON file to the `rules/` directory (or modify an existing one). [cite: 65] [cite_start]Follow the standard Pipeline Sentinel finding format (see the repo’s README). [cite: 66]
3.  [cite_start]Open a Pull Request — our maintainers will review and merge. [cite: 67]

---

## [cite_start]🏗️ Architecture [cite: 68]

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
[cite_start][cite: 68, 69]

> [cite_start]**📌 Diagram Placeholder:**  [cite: 69]
![Architecture Diagram](docs/architecture.png)` [cite: 70]

---

## [cite_start]🗺️ Roadmap [cite: 70]

| Phase | Feature | Status |
| :--- | :--- | :--- |
| ✅ Phase 1 | [cite_start]Multi‑scanner engine (Trivy, Semgrep, Poutine, Zizmor) [cite: 70] | [cite_start]Done [cite: 70] |
| ✅ Phase 1 | [cite_start]LLM analysis (Ollama + LiteLLM) [cite: 70] | [cite_start]Done [cite: 70] |
| ✅ Phase 1 | [cite_start]Scan history, trend chart, scan diff [cite: 70] | [cite_start]Done [cite: 70] |
| ✅ Phase 1 | [cite_start]GitHub Action (composite) [cite: 70] | [cite_start]Done [cite: 70] |
| ✅ Phase 1 | [cite_start]Docker image (multi‑stage, non‑root) [cite: 70] | [cite_start]Done [cite: 70] |
| ✅ Phase 2 | [cite_start]Attack‑path visualization with MITRE ATT&CK & topology [cite: 70] | [cite_start]Done [cite: 70] |
| ✅ Phase 2 | [cite_start]Policy‑as‑Code engine (`--policy`) [cite: 70] | [cite_start]Done [cite: 70] |
| ✅ Phase 2 | [cite_start]Auto‑remediation engine (`--fix`) [cite: 70] | [cite_start]Done [cite: 70] |
| ✅ Phase 2 | [cite_start]Compliance reports (PDF) with redaction [cite: 70] | [cite_start]Done [cite: 70] |
| ✅ Phase 2 | [cite_start]Hybrid RuleFusion engine (local + community rules) [cite: 70] | [cite_start]Done [cite: 70] |
| ✅ Phase 3 | [cite_start]Web dashboard Blueprint refactor (modular Flask) [cite: 70] | [cite_start]Done [cite: 70] |
| ✅ Phase 3 | [cite_start]Real scanner plugin system with entry points [cite: 70] | [cite_start]Done [cite: 70] |
| ✅ Phase 3 | [cite_start]SQLAlchemy ORM with pagination [cite: 70] | [cite_start]Done [cite: 70] |
| ✅ Phase 3 | [cite_start]SBOM & Dependency Confusion Detection [cite: 70] | [cite_start]Done [cite: 70] |
| ✅ Phase 3 | [cite_start]RAG‑powered security search [cite: 70] | [cite_start]Done [cite: 70] |
| ✅ Phase 3 | [cite_start]Attack Simulation (sandbox) [cite: 70] | [cite_start]Done [cite: 70] |
| ✅ Phase 3 | [cite_start]Dynamic Risk Scoring [cite: 70] | [cite_start]Done [cite: 70] |
| ✅ Phase 3 | [cite_start]Interactive wizard (`--wizard`) [cite: 70, 71] | [cite_start]Done [cite: 71] |
| ✅ Phase 3 | [cite_start]Human review mode (`--review`) [cite: 71] | [cite_start]Done [cite: 71] |
| ✅ Phase 3 | [cite_start]Gitleaks secret scanner [cite: 71] | [cite_start]Done [cite: 71] |
| ✅ Phase 3 | [cite_start]Security badge endpoint [cite: 71] | [cite_start]Done [cite: 71] |
| ✅ Phase 3 | [cite_start]Full test suite & CI pipeline [cite: 71] | [cite_start]Done [cite: 71] |
| 🔲 Phase 4 | [cite_start]Jira / Slack integration [cite: 71] | [cite_start]Planned [cite: 71] |
| 🔲 Phase 4 | [cite_start]SARIF & CycloneDX support [cite: 71] | [cite_start]Planned [cite: 71] |
| 🔲 Phase 4 | [cite_start]Pull Request assistant (GitHub App) [cite: 71] | [cite_start]Planned [cite: 71] |

---

## [cite_start]🧪 Testing & CI [cite: 71]

[cite_start]Pipeline Sentinel is thoroughly tested to ensure reliability for production use. [cite: 71] 
* [cite_start]**Unit & Integration Tests:** 23 tests covering scanners, rule engine, database, analyzer, API, and CLI. [cite: 72]
* **CI Pipeline:** Every push and pull request triggers automated testing (pytest) and linting (ruff) via GitHub Actions. [cite: 73]

You can run the tests locally: [cite: 74]
```bash
pip install -e .
pip install pytest pytest-flask ruff
pytest tests/ -v
ruff check .
```
[cite_start][cite: 74]

---

## 🤝 Contributing [cite: 75]

We welcome contributions of all kinds! Please read our `CONTRIBUTING.md` for detailed guidelines on how to set up the project, add new scanners, or submit rule changes. [cite: 75] For contributing community rules, see the Community Rules section above. [cite: 76]

---

## 👨‍💻 Authors [cite: 77]

**ReverseForge** — ( Mehrdoost And Mi0r4 )   [cite: 77]

[cite_start][![GitHub](https://img.shields.io/badge/GitHub-Mehrdoost-181717?logo=github)](https://github.com/ReverseForge) [cite: 79]
[cite_start][![GitHub](https://img.shields.io/badge/GitHub-Mehrdoost-181717?logo=github)](https://github.com/Mehrdoost) [cite: 79]
[cite_start][![GitHub](https://img.shields.io/badge/GitHub-Mehrdoost-181717?logo=github)](https://github.com/miora-sora) [cite: 79]


---

## 📜 License [cite: 79]

[cite_start]MIT — see [LICENSE](LICENSE). [cite: 79]

<div align="center">
⭐ If this project helps your team ship safer software, drop a star — it makes a real difference. [cite: 79]
</div>