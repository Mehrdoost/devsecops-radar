<div align="center">

# 🛡️ Pipeline Sentinel

**The Open‑Source DevSecOps Command Center — Unify, Analyse, Remediate.**

[![PyPI version](https://img.shields.io/pypi/v/devsecops-radar?style=for-the-badge&color=2196F3)](https://pypi.org/project/devsecops-radar/)
[![License](https://img.shields.io/github/license/Mehrdoost/devsecops-radar?style=for-the-badge&color=4CAF50)](LICENSE)
[![GitHub release](https://img.shields.io/github/v/release/Mehrdoost/devsecops-radar?include_prereleases&style=for-the-badge&color=FF9800)](https://github.com/Mehrdoost/devsecops-radar/releases)
[![CI](https://img.shields.io/github/actions/workflow/status/Mehrdoost/devsecops-radar/ci.yml?branch=main&style=for-the-badge&color=9C27B0)](https://github.com/Mehrdoost/devsecops-radar/actions)
[![codecov](https://codecov.io/gh/Mehrdoost/devsecops-radar/branch/main/graph/badge.svg?token=TOKEN&style=for-the-badge)](https://codecov.io/gh/Mehrdoost/devsecops-radar)
[![Stars](https://img.shields.io/github/stars/Mehrdoost/devsecops-radar?style=for-the-badge&color=FFEB3B)](https://github.com/Mehrdoost/devsecops-radar/stargazers)

<br>

> 📖 **Read this in:** [Русский](README_ru.md) | [中文](README_zh.md) | [العربية](README_ar.md)

<br>

*Severity doughnut, trend line chart, attack‑path graph (clickable nodes), topology view, executive summary, and attack simulation panel — all fully offline.*

![Pipeline Sentinel Dashboard](docs/Demo.gif)

</div>

---

<details>
<summary><b>📑 Table of Contents (Click to expand)</b></summary>

1. [What Is Pipeline Sentinel? (Simple Explanation)](#-what-is-pipeline-sentinel-simple-explanation)
2. [Why You Need It](#-why-you-need-it)
3. [Where to Run It in Your Network](#-where-to-run-it-in-your-network)
4. [Dashboard Preview](#-dashboard-preview)
5. [Quick Start](#-quick-start)
6. [Prerequisites](#-prerequisites)
7. [Installation](#-installation)
8. [How to Use (Step‑by‑Step)](#-how-to-use-stepbystep)
9. [Complete Command Reference](#-complete-command-reference)
10. [Core Capabilities](#-core-capabilities)
11. [Community Rules & Online Updates](#-community-rules--online-updates)
12. [Attack Simulation & What‑If Analysis](#-attack-simulation--what‑if-analysis)
13. [Security Hardening (v0.4.1)](#-security-hardening-v060)
14. [Architecture](#-architecture)
15. [Roadmap](#-roadmap)
16. [Testing & CI](#-testing--ci)
17. [Security Policy](#-security-policy)
18. [Contributing](#-contributing)
19. [Code of Conduct](#-code-of-conduct)
20. [Author](#-author)
21. [License](#-license)

</details>

---

## 👨‍👩‍👧 What Is Pipeline Sentinel? (Simple Explanation)

> **Imagine you have several security guards**, each watching a different door of a building. They all shout their findings in different languages, and you have to run around to understand what’s going on.

**Pipeline Sentinel** puts them all in one room, translates their reports, and shows you a single, clear screen with the full picture. It connects to tools like **Trivy** (checks your containers), **Semgrep** (scans your code), **Poutine** (audits your GitLab pipelines), **Zizmor** (secures your GitHub Actions), and **Gitleaks** (finds secrets). 

Instead of digging through multiple JSON files, you get a **beautiful, dark‑mode command‑center dashboard** that tells you what’s critical, how risks are trending, and even how an attacker might chain several small issues into a big problem.

*Think of it as a **security camera system for your entire CI/CD pipeline** — it watches everything, alerts you, suggests fixes, and even lets you simulate attack chains, all without needing internet access if you want.*

---

## 💥 Why You Need It

In 2026, **supply chain attacks** have become the #1 threat. Tools like Trivy themselves were compromised, and attackers now inject malicious code directly into build pipelines. **You can no longer just scan your code; you must scan your pipeline.**

**Pipeline Sentinel gives you:**
- ✅ **One screen for all scanners** – stop juggling log files.
- ✅ **AI that understands attack chains** – “A leaked secret + an old library = a disaster.”
- ✅ **Automatic fixes** – with a single flag, it patches files and opens a pull request (with backup).
- ✅ **Human review mode** – inspect each fix before applying.
- ✅ **Compliance reports** – generate a PDF for your boss or auditor.
- ✅ **Attack simulation** – tick a few findings and see a generated attack script.
- ✅ **100% offline capable** – works in air‑gapped environments where security matters most.
- ✅ **Interactive wizard** – one command to get everything running.
- ✅ **Community rules marketplace** – pull curated detection rules from the community.

---

## 📍 Where to Run It in Your Network

Pipeline Sentinel is designed to be **flexible** — you decide where it fits best:

| Deployment | Description |
| :--- | :--- |
| 🖥️ **Local Developer Machine** | Run the CLI and dashboard right on your laptop. Perfect for individual pentesters or developers who want instant feedback. |
| 🔧 **CI/CD Runner** | Use the GitHub Action or call `devsecops-radar` directly in your Jenkins/GitLab CI scripts. It can fail the build if critical vulnerabilities exceed your policy (`--policy`). |
| 🏢 **Central Security Server** | Install on a dedicated server (via Docker or pip) that collects scan results from multiple teams. The dashboard becomes a shared security operations console. |
| 🌐 **Air‑Gapped Networks** | Copy the Docker image and sample data to an offline server. The dashboard works with zero external calls — all assets are embedded. |

<details>
<summary><b>🔍 View Typical Network Flow</b></summary>
<br>

```text
[Trivy scan] ──┐
[Semgrep scan] ─┤
[Poutine scan] ─┼──> devsecops-radar (CLI) ──> findings.json ──> Dashboard (Flask) ──> Browser
[Zizmor scan] ─┘
[Gitleaks scan] ┘
```
> **📌 Diagram Placeholder:** > ![Network Flow Diagram](docs/architecture-1.png)

</details>

---

## 📸 Dashboard Preview

*(See the animated demo at the top of this README for a live preview of the UI in action!)*

---

## 🚀 Quick Start

Get up and running in 3 simple steps:

```bash
# 1. Install from PyPI
pip install devsecops-radar

# 2. Feed scanner data (sample data is included in the repo)
devsecops-radar --trivy sample_trivy.json --semgrep sample_semgrep.json

# 3. Launch the dashboard
devsecops-radar-web
```
Open **http://localhost:8080** — your unified command center is live with sample findings.

> [!TIP]
> 🧙 **Want a fully guided setup?** Run the interactive wizard:
> ```bash
> devsecops-radar --wizard
> ```

---

## 📦 Installation

<details>
<summary><b>View All Installation Options (PyPI, Docker, Source, One-Command)</b></summary>
<br>

### Option 1 — PyPI (Recommended)
```bash
pip install devsecops-radar
```

### Option 2 — From Source
```bash
git clone [https://github.com/Mehrdoost/devsecops-radar.git](https://github.com/Mehrdoost/devsecops-radar.git)
cd devsecops-radar
pip install -e ".[dev]"
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

</details>

---

## 📋 Prerequisites

> [!IMPORTANT]
> Pipeline Sentinel relies on external security tools to produce the JSON reports it consumes. You must install these tools separately according to your needs.

- **Required for offline scanning:** Trivy, Semgrep, Poutine, Zizmor, Gitleaks.
- **Optional:** Ollama (AI analysis), Docker (Sandboxing), OPA (Rego policy).

> 📖 **See `PREREQUISITES.md` for full installation details of these tools.**

---

## 🧭 How to Use (Step‑by‑Step)

<details open>
<summary><b>1. Run Your Security Scanners</b></summary>
<br>

Generate JSON output from your tools:
```bash
trivy image --format json -o trivy.json nginx:latest
semgrep --config=auto --json --output semgrep.json .
poutine scan ./repo --format json --output poutine.json
zizmor scan ./repo --output zizmor.json --format json
gitleaks detect --source . --report-format json --report-path gitleaks.json
```
</details>

<details open>
<summary><b>2. Merge Findings with the CLI</b></summary>
<br>

```bash
devsecops-radar --trivy trivy.json --semgrep semgrep.json --poutine poutine.json --zizmor zizmor.json --gitleaks gitleaks.json
```
*This produces a single `findings.json` with all findings merged and normalised.*
</details>

<details open>
<summary><b>3. View the Dashboard</b></summary>
<br>

```bash
devsecops-radar-web
```
**The dashboard shows:**
* **Severity Breakdown** – Doughnut chart with total count
* **Trend Over Time** – Line chart from scan history
* **Pipeline Security** – Poutine + Zizmor statistics card
* **Attack Path Graph** – Interactive D3.js graph (click nodes for details)
* **Executive Summary** – Risk score and AI‑generated summary
* **Findings Table** – Searchable, filterable, paginated, with checkboxes for simulation
</details>

<details>
<summary><b>4. Enable AI Analysis (Optional)</b></summary>
<br>

```bash
ollama pull llama3.2:latest
devsecops-radar --trivy trivy.json --analyze
devsecops-radar-web
```
The LLM generates `findings_ai_summary.json` containing: `executive_summary`, `risk_score`, `attack_paths` (with MITRE ATT&CK), `top_remediations`, and `false_positives_likely`.
</details>

<details>
<summary><b>5. Auto‑Remediation (with Human Review)</b></summary>
<br>

```bash
# Apply fixes automatically
devsecops-radar --trivy trivy.json --analyze --fix

# Interactive step‑by‑step review
devsecops-radar --trivy trivy.json --analyze --fix --review
```
> [!NOTE]
> *All modified files are backed up to `~/.devsecops-radar/backups/`. The tool creates a new git branch `auto-fix` and pushes it for review.*
</details>

<details>
<summary><b>6. Policy Enforcement</b></summary>
<br>

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
*If critical findings exceed 5, the command exits with code 1. You can also use OPA Rego policies (`--rego-policy`).*
</details>

<details>
<summary><b>7. Generate Compliance & Standard Reports</b></summary>
<br>

```bash
# PDF report with compliance mapping
devsecops-radar --trivy trivy.json --analyze --compliance CIS --report cis-report.pdf

# Export as SARIF for GitHub Code Scanning
devsecops-radar --trivy trivy.json --export-sarif report.sarif

# Export as CycloneDX SBOM
devsecops-radar --trivy trivy.json --export-cyclonedx report.cdx.json
```
</details>

<details>
<summary><b>8. Security Badge for Your Project</b></summary>
<br>

Embed a dynamic security badge in your README:
```markdown
[![Security Status](https://your-server/badge/1.svg)](https://github.com/Mehrdoost/devsecops-radar)
```
</details>

<details>
<summary><b>9. Jira / Asana Integration (New!)</b></summary>
<br>

Set environment variables to create issues automatically:
```bash
export JIRA_URL="[https://your-domain.atlassian.net](https://your-domain.atlassian.net)"
export JIRA_TOKEN="your-api-token"
devsecops-radar --trivy trivy.json --analyze --notify-jira

export ASANA_TOKEN="your-asana-token"
export ASANA_WORKSPACE="your-workspace-gid"
devsecops-radar --trivy trivy.json --analyze --notify-asana
```
</details>

---

## 📋 Complete Command Reference

<details open>
<summary><b>Click to Expand Command Categories</b></summary>
<br>

### 🔎 Scanners & Inputs
| Flag | Description | Example |
| :--- | :--- | :--- |
| `--trivy` | Trivy JSON file or image name | `--trivy` <kbd>results.json</kbd> or <kbd>nginx:latest</kbd> |
| `--semgrep` | Semgrep JSON file or directory | `--semgrep` <kbd>results.json</kbd> or <kbd>./src</kbd> |
| `--poutine` | Poutine JSON file or repo path | `--poutine` <kbd>results.json</kbd> or <kbd>./repo</kbd> |
| `--zizmor` | Zizmor JSON file or repo path | `--zizmor` <kbd>results.json</kbd> or <kbd>./repo</kbd> |
| `--gitleaks`| Gitleaks JSON file or repo path | `--gitleaks` <kbd>results.json</kbd> or <kbd>./repo</kbd> |
| `--rules` | Directory with custom JSON rules | `--rules` <kbd>~/my-rules/</kbd> |
| `--topology`| Path to topology JSON file | `--topology` <kbd>topology.json</kbd> |

### 🧠 AI, Policies & Remediation
| Flag | Description | Example |
| :--- | :--- | :--- |
| `--analyze` | Enable async LLM analysis (Ollama required) | `--analyze` |
| `--llm-backend`| `ollama` (default) or `litellm` | `--llm-backend` <kbd>litellm</kbd> |
| `--llm-model` | Model name | `--llm-model` <kbd>gpt-4o-mini</kbd> |
| `--fix` | Auto‑apply AI‑suggested fixes (with backup) | `--fix` |
| `--review` | Interactive step‑by‑step remediation | `--review` |
| `--policy` | Policy JSON file for gating | `--policy` <kbd>policy.json</kbd> |
| `--rego-policy`| OPA Rego policy file | `--rego-policy` <kbd>policy.rego</kbd> |

### 📊 Reports & Exports
| Flag | Description | Example |
| :--- | :--- | :--- |
| `--output` | Output JSON file (default: findings.json) | `--output` <kbd>merged.json</kbd> |
| `--report` | Generate PDF/JSON/HTML report | `--report` <kbd>report.pdf</kbd> |
| `--export-sarif`| Export findings as SARIF | `--export-sarif` <kbd>report.sarif</kbd> |
| `--export-cyclonedx`| Export findings as CycloneDX | `--export-cyclonedx` <kbd>report.cdx</kbd> |
| `--compliance`| Framework: `CIS`, `PCI-DSS`, `ISO27001` | `--compliance` <kbd>CIS</kbd> |

### ⚙️ Integrations & Setup
| Flag | Description | Example |
| :--- | :--- | :--- |
| `--notify-jira` | Create Jira issues for criticals | `--notify-jira` |
| `--notify-asana`| Create Asana tasks for criticals | `--notify-asana` |
| `--wizard` | Interactive first‑time setup wizard | `--wizard` |
| `--update-rules`| Download/update community rules | `--update-rules` |

<br>

> [!TIP]
> ### `devsecops-radar-web` — Web Server Options
> ```bash
> devsecops-radar-web                       # Launch on http://localhost:8080
> FINDINGS_FILE=my.json devsecops-radar-web # Use a custom findings file
> PIPELINE_API_KEY=secret devsecops-radar-web  # Enable API authentication
> ```

</details>

---

## ✨ Core Capabilities

<details open>
<summary><b>Explore the Engine Powering Pipeline Sentinel</b></summary>
<br>

* **🔌 Multi‑Scanner Plugin Architecture:** Built‑in support for Trivy (`--trivy`), Semgrep (`--semgrep`), Poutine (`--poutine`), Zizmor (`--zizmor`), and Gitleaks (`--gitleaks`).
* **🧩 Hybrid RuleFusion Engine:** Load custom JSON rules locally or pull community‑curated rules from a configurable Git repository (`--update-rules`).
* **🧠 LLM‑Powered Analysis:** Async, enriched context (NIST NVD/GitHub links), structured JSON with MITRE ATT&CK, risk scores, and step‑by‑step remediation. Supports Ollama and LiteLLM.
* **🕸️ Multi‑Step Attack Path Visualization:** Interactive D3.js force graph that chains findings into realistic attack scenarios based on your network topology.
* **🛡️ Policy‑as‑Code (JSON & Rego):** Define simple security gates or write complex rules in Rego for OPA to fail pipelines safely.
* **🛠️ Auto‑Remediation:** AI‑suggested fixes applied automatically (`--fix`) or reviewed (`--review`). Every file is backed up safely in a new Git branch.
* **📊 Compliance & Reports:** Professional reports in PDF, JSON, HTML (`--report`), plus SARIF and CycloneDX exports.
* **📈 Scan History & Trends:** SQLAlchemy‑backed database with fast pagination and historical trend comparisons.
* **🧪 SBOM & Dependency Confusion:** Generate CycloneDX SBOMs, apply VEX files, and detect impersonation risks.
* **🔍 RAG‑Powered Security Search:** Ask natural language questions about your scan history.
* **📉 Dynamic Risk Scoring:** Context-aware scoring based on asset exposure, exploit availability, and threat intelligence.
* **🔒 Privacy & Offline‑First:** 100% embedded assets. LLM analysis runs locally via Ollama. No data leaves your network.

</details>

---

## 🌍 Community Rules & Online Updates

Pipeline Sentinel features a community‑driven rule marketplace housed in a separate repository: `devsecops-radar-rules`.

**How It Works:**
The repository contains curated JSON rule files for all supported scanners. You can pull the latest rules with a single command:
```bash
devsecops-radar --update-rules
```
Rules are stored locally in `~/.devsecops-radar/community-rules/`. To use them alongside your scanner results:
```bash
devsecops-radar --trivy scan.json --rules ~/.devsecops-radar/community-rules/
```
> [!NOTE]
> *(You can even point to your own private repository via `COMMUNITY_RULES_REPO`!)*

---

## ⚔️ Attack Simulation & What‑If Analysis

**Interactive attack simulation directly from the dashboard:**
1. Tick the checkboxes next to the findings you want to investigate.
2. Click **“⚡ Simulate Selected”**.
3. A modal displays a generated attack script (`bash`), attack chain description, and (if Docker is available) the sandbox output.

*(You can also click any node in the Attack Path Graph and press **“Simulate this attack”**)*.

---

<details>
<summary><b>🔐 Security Hardening (v0.4.1)</b></summary>
<br>

Pipeline Sentinel now includes several important security improvements:
* **Command injection prevention** – all scanner inputs and community repo URLs are strictly validated.
* **Password hashing** – API keys are stored using Werkzeug’s secure hashing (no plaintext).
* **Safe git staging** – only the files that were actually modified are committed, preventing accidental exposure of `.env` or other secrets.
* **Consistent DB session management** – all database operations use the same context manager, preventing resource leaks.
* **Specific exception handling** – bare `except` clauses have been replaced with targeted exceptions, improving debuggability.
* **Removal of duplicated parsing code** – the deprecated `parser.py` module has been deleted.
</details>

<details>
<summary><b>🏗️ Architecture</b></summary>
<br>

```text
devsecops_radar/
├── cli/            # CLI entry point – plugin discovery, policy, remediation
├── core/           # RuleFusion engine, DB (SQLAlchemy), async LLM analysers
├── scanners/       # Pluggable scanner classes (extend ScannerPlugin)
├── plugins/        # ScannerPlugin abstract base class & entry points
└── web/            # Flask dashboard (modular Blueprints, WCAG 2.1 AA)
    ├── dashboard/  # Main dashboard routes & embedded HTML
    ├── attack_paths/
    ├── topology/
    ├── summary/
    └── sentry/     # Live webhook agent for CI/CD
```
> **📌 Diagram Placeholder:**
> ![Network Flow Diagram](docs/architecture-2.png)
</details>

<details>
<summary><b>🗺️ Roadmap</b></summary>
<br>

| Phase | Feature | Status |
| :--- | :--- | :--- |
| ✅ **Phase 1** | Multi‑scanner engine (Trivy, Semgrep, Poutine, Zizmor), LLM analysis, GH Actions | Done |
| ✅ **Phase 2** | Attack‑path visualization, Policy‑as‑Code, Auto‑remediation, Compliance reports | Done |
| ✅ **Phase 3** | Web dashboard Blueprint, ORM pagination, SBOM, Dynamic Risk Scoring, Gitleaks | Done |
| ✅ **Phase 4** | Advanced attack simulation, VEX filtering, Async LLM, SARIF/CycloneDX | Done |
| 🔲 **Phase 5** | eBPF runtime security agent | Planned |
| 🔲 **Phase 5** | Rule marketplace with YAML | Planned |
| 🔲 **Phase 5** | Pull Request assistant (GitHub App) | Planned |

> See the [open issues](https://github.com/Mehrdoost/devsecops-radar/issues) for a full list of proposed features.
</details>

<details>
<summary><b>🧪 Testing & CI</b></summary>
<br>

Pipeline Sentinel is thoroughly tested to ensure reliability for production use.
* **Unit & Integration Tests:** 23+ tests covering scanners, rule engine, database, analyzer, API, and CLI.
* **CI Pipeline:** Every push and pull request triggers automated testing (`pytest` with coverage) and linting (`ruff`, `mypy`) via GitHub Actions.

Run tests locally:
```bash
pip install -e ".[dev]"
pip install pytest pytest-flask ruff
pytest tests/ -v --cov=devsecops_radar --cov-report=term-missing
ruff check .
mypy .
```
</details>

---

## 🤝 Community & Support

<details>
<summary><b>Contributing, Security Policy, & Code of Conduct</b></summary>
<br>

* **Security Policy:** We take security seriously. If you discover a vulnerability, please report it privately. See our full Security Policy for details.
* **Contributing:** We welcome contributions of all kinds! Please read our Contributing Guide. For adding new rules, see the Community Rules section.
* **Code of Conduct:** This project adheres to the Contributor Covenant Code of Conduct. By participating, you are expected to uphold this code.
</details>

---

## 👨‍💻 Author

**ReverseForge** — ( Mehrdoost And Mi0r4 )  

[![GitHub](https://img.shields.io/badge/GitHub-ReverseForge-181717?style=for-the-badge&logo=github)](https://github.com/ReverseForge) 
[![GitHub](https://img.shields.io/badge/GitHub-Mehrdoost-181717?style=for-the-badge&logo=github)](https://github.com/Mehrdoost) 
[![GitHub](https://img.shields.io/badge/GitHub-miora--sora-181717?style=for-the-badge&logo=github)](https://github.com/miora-sora) 

---

## 📜 License

MIT — see [LICENSE](LICENSE).

<div align="center">
<br>

⭐ **If this project helps your team ship safer software, drop a star — it makes a real difference.**

</div>