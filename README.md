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

---

## 📖 Table of Contents
1. [What Is Pipeline Sentinel?](#-what-is-pipeline-sentinel)
2. [Roadmap](#️-roadmap)
3. [Quick Start](#-quick-start)
4. [Installation](#-installation)
5. [How to Use](#-how-to-use)
6. [Complete Command Reference](#-complete-command-reference)
7. [Core Capabilities](#-core-capabilities)
8. [Architecture](#️-architecture)
9. [Security](#-security)
10. [GitHub Action](#-github-action)
11. [Contributing](#-contributing)
12. [Author](#-author)
13. [License](#-license)

---

## 📸 What Is Pipeline Sentinel?

**Pipeline Sentinel** is a security observability platform built for **CI/CD pipelines**. It takes the fragmented JSON output from popular open‑source scanners — **Trivy** (containers), **Semgrep** (SAST), **Poutine** (GitLab CI), and **Zizmor** (GitHub Actions) — and merges them into a **single, beautiful, offline‑ready dashboard**.

> Think of it as **Nuclei for CI/CD security**: define your own rules, feed it JSON, and let it map your attack surface.

### 🎯 Who Is This For?

| Persona | How Pipeline Sentinel Helps |
| :--- | :--- |
| **DevSecOps Engineers** | One dashboard instead of four. Merge scanner reports and see the full picture instantly. |
| **Penetration Testers** | Feed custom tool JSON, generate AI‑powered attack graphs with MITRE ATT&CK. |
| **Security Teams (air‑gapped)** | Works 100% offline. No CDN, no external API calls. |
| **Compliance Officers** | Generate PDF reports aligned to CIS, PCI‑DSS, or ISO 27001. |
| **CI/CD Pipeline Owners** | Integrate via GitHub Action to get a security summary on every PR. |

### 📊 Dashboard Preview

![Dashboard Demo](docs/Demo.gif)

---

## 🗺️ Roadmap

Pipeline Sentinel evolves rapidly. Here is the public roadmap:

| Phase | Feature | Status |
| :--- | :--- | :--- |
| ✅ **Phase 1** | Multi‑scanner plugin engine (Trivy, Semgrep, Poutine, Zizmor) | Done |
| ✅ **Phase 1** | LLM‑powered analysis (Ollama + LiteLLM) | Done |
| ✅ **Phase 1** | Scan history, trend chart, scan diff | Done |
| ✅ **Phase 1** | GitHub Action (composite) | Done |
| ✅ **Phase 1** | Docker image (multi‑stage, non‑root) | Done |
| ✅ **Phase 2** | Attack‑path visualisation with MITRE ATT&CK & topology | Done |
| ✅ **Phase 2** | Policy‑as‑Code engine (`--policy`) | Done |
| ✅ **Phase 2** | Auto‑remediation engine (`--fix`) | Done |
| ✅ **Phase 2** | Compliance reports (PDF) | Done |
| ✅ **Phase 2** | Hybrid RuleFusion engine (local + community rules) | Done |
| ✅ **Phase 3** | Web dashboard Blueprint refactor (modular Flask) | Done |
| ✅ **Phase 3** | Real scanner plugin system with entry points | Done |
| ✅ **Phase 3** | SQLAlchemy ORM for scan history | Done |
| ✅ **Phase 3** | SBOM health reports | Done |
| ✅ **Phase 3** | Pipeline Sentry (live webhook agent) | Done |
| 🔲 **Phase 4** | Jira / Slack integration | Planned |
| 🔲 **Phase 4** | SARIF & CycloneDX support | Planned |
| 🔲 **Phase 4** | Rule Marketplace (community YAML rules) | Planned |

> See the [open issues](https://github.com/Mehrdoost/devsecops-radar/issues) for a full list of proposed features.

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

---

## 🧭 How to Use

### Step 1 — Run Your Security Scanners
Generate JSON output from your tools:

```bash
trivy image --format json -o trivy.json nginx:latest
semgrep --config=auto --json --output semgrep.json .
poutine scan ./repo --format json --output poutine.json
zizmor scan ./repo --output zizmor.json --format json
```

### Step 2 — Merge Findings with the CLI
```bash
devsecops-radar --trivy trivy.json --semgrep semgrep.json --poutine poutine.json --zizmor zizmor.json
```
This produces a single `findings.json` file with all findings merged and normalised.

### Step 3 — View the Dashboard
```bash
devsecops-radar-web
```
The dashboard shows:
*   **Severity Breakdown** — Doughnut chart of CRITICAL, HIGH, MEDIUM, LOW counts
*   **Trend Over Time** — Line chart showing how severity counts evolve across scans
*   **Pipeline Security** — Dedicated Poutine + Zizmor statistics card
*   **Attack Path Graph** — Interactive D3.js force graph (when AI analysis is enabled)
*   **Executive Summary** — Risk score and AI‑generated summary
*   **Findings Table** — Searchable, filterable table of all findings

### Step 4 — Enable AI Analysis (Optional)
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

### Step 5 — Auto‑Remediation
```bash
devsecops-radar --trivy trivy.json --analyze --fix
```
The tool will apply AI‑suggested fixes, create a new git branch `auto-fix`, and push it for review.

### Step 6 — Policy Enforcement
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
If critical findings exceed 5, the command exits with code 1 — suitable for CI/CD gates.

### Step 7 — Generate Compliance Reports
```bash
devsecops-radar --trivy trivy.json --analyze --compliance CIS --report cis-report.pdf
```
A PDF report is created with an executive summary, risk score, findings table, and compliance mapping.

---

## 📋 Complete Command Reference

### `devsecops-radar` — CLI Flags

| Flag | Description | Example |
| :--- | :--- | :--- |
| `--trivy` | Trivy JSON file or image name | `--trivy results.json` or `--trivy nginx:latest` |
| `--semgrep` | Semgrep JSON file or directory | `--semgrep results.json` or `--semgrep ./src` |
| `--poutine` | Poutine JSON file or repo path | `--poutine results.json` or `--poutine ./repo` |
| `--zizmor` | Zizmor JSON file or repo path | `--zizmor results.json` or `--zizmor ./repo` |
| `--rules` | Directory with custom JSON rule files | `--rules ~/my-security-rules/` |
| `--policy` | Policy JSON file for gating | `--policy policy.json` |
| `--analyze` | Enable LLM analysis (Ollama required) | `--analyze` |
| `--llm-backend` | `ollama` (default) or `litellm` | `--llm-backend litellm` |
| `--llm-model` | Model name | `--llm-model gpt-4o-mini` |
| `--fix` | Auto‑apply AI‑suggested fixes | `--fix` |
| `--topology` | Path to topology JSON file | `--topology topology.json` |
| `--compliance` | Framework: `CIS`, `PCI-DSS`, `ISO27001` | `--compliance CIS` |
| `--report` | Generate PDF report (output filename) | `--report security_report.pdf` |
| `--output` | Output JSON file (default: findings.json) | `--output merged.json` |

### `devsecops-radar-web` — Web Server

```bash
devsecops-radar-web                          # Launch on http://localhost:8080
FINDINGS_FILE=my.json devsecops-radar-web    # Use a custom findings file
PIPELINE_API_KEY=secret devsecops-radar-web  # Enable API authentication
```

### Usage Examples

```bash
# Merge multiple scanner outputs
devsecops-radar --trivy trivy_scan.json --semgrep semgrep_scan.json

# Scan directly (if tools are installed)
devsecops-radar --trivy nginx:latest --semgrep ./src --poutine ./repo

# Merge built‑in scanners with custom rules
devsecops-radar --trivy trivy_scan.json --rules ~/my-security-rules/

# Enable AI analysis (Ollama must be running)
ollama pull llama3.2:latest
devsecops-radar --trivy trivy_scan.json --semgrep semgrep_scan.json --analyze

# Use OpenAI via LiteLLM
export OPENAI_API_KEY=sk-...
devsecops-radar --trivy trivy_scan.json --analyze --llm-backend litellm --llm-model gpt-4o-mini

# Build scan history and view trends
devsecops-radar --trivy sample_trivy.json --semgrep sample_semgrep.json
devsecops-radar --trivy sample_trivy.json --poutine sample_poutine.json
devsecops-radar-web    # Trend chart now shows multiple data points
```

---

## ✨ Core Capabilities

### 🔌 Multi‑Scanner Plugin Architecture
Built‑in support for four scanners with a real plugin system based on `ScannerPlugin` abstract class. Third‑party scanners can be installed as separate packages and discovered automatically via Python entry points.

| Scanner | What It Scans | Flag |
| :--- | :--- | :--- |
| **Trivy** | Container images & dependencies | `--trivy` |
| **Semgrep** | Static Code Analysis (SAST) | `--semgrep` |
| **Poutine** | GitLab CI/CD configuration security | `--poutine` |
| **Zizmor** | GitHub Actions workflow security | `--zizmor` |

### 🧩 Hybrid RuleFusion Engine
*   **Offline** — Load custom JSON rules from any local directory (`--rules ~/my-rules/`)
*   **Online** — Pull community‑curated rules with `--update-rules`
*   Auto‑detects Trivy, Semgrep, Poutine, Zizmor, and plain‑list formats
*   Policy evaluation built directly into the engine

### 🧠 LLM‑Powered Analysis
*   Ollama (local, offline) and LiteLLM (OpenAI, Anthropic, etc.) support
*   Engineered few‑shot prompts with structured JSON output
*   Token‑aware finding selection for large datasets
*   Produces executive summaries, risk scores, attack paths with MITRE ATT&CK mapping, and remediation guidance

### 🕸️ Attack Path Visualization
Interactive D3.js force graph showing how separate vulnerabilities can be chained into an attack scenario. Accepts a topology file to map findings onto your actual infrastructure.

### 🛡️ Policy‑as‑Code
Define security gates as JSON:
```json
{
  "max_critical": 5, 
  "on_violation": "fail"
}
```

### 🛠️ Auto‑Remediation
AI‑suggested fixes are applied automatically. The tool creates a new git branch and pushes it for review.

### 📊 Compliance Reports
Generate PDF reports with executive summary, risk score, findings table, and mapping to CIS, PCI‑DSS, or ISO 27001 controls.

### 📈 Scan History & Trends
SQLite‑backed (with SQLAlchemy ORM) history with trend line chart and scan diff API.

---

## 🏗️ Architecture

```text
devsecops_radar/
├── cli/            # CLI entry point — plugin discovery, policy, remediation
├── core/           # RuleFusion engine, DB (SQLAlchemy), LLM analysers
├── scanners/       # Pluggable scanner classes (extend ScannerPlugin)
├── plugins/        # ScannerPlugin abstract base class
└── web/            # Flask dashboard (modular Blueprints)
    ├── dashboard/  # Main dashboard routes & embedded HTML
    ├── attack_paths/
    ├── topology/
    ├── summary/
    └── sentry/     # Live webhook agent for CI/CD
```

---

## 🔒 Security

*   **Input validation** — All scanner targets are sanitised against command injection.
*   **Offline‑first** — No data leaves your network.
*   **LLM privacy** — Ollama runs locally; optional LiteLLM for cloud models.
*   **API authentication** — Optional API key for dashboard access.
*   **Non‑root Docker** — Container runs as unprivileged user.
*   **Policy‑as‑Code** — Enforce gates before deployment.

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