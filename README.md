<div align="center">

# 🛡️ Pipeline Sentinel

### *The Open‑Source DevSecOps Command Center — Unify, Analyse, Remediate.*

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

![Pipeline Sentinel Dashboard](docs/demo.gif)

</div>

---

<details>
<summary><b>📑 Table of Contents (Click to expand)</b></summary>

1. [What Is Pipeline Sentinel? (Simple Explanation)](#-what-is-pipeline-sentinel-simple-explanation)
2. [Why You Need It](#-why-you-need-it)
3. [Where to Run It in Your Network](#-where-to-run-it-in-your-network)
4. [Network Flow & Topology](#-network-flow--topology)
5. [Dashboard Preview](#-dashboard-preview)
6. [Quick Start](#-quick-start)
7. [Prerequisites](#-prerequisites)
8. [Installation](#-installation)
9. [How to Use (Step‑by‑Step)](#-how-to-use-stepbystep)
10. [Complete Command Reference](#-complete-command-reference)
11. [Core Capabilities](#-core-capabilities)
12. [Community Rules & Online Updates](#-community-rules--online-updates)
13. [Attack Simulation & What‑If Analysis](#-attack-simulation--what‑if-analysis)
14. [Security Improvements in v0.4.4](#-security-improvements-in-v044)
15. [Architecture](#-architecture)
16. [Roadmap](#-roadmap)
17. [Testing & CI](#-testing--ci)
18. [Security Policy](#-security-policy)
19. [Contributing](#-contributing)
20. [Code of Conduct](#-code-of-conduct)
21. [Support Development](#-support-development)
22. [Author](#-author)
23. [License](#-license)

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
* 🎯 **Unified Aggregation:** One screen for all scanners – stop juggling log files.
* 🧠 **Graph AI Insights:** AI that understands attack chains – *"A leaked secret + an old library = a disaster."*
* ⚡ **Auto-Remediation:** Automatically patches files and opens a pull request (with automated backups) with a single flag.
* 👥 **Human Review Mode:** Step-by-step interactive interface to inspect each fix before applying it to production.
* 📊 **Compliance-Ready Reports:** Instantly generate beautiful, executive-ready PDF summaries for auditors or stakeholders.
* ⚔️ **Attack Simulation:** Select security findings and automatically generate operational proof-of-concept scripts.
* 🔒 **Air-Gapped Privacy:** 100% offline capable. Perfect for highly restricted environments where data residency is paramount.
* 🧙 **Interactive Wizard:** A single command leads you through the entire initialization and onboarding process.
* 🛒 **Rules Marketplace:** Dynamically fetch and update curated detection definitions directly from the community.

---

## 📍 Where to Run It in Your Network

Pipeline Sentinel is designed to adapt to your setup. You decide where it fits best:

| Deployment Mode | Operational Profile & Context |
| :--- | :--- |
| 🖥️ **Local Dev Machine** | Run the CLI and dashboard right on your laptop. Perfect for individual pentesters or developers who want instant, localized feedback. |
| 🔧 **CI/CD Runner Pipeline** | Integrate directly into Jenkins/GitLab CI or GitHub Actions. Fail builds automatically if critical vulnerabilities exceed your security policy rules. |
| 🏢 **Central Security Operations** | Deploy via Docker on a central server to collect scan history across multiple teams, unifying visibility into a shared security console. |
| 🌐 **Air‑Gapped Environments** | Air-gap friendly. Deploy the standalone Docker bundle to isolated networks with zero external asset dependencies or tracker requests. |

---

## 🔍 Network Flow & Topology

### 🔄 Logical Data Lifecycle
The functional flow below maps exactly how raw multi-scanner inputs route through our parsing engine to be normalized and centralized:

```mermaid
graph LR
    subgraph Scanners [Multi-Scanner Core Inputs]
        T[Trivy Scan] 
        S[Semgrep Scan] 
        P[Poutine Scan] 
        Z[Zizmor Scan] 
        G[Gitleaks Scan]
    end

    Scanners --->|Raw Reports| CLI(🛡️ devsecops-radar CLI Engine)
    CLI --->|Normalize & Deduplicate| Out[findings.json]
    Out ---> Web(📊 Flask Dashboard App)
    Web ---> UI[🌐 Modern Browser Command Center]

    style CLI fill:#1e1e2e,stroke:#3b82f6,stroke-width:2px,color:#cdd6f4
    style Web fill:#1e1e2e,stroke:#10b981,stroke-width:2px,color:#cdd6f4
    style Out fill:#181825,stroke:#fab387,stroke-width:1px,color:#a6e3a1
    style UI fill:#11111b,stroke:#a6e3a1,stroke-width:2px,color:#cdd6f4
```

### 🌐 Operational Infrastructure Mapping
Once processed, the centralized findings are rendered inside your topology mapping network boundaries, visualising the operational relationship between distinct pipeline segments:

![Network Flow Diagram](docs/architecture-1.png)

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
git clone https://github.com/Mehrdoost/devsecops-radar.git
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
curl -fsSL https://raw.githubusercontent.com/Mehrdoost/devsecops-radar/main/install.sh | bash
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
<summary><b>3. View the Dashboard Engine</b></summary>
<br>

Execute the web wrapper to spin up your centralized analytics engine:
```bash
devsecops-radar-web
```

### 📊 Tactical Web Console Architecture
The single-page real-time dashboard elegantly partitions telemetry into high-impact actionable items:

| Dashboard Component | Interface Visualization Type | Core Operational Value |
| :--- | :--- | :--- |
| **Severity Breakdown** | Dynamic Doughnut Charts | Instant tracking of global exposure density and total counts. |
| **Trend Over Time** | Aggregated Line Timelines | Historical trajectory graphs drawn from persistent scan logs. |
| **Pipeline Security** | Specialized Poutine + Zizmor Matrix | Micro-telemetry analyzing supply chain health and meta-workflows. |
| **Attack Path Graph** | Interactive D3.js Force Nodes | Clickable chain mapping demonstrating structural flaw correlations. |
| **Executive Summary** | Context-Rich Summary & Risk Scoring | Algorithmic threat intelligence translated into executive-ready metrics. |
| **Findings Datagrid** | Searchable Paginated Checkbox Tables | Granular configuration control built for isolating entities for target simulations. |

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

![AI Analysis](docs/AI_CLI.PNG)

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
> All modified files are backed up to `~/.devsecops-radar/backups/`. The tool creates a new git branch `auto-fix` and pushes it for review.
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
export JIRA_URL="https://your-domain.atlassian.net"
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
| `--output` | Output JSON file (default: findings.json)| `--output` <kbd>merged.json</kbd> |
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
> **`devsecops-radar-web` — Web Server Options**

```bash
devsecops-radar-web                         # Launch on http://localhost:8080
FINDINGS_FILE=my.json devsecops-radar-web   # Use a custom findings file
PIPELINE_API_KEY=secret devsecops-radar-web # Enable API authentication
```
![Login](docs/Login_env.png)

</details>

---

## ✨ Core Capabilities

### 🔌 Multi-Scanner Ingestion Engine
* **Pluggable Architecture:** Native modular decoders ingest structured data seamlessly from Trivy, Semgrep, Poutine, Zizmor, and Gitleaks.
* **Hybrid RuleFusion Layer:** Dynamically evaluation of custom local JSON policies mapped on top of live community-driven git feeds.
* **Scan History Optimization:** Persistent historical compilation powered by SQLAlchemy featuring sub-second result slicing.

### 🧠 Advanced Intelligence & Active Remediation
* **Asynchronous Context Enriched LLM:** Multi-backend integration hooks (Ollama/LiteLLM) mapping structural CVE configurations to real-world MITRE ATT&CK vectors.
* **Interactive Remediation Tracks:** Intelligent mutation options applying autonomous hotfixes (`--fix`) balanced by modular human verification checklines (`--review`).
* **Exploit-Aware Scoring:** Modern analytical calculations analyzing vector severities alongside real-time asset exposure and dynamic surface reachability.

### 🛡️ Enterprise Policy & Supply-Chain Governance
* **Policy-as-Code Frameworks:** Advanced control assertions parsing validation rules via strict local JSON constraints or distributed Open Policy Agent (OPA) Rego scripts.
* **Supply Chain Verification:** Comprehensive CycloneDX SBOM data compilation complete with proactive VEX vulnerability masking layers.
* **Air-Gapped Absolute Confidentiality:** Complete dependency localization guaranteeing data processing loops execute with zero external request callbacks.

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
> You can even point to your own private repository via `COMMUNITY_RULES_REPO`!

---

## ⚔️ Attack Simulation & What‑If Analysis

**Interactive attack simulation directly from the dashboard:**
1. Tick the checkboxes next to the findings you want to investigate.
2. Click **“⚡ Simulate Selected”**.
3. A modal displays a generated attack script (`bash`), attack chain description, and (if Docker is available) the sandbox output.

*(You can also click any node in the Attack Path Graph and press **“Simulate this attack”**)*.

![Attack Simulation](docs/Simulation.PNG)

---

## 🔐 Security Hardening & Production Readiness in v0.4.4

This release is a comprehensive security and stability overhaul. All known
vulnerabilities in the web interface, API, and scanner logic have been fixed.
The project now meets enterprise‑grade security expectations, especially in
air‑gapped environments.

### 🔐 Security Fixes (Critical & High Severity)
- XSS (Stored) – Dashboard table rows and detail views no longer inject raw
  finding data into the DOM; all values are properly escaped.
- Path Traversal – Data files (findings.json, AI summaries, topology) are
  validated to stay within the working directory. Arbitrary file read via
  environment variables is blocked.
- Authentication Bypass – Endpoints /api/attack-paths, /api/summary,
  /api/topology, and /api/scan-result now correctly enforce API‑key
  authentication.
- API Key Exposure – The dashboard no longer renders the real API key in the
  page source.
- Command Injection in Attack Simulation – Script generation now allows only
  a safe subset of characters; multi‑line and special characters are stripped.
- Secret Leakage in Reports – Gitleaks findings no longer contain the actual
  secret in the description; PDF/HTML reports redact common token patterns (GitHub,
  GitLab, AWS, JWT) across all fields.

### 🧱 Architecture & Performance
- Rate Limiting – Login and all API‑key protected endpoints are rate‑limited
  (in‑memory, thread‑safe).
- Session Management – The database scoped session is no longer manually
  closed, preventing “instance not bound” errors in multi‑step requests.
- Database Schema – execution_time now stored as Float (seconds); redundant
  findings_json column removed; index added on scans.timestamp.
- AI Analyzer – Concurrent chunk processing capped at 5; Ollama endpoint
  restricted to localhost to guarantee air‑gap compliance.
- Policy Engine – New on_violation field (warn / fail) allows flexible
  policy enforcement.

### 🛡 Scanner Improvements
- All scanners (trivy, semgrep, zizmor, poutine, gitleaks) now call
  _validate_target_path before parsing any file, blocking path‑traversal at
  the adapter layer.
- Trivy now supports image digests (repo@sha256:...).
- Semgrep and Gitleaks properly treat non‑zero exit codes that indicate findings.

### 🎨 Developer & Operations
- semgrep moved to optional dependencies (pip install devsecops-radar[extra]).
- Ruff enabled with security rules (S); line length set to 120.
- Jira project key and issue type configurable via JIRA_PROJECT_KEY and
  JIRA_ISSUE_TYPE.
- CORS origins controlled by CORS_ORIGINS environment variable (no longer *).
- All Python files formatted to comply with the new standard.

### ⬆️ Upgrade Instructions
1. Pull the latest image or update the package: pip install --upgrade devsecops-radar
2. Review your .env file – ensure JWT_SECRET and PIPELINE_API_KEY are strong
   (≥ 32 characters).
3. If using Jira, set JIRA_PROJECT_KEY and JIRA_ISSUE_TYPE.
4. Restart the web server.

---

## 🏗️ Architecture

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

![Architecture Diagram](docs/architecture-2.png)

---

## 🗺️ Roadmap

| Phase | Feature | Status |
| :--- | :--- | :--- |
| ✅ **Phase 1** | Multi‑scanner engine (Trivy, Semgrep, Poutine, Zizmor), LLM analysis, GH Actions | Done |
| ✅ **Phase 2** | Attack‑path visualization, Policy‑as‑Code, Auto‑remediation, Compliance reports | Done |
| ✅ **Phase 3** | Web dashboard Blueprint, ORM pagination, SBOM, Dynamic Risk Scoring, Gitleaks | Done |
| ✅ **Phase 4** | Advanced attack simulation, VEX filtering, Async LLM, SARIF/CycloneDX | Done |
| 🔲 **Phase 5** | eBPF runtime security agent | Planned |
| 🔲 **Phase 5** | Rule marketplace with YAML | Planned |
| 🔲 **Phase 5** | Pull Request assistant (GitHub App) | Planned |

> [!NOTE]
> See the [open issues](https://github.com/Mehrdoost/devsecops-radar/issues) for a full list of proposed features.

---

## 🧪 Testing & CI

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

---

## 🤝 Community & Support

* **Security Policy:** We take security seriously. If you discover a vulnerability, please report it privately. See our full Security Policy for details.
* **Contributing:** We welcome contributions of all kinds! Please read our Contributing Guide. For adding new rules, see the Community Rules section.
* **Code of Conduct:** This project adheres to the Contributor Covenant Code of Conduct. By participating, you are expected to uphold this code.

---

## ⚡ Support Development

Sponsor this project with a crypto donation.  
All funds go directly to the developer.

**[🔗 Donate USDC (Polygon)](https://polygonscan.com/address/0x6b7c1c572D45575Fa5409CB52F25B750B3097c8b)** <sub>`0x1234...5678`</sub> · <sub><img src="docs/donate-qr.png" width="90" alt="QR" valign="middle" /></sub>

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