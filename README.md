# 🛡️ Pipeline Sentinel

**The open‑source DevSecOps command centre.** Aggregate, correlate, and visualise security findings from **Trivy, Semgrep, Poutine, and Zizmor** in a single, offline‑ready dashboard. Optionally power it with an **LLM‑backed analysis engine**, track your security posture over time, and visualise attack paths — all from one CLI + Web UI. No cloud required.

[![GitHub stars](https://img.shields.io/github/stars/Mehrdoost/devsecops-radar?style=social)](https://github.com/Mehrdoost/devsecops-radar/stargazers)
[![License](https://img.shields.io/github/license/Mehrdoost/devsecops-radar)](LICENSE)
[![PyPI version](https://img.shields.io/pypi/v/devsecops-radar.svg)](https://pypi.org/project/devsecops-radar/)
[![GitHub release](https://img.shields.io/github/v/release/Mehrdoost/devsecops-radar?include_prereleases)](https://github.com/Mehrdoost/devsecops-radar/releases)
[![CI](https://github.com/Mehrdoost/devsecops-radar/actions/workflows/test-action.yml/badge.svg)](https://github.com/Mehrdoost/devsecops-radar/actions/workflows/test-action.yml)

> 📖 **Read this in:** [Русский](README_ru.md) | [中文](README_zh.md)

---

## 📸 Dashboard Preview

![Pipeline Sentinel Dashboard](docs/Demo.gif)
*(Severity doughnut, trend line chart, search & filter, and AI‑generated attack‑path graph — all fully offline.)*

---

## 📖 What Is Pipeline Sentinel?

Pipeline Sentinel is a **security observability platform for CI/CD pipelines**. It takes the fragmented JSON output from popular open‑source scanners — Trivy (containers & dependencies), Semgrep (static code analysis), Poutine (GitLab CI security), and Zizmor (GitHub Actions security) — and merges them into a single, beautiful, dark‑mode dashboard that you can access from any browser.

The project was born from a real‑world frustration: **a production release was delayed for hours** while the team manually correlated findings from four separate scanners, each producing a different JSON structure. Pipeline Sentinel eliminates that pain by acting as a universal translation layer that understands all major scanner formats out of the box, and can be extended to support any custom tool in minutes.

### 🎯 Who Is This For?

| Persona | How Pipeline Sentinel Helps |
| :--- | :--- |
| **DevSecOps Engineers** | One dashboard instead of four. Merge Trivy, Semgrep, Poutine, and Zizmor reports and see the full picture instantly. |
| **Penetration Testers & Red Teams** | Feed your custom tool JSON, correlate findings, and generate AI‑powered attack‑path graphs for your reports. |
| **Security Teams in Air‑Gapped Environments** | Works 100% offline — no CDN, no external API calls, no cloud dependency. All assets are embedded. |
| **CI/CD Pipeline Owners** | Add the GitHub Action to your workflow and get a security summary on every PR. |
| **Open‑Source Maintainers** | Use the hybrid RuleFusion engine to build community‑curated security rule packs. |

### 🔐 The Real‑World Context (Why Now?)

In **March 2026**, the DevSecOps community was shaken when the widely‑used Trivy vulnerability scanner itself fell victim to a supply chain attack (CVE‑2026‑33634). Threat actors used compromised credentials to publish malicious Trivy releases and inject credential‑stealing malware into GitHub Actions tags. This was followed in April 2026 by the **Mini Shai‑Hulud** campaign — a cross‑ecosystem attack that compromised Python, Node.js, and PHP packages through stolen CI/CD tokens — and the **TeamPCP** attacks that poisoned Checkmarx KICS across Docker Hub, VS Code, and GitHub Actions simultaneously.

The lesson is clear: **scanning your code is no longer enough. You must also scan your pipeline itself.** That is exactly what Pipeline Sentinel does. It unifies container scanning (Trivy), static code analysis (Semgrep), GitLab CI security (Poutine), and GitHub Actions security (Zizmor) under one roof — and lets you add any other scanner you trust.

---

## 🚀 Quick Start (3 Commands)

```bash
# 1. Install
pip install devsecops-radar

# 2. Feed scanner data (sample data is included)
devsecops-radar --trivy sample_trivy.json --semgrep sample_semgrep.json

# 3. Launch the dashboard
devsecops-radar-web
```

Open http://localhost:8080 in your browser. The dashboard loads instantly with sample findings.

---

## 📦 Installation Options

### Option 1 – Install from PyPI (Recommended)
```bash
pip install devsecops-radar
```

### Option 2 – Install from Source
```bash
git clone [https://github.com/Mehrdoost/devsecops-radar.git](https://github.com/Mehrdoost/devsecops-radar.git)
cd devsecops-radar
pip install -e .
```

### Option 3 – Run with Docker
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

## 📋 Complete Command Reference

Pipeline Sentinel has two entry points: `devsecops-radar` (CLI — merges findings) and `devsecops-radar-web` (launches the dashboard).

### `devsecops-radar` — CLI Flags

| Flag | Type | Description | Example |
| :--- | :--- | :--- | :--- |
| `--trivy` | PATH or IMAGE | Trivy JSON file, or an image name to scan directly | `--trivy results.json` or `--trivy nginx:latest` |
| `--semgrep` | PATH or DIRECTORY | Semgrep JSON file, or a directory to scan directly | `--semgrep results.json` or `--semgrep ./src` |
| `--poutine` | PATH or REPO | Poutine JSON file, or a repository path to scan | `--poutine results.json` or `--poutine ./repo` |
| `--zizmor` | PATH or REPO | Zizmor JSON file, or a repository path to scan | `--zizmor results.json` or `--zizmor ./repo` |
| `--rules` | PATH | Directory containing custom JSON rule files | `--rules ~/my-security-rules/` |
| `--analyze` | FLAG | Enable LLM analysis (requires Ollama) | `--analyze` |
| `--llm-backend` | STRING | LLM backend: `ollama` (default) or `litellm` | `--llm-backend litellm` |
| `--llm-model` | STRING | Model name (overrides default) | `--llm-model gpt-4o-mini` |
| `--output` | PATH | Output file for merged findings (default: findings.json) | `--output my_results.json` |

### `devsecops-radar-web` — Web Server

```bash
devsecops-radar-web                       # Launch on http://localhost:8080
FINDINGS_FILE=my_results.json devsecops-radar-web   # Use a custom findings file
```

### Basic Usage Examples

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

# Build scan history (multiple runs) and view trends
devsecops-radar --trivy sample_trivy.json --semgrep sample_semgrep.json
devsecops-radar --trivy sample_trivy.json --poutine sample_poutine.json
devsecops-radar-web    # Trend chart now shows multiple data points
```

---

## 🧭 How to Use Pipeline Sentinel — Step‑by‑Step

### Step 1 – Run Your Security Scanners
Run your existing security tools and save the output as JSON. Pipeline Sentinel supports these scanners natively:

```bash
# Trivy — container and dependency scanning
trivy image --format json --output trivy.json nginx:latest

# Semgrep — static code analysis
semgrep --config=auto --json --output semgrep.json ./src

# Poutine — GitLab CI/CD security
poutine scan ./repo --format json --output poutine.json

# Zizmor — GitHub Actions security
zizmor scan ./repo --output zizmor.json --format json
```

### Step 2 – Merge Findings with the CLI
Feed the JSON files into Pipeline Sentinel:

```bash
devsecops-radar --trivy trivy.json --semgrep semgrep.json --poutine poutine.json --zizmor zizmor.json
```
This produces a single `findings.json` file with all findings merged and normalised.

### Step 3 – View the Dashboard

```bash
devsecops-radar-web
```
Open http://localhost:8080 in your browser. The dashboard shows:
*   **Severity Breakdown** — Doughnut chart of CRITICAL, HIGH, MEDIUM, LOW counts.
*   **Trend Over Time** — Line chart showing how severity counts evolve across scans.
*   **Attack Paths** — Interactive D3.js force graph (visible when AI analysis is enabled).
*   **Findings Table** — Searchable, filterable table of all findings.

### Step 4 – (Optional) Enable AI Analysis

```bash
ollama pull llama3.2:latest
devsecops-radar --trivy trivy.json --semgrep semgrep.json --analyze
devsecops-radar-web
```
The LLM generates a structured JSON analysis (`findings_ai_summary.json`) containing:
*   `executive_summary` — 2–3 sentence risk posture overview.
*   `risk_score` — 0–100 numeric risk rating.
*   `attack_paths` — How separate findings can be chained into an attack.
*   `top_remediations` — Prioritised, actionable fix steps.
*   `false_positives_likely` — Findings that appear benign.

*The dashboard automatically renders attack paths as an interactive graph.*

---

## 🔌 Offline + Online: The Hybrid RuleFusion Engine

Pipeline Sentinel is designed for both air‑gapped environments and connected teams. You decide how much connectivity you need.

### Offline Mode — Local Rules Directory
Create a folder (e.g., `~/my-security-rules/`), place your JSON files inside, and run:

```bash
devsecops-radar --trivy scan.json --rules ~/my-security-rules/
```

The engine auto‑detects the format of every JSON file. It understands:
*   **Trivy format** (`Results` → `Vulnerabilities`)
*   **Semgrep format** (`results` → `check_id`)
*   **Poutine / Zizmor / Generic format** (`findings` → `rule_id`)
*   **Plain list format** (any JSON array where each item has `severity`, `id`, and `title`)

**Example custom rule (`~/my-security-rules/custom.json`):**
```json
[
  {
    "tool": "My Custom Scanner",
    "target": "production/nginx.conf",
    "id": "CUSTOM-2026-001",
    "severity": "HIGH",
    "title": "TLS 1.0 enabled on production",
    "description": "TLS 1.0 is deprecated and vulnerable to POODLE and BEAST attacks. Disable TLS 1.0 and 1.1. Enable only TLS 1.2 and 1.3.",
    "line": 25
  }
]
```

### Online Mode — Community Rules (Optional)
If you have internet access and want to pull community‑curated rules:

```bash
devsecops-radar --update-rules
```
This clones (or pulls) the `devsecops-radar-rules` repository to `~/.devsecops-radar/community-rules/`. To use them alongside your scans:

```bash
devsecops-radar --trivy scan.json --rules ~/.devsecops-radar/community-rules/
```
💡 **Pro tip:** You can use `--rules` multiple times. Combine your local rules with the community rules, then layer in built‑in scanner outputs — everything merges into one dashboard.

---

## 🏗️ Architecture

```text
devsecops_radar/
├── cli/            # CLI entry point (scanner.py) — plugin registry + argument parser
├── core/           # RuleFusion engine, database (SQLite), LLM analysers
├── scanners/       # Pluggable scanner classes (Trivy, Semgrep, Poutine, Zizmor)
└── web/            # Flask dashboard (HTML, CSS, and JS embedded)
```

*Adding a new scanner is as simple as subclassing `BaseScanner` and implementing `parse()`. The plugin registry in `scanner.py` picks it up automatically.*

---

## ✨ Key Features

| Capability | Description |
| :--- | :--- |
| 🔌 **Multi‑Scanner Plugin Architecture** | Built‑in support for Trivy, Semgrep, Poutine, Zizmor. Add your own scanner class in minutes. |
| 🧩 **Hybrid RuleFusion Engine** | Load custom JSON rules from local directories (offline) or pull community‑curated rules from GitHub (online). |
| 🧠 **LLM‑Powered Analysis** | Engineered prompts for Ollama and LiteLLM. Get executive summaries, risk scores, attack paths, and remediation advice — fully offline with local models. |
| 🕸️ **Attack Path Visualisation** | Interactive D3.js force graph showing how multiple findings can be chained into an attack scenario. |
| 📈 **Scan History & Trend Tracking** | SQLite‑backed history with trend line chart and scan diff API. |
| 🤖 **GitHub Action** | One‑step CI/CD integration. Generates a job summary and optionally comments on PRs. |
| 🎨 **Fully Offline Dashboard** | All front‑end assets are embedded. No CDN calls, no external requests. |
| 🐳 **Docker Native** | Official image on GitHub Container Registry. One `docker run` away. |

---

## 🔧 Built‑in Scanners

| Scanner | What It Scans | Flag | Example |
| :--- | :--- | :--- | :--- |
| **Trivy** | Container images & dependencies | `--trivy` | `--trivy results.json` or `--trivy nginx:latest` |
| **Semgrep** | Static Code Analysis (SAST) | `--semgrep` | `--semgrep results.json` or `--semgrep ./src` |
| **Poutine** | GitLab CI/CD configuration security | `--poutine` | `--poutine results.json` or `--poutine ./repo` |
| **Zizmor** | GitHub Actions workflow security | `--zizmor` | `--zizmor results.json` or `--zizmor ./repo` |

---

## 🔒 Security Considerations

*   **Air‑gap ready:** Pipeline Sentinel never phones home. The dashboard works entirely offline with zero external CDN or API calls.
*   **Local‑first design:** All scan data stays on your machine. The SQLite database (`scan_history.db`) is stored locally.
*   **LLM privacy:** When using Ollama, all AI analysis runs on your hardware. No scan data ever leaves your network.
*   **Scanner isolation:** Each scanner runs independently. A failure in one scanner does not affect the others.
*   **Credentials:** Never hardcode API keys. Use environment variables (`PIPELINE_LLM_MODEL`, `PIPELINE_LLM_ENDPOINT`, `OPENAI_API_KEY`) for LLM backends.

---

## 🤖 GitHub Action

Add security analysis to your CI/CD pipeline with one step:

```yaml
- name: Pipeline Sentinel
  uses: Mehrdoost/devsecops-radar/action@main
  with:
    trivy_report: trivy-results.json
    semgrep_report: semgrep-results.json
    poutine_report: poutine-results.json
    zizmor_report: zizmor-results.json
```

*The action merges all findings, creates a job summary, and outputs CRITICAL and HIGH counts for downstream gating.*

---

## 🗺️ Roadmap

- [x] Multi‑scanner plugin engine (Trivy, Semgrep, Poutine, Zizmor)
- [x] LLM‑powered analysis (Ollama + LiteLLM)
- [x] Scan history with trend chart and scan diff API
- [x] Attack Path Visualisation (D3.js)
- [x] GitHub Action (composite)
- [x] Docker image (GitHub Container Registry)
- [x] Hybrid RuleFusion engine (local + community rules)
- [ ] Security guardrail policies (`policy.yml`) — Policy‑as‑Code
- [ ] Jira / Slack integration
- [ ] SARIF & CycloneDX support (GitHub Advanced Security, DefectDojo compatibility)

---

## 🤝 Contributing

Pull requests and issues are warmly welcome! If you'd like to integrate a new scanner, open an issue with a sample of its JSON output. For permanent scanner plugins, extend the `BaseScanner` class and add it to the registry in `scanner.py`.

---

## 👨‍💻 Author

**Mehrdoost** 

[![GitHub](https://img.shields.io/badge/GitHub-Mehrdoost-181717?logo=github)](https://github.com/Mehrdoost)


---

## 📜 License

MIT — see [LICENSE](LICENSE).

⭐ **If this project helps your team ship safer software, drop a star — it makes a real difference.**