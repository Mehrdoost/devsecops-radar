# 🛡️ Pipeline Sentinel

**Unified CI/CD Security Observability — Offline‑Ready, AI‑Enhanced, and Extensible**

Aggregate findings from **Trivy, Semgrep, Poutine, and Zizmor** into a single beautiful dark‑mode dashboard. Correlate risks with an **LLM‑powered analysis engine**, track security trends over time, and enforce guardrails — all in one CLI + Web UI.

[![GitHub stars](https://img.shields.io/github/stars/Mehrdoost/devsecops-radar?style=social)](https://github.com/Mehrdoost/devsecops-radar/stargazers)
[![License](https://img.shields.io/github/license/Mehrdoost/devsecops-radar)](LICENSE)
[![PyPI version](https://img.shields.io/pypi/v/devsecops-radar.svg)](https://pypi.org/project/devsecops-radar/)
[![GitHub release](https://img.shields.io/github/v/release/Mehrdoost/devsecops-radar?include_prereleases)](https://github.com/Mehrdoost/devsecops-radar/releases)
[![CI](https://github.com/Mehrdoost/devsecops-radar/actions/workflows/test-action.yml/badge.svg)](https://github.com/Mehrdoost/devsecops-radar/actions/workflows/test-action.yml)
[![Docker Pulls](https://img.shields.io/docker/pulls/Mehrdoost/devsecops-radar)](https://hub.docker.com/r/Mehrdoost/devsecops-radar)

> 📖 **Read this in:** [Русский](README_ru.md) | [中文](README_zh.md)

---

## 📸 Dashboard Preview

![Pipeline Sentinel Dashboard](docs/Demo.gif)
*(Severity doughnut, trend line chart, search & filter — all fully offline.)*

---

## 🚀 Quick Start

### Option 1 – Install from PyPI (recommended)

```bash
pip install devsecops-radar

# Feed scanner JSONs (sample data is included in the repo)
devsecops-radar --trivy sample_trivy.json --semgrep sample_semgrep.json

# Launch the dashboard
devsecops-radar-web
```

Open http://localhost:8080 — your unified dashboard is live.

### Option 2 – Install from Source

```bash
git clone [https://github.com/Mehrdoost/devsecops-radar.git](https://github.com/Mehrdoost/devsecops-radar.git)
cd devsecops-radar
pip install -e .
devsecops-radar --trivy sample_trivy.json --semgrep sample_semgrep.json
devsecops-radar-web
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

## ✨ Key Features

| Capability | Description |
| :--- | :--- |
| 🔌 **Multi‑Scanner Integration** | Natively parses Trivy, Semgrep, Poutine, and Zizmor. Add your own scanner via the plugin architecture. |
| 🧩 **Hybrid Rule Engine** | Load custom rules from a local directory (offline) or pull community‑curated rules from GitHub (`--update-rules`). |
| 🧠 **LLM‑Powered Analysis** | Optional AI correlation, false‑positive reduction, and attack‑path identification (Ollama‑backed, fully offline). |
| 📈 **Scan History & Trends** | SQLite‑powered historical storage. Visual trend chart shows risk evolution over time. |
| 🤖 **GitHub Action** | One‑step integration into your CI/CD. Summarises findings and optionally comments on PRs. |
| 🎨 **Beautiful Dark Dashboard** | Severity doughnut, trend line chart, search & filters — works fully offline (all assets bundled). |
| 🐳 **Docker Native** | Official image on GitHub Container Registry. Just one `docker run` away. |

---

## 🔧 Supported Scanners (Built‑In)

| Scanner | What it scans | Example use |
| :--- | :--- | :--- |
| **Trivy** | Container images & dependencies | `trivy image nginx:latest` |
| **Semgrep** | SAST (Static Code Analysis) | `.semgrep.yml` rules |
| **Poutine** | GitLab CI/CD configuration security | `.gitlab-ci.yml` misconfigs |
| **Zizmor** | GitHub Actions workflow security | Workflow injection risks |

*Missing your tool? Add it yourself — see the Rule Engine section below.*

---

## 🧩 Custom Rule Engine — Add Your Own Rules

Pipeline Sentinel ships with a Hybrid Rule Engine (RuleFusion) that lets you feed any JSON into the dashboard. No Python code required.

### Step‑by‑Step (All Three Install Methods)

**1. Create your rule JSON file.**
Any JSON file that contains a list of findings is accepted. Here is a minimal example (`my-findings.json`):

```json
[
  {
    "tool": "My Scanner",
    "target": "production/nginx.conf",
    "id": "CUSTOM-2026-001",
    "severity": "HIGH",
    "title": "TLS 1.0 enabled",
    "description": "TLS 1.0 is deprecated and vulnerable. Disable it and enable TLS 1.2+ only.",
    "line": 25
  }
]
```

**2. Place your JSON files in a directory.**
Create a folder (e.g., `~/my-security-rules/`) and copy your `.json` files there.

**3. Run Pipeline Sentinel with the `--rules` flag.**

```bash
# PyPI / Source install
devsecops-radar --trivy sample_trivy.json --rules ~/my-security-rules/

# Docker (mount your rules folder)
docker run -p 8080:8080 -v ~/my-security-rules:/rules ghcr.io/mehrdoost/devsecops-radar:latest
```

Your custom findings will appear in the dashboard alongside the built‑in scanner results.

### Auto‑Detected Formats
The engine automatically recognises the JSON structure of:
*   **Trivy** (`Results` → `Vulnerabilities`)
*   **Semgrep** (`results` → `check_id`)
*   **Poutine / Zizmor / Generic** (`findings` → `rule_id`)
*   **Plain list of findings** (any JSON array with `severity`, `id`, `title`)

*If you want to permanently add a new scanner, extend the `BaseScanner` class. See the Plugin Developer Guide.*

---

## 📊 Scan History & Trends

Every CLI run automatically saves findings in a local `scan_history.db`.
The dashboard renders a **Trend Over Time** line chart so you can monitor whether your security posture is improving.

```bash
# Build history with multiple scans
devsecops-radar --trivy sample_trivy.json --semgrep sample_semgrep.json
devsecops-radar --trivy sample_trivy.json --poutine sample_poutine.json
devsecops-radar-web

# View the trend chart at http://localhost:8080
```

---

## 🧠 AI‑Powered Analysis (Optional)

Enable LLM analysis with `--analyze` (requires a local Ollama instance):

```bash
ollama pull llama3.2:latest          # one‑time setup
devsecops-radar --trivy sample_trivy.json --semgrep sample_semgrep.json --analyze
```

*Generates `findings_ai_summary.md` with executive summary, attack paths, and remediation tips.*

---

## 🤖 GitHub Action

Add security analysis to your workflow in one step:

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

## 🏗️ Architecture

```text
devsecops_radar/
├── cli/            # CLI entry point (scanner.py)
├── core/           # Rule engine, DB, LLM analyzer
├── scanners/       # Pluggable scanner classes (Trivy, Semgrep, ...)
└── web/            # Flask dashboard (HTML/JS/CSS embedded)
```

Adding a new scanner is as simple as subclassing `BaseScanner` and implementing `parse()`.

---

## 🤝 Contributing

Pull requests and issues are warmly welcome!
If you’d like to integrate a new scanner, open an issue with a sample of its JSON output.

---

## 🗺️ Roadmap

- [x] Multi‑scanner plugin engine
- [x] LLM correlation & analysis
- [x] Scan history + trend chart
- [x] GitHub Action (composite)
- [x] Docker image (GHCR)
- [ ] Security guardrail policies (`policy.yml`)
- [ ] AI remediation advisor (detailed fix guidance)
- [ ] Findings diff/compare between branches
- [ ] Jira / Slack integration

---

## 👨‍💻 Author

**Mehrdoost** 

[![GitHub](https://img.shields.io/badge/GitHub-Mehrdoost-181717?logo=github)](https://github.com/Mehrdoost)


---

## 📜 License

MIT — see [LICENSE](LICENSE).

⭐ **If this project helps your team ship safer software, drop a star — it means a lot.**
