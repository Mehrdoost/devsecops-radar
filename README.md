# 🛡️ Pipeline Sentinel

**Unified CI/CD Security Observability — AI‑Enhanced & Offline‑Ready**

Aggregate findings from **Trivy, Semgrep, Poutine, Zizmor** and more into a single, beautiful dashboard. Correlate risks with an **LLM‑powered analysis engine**, track security trends over time, and enforce guardrails – all in one CLI + web UI.

[![GitHub stars](https://img.shields.io/github/stars/Mehrdoost/devsecops-radar?style=social)](https://github.com/Mehrdoost/devsecops-radar/stargazers)
[![License](https://img.shields.io/github/license/Mehrdoost/devsecops-radar)](LICENSE)
[![Docker Pulls](https://img.shields.io/docker/pulls/Mehrdoost/devsecops-radar)](https://hub.docker.com/r/Mehrdoost/devsecops-radar)
[![PyPI version](https://img.shields.io/pypi/v/devsecops-radar.svg)](https://pypi.org/project/devsecops-radar/)
[![GitHub release](https://img.shields.io/github/v/release/Mehrdoost/devsecops-radar?include_prereleases)](https://github.com/Mehrdoost/devsecops-radar/releases)
[![CI](https://github.com/Mehrdoost/devsecops-radar/actions/workflows/test-action.yml/badge.svg)](https://github.com/Mehrdoost/devsecops-radar/actions/workflows/test-action.yml)

---

## 🚀 Quick Start

```bash
# Install from PyPI
pip install devsecops-radar

# Or install directly from GitHub
pip install git+[https://github.com/Mehrdoost/devsecops-radar.git](https://github.com/Mehrdoost/devsecops-radar.git)

# Run the web dashboard
devsecops-radar-web
```

🐳 **Docker:** `docker pull ghcr.io/mehrdoost/devsecops-radar:latest` *(see instructions below)*

---

## ✨ Key Features

| Capability | Description |
| :--- | :--- |
| 🔌 **Multi‑Scanner Integration** | Natively parses Trivy, Semgrep, Poutine, Zizmor. More via pluggable architecture. |
| 🧠 **LLM‑Powered Analysis** | Optional AI correlation, false‑positive reduction, attack‑path identification (Ollama‑backed, offline capable). |
| 📈 **Scan History & Trends** | SQLite‑powered historical storage. Visual trend chart shows risk evolution over time. |
| 🤖 **GitHub Action** | One‑step integration into your CI/CD. Summarises findings and optionally comments on PRs. |
| 🎨 **Beautiful Dark Dashboard** | Severity doughnut, trend line chart, search & filters – works fully offline (all assets bundled). |
| 🐳 **Docker Native** | Official image on GitHub Container Registry. Just one `docker run` away. |

---

## 🔧 Supported Scanners

| Scanner | What it scans | Status |
| :--- | :--- | :--- |
| **Trivy** | Container images & dependencies | ✅ |
| **Semgrep** | SAST (Static Code Analysis) | ✅ |
| **Poutine** | GitLab CI/CD configuration security | ✅ |
| **Zizmor** | GitHub Actions workflow security | ✅ |
| **Snyk, ZAP, Dependency-Track** | Roadmap | 🔲 |

*Adding a new scanner is easy – extend `BaseScanner` and plug it in.*

---


## 📸 Dashboard Preview

![DevSecOps Radar Dashboard](docs/Demo.gif)

---

## 🤖 GitHub Action

Add security analysis to your workflow with a single step:

```yaml
- name: Pipeline Sentinel
  uses: Mehrdoost/devsecops-radar/action@main
  with:
    trivy_report: trivy-results.json
    semgrep_report: semgrep-results.json
    poutine_report: poutine-results.json
    zizmor_report: zizmor-results.json
```

The action merges findings, creates a job summary, and outputs CRITICAL/HIGH counts.

---

## 📊 Scan History & Trends

Every run automatically stores findings in a local `scan_history.db`.
The dashboard renders a **Trend Over Time** chart so teams can monitor whether security posture is improving.

```bash
# Multiple scans build history
devsecops-radar --trivy sample_trivy.json --semgrep sample_semgrep.json
devsecops-radar --trivy sample_trivy.json --semgrep sample_semgrep.json --poutine sample_poutine.json

# Now view the trend in the dashboard
devsecops-radar-web
```

---

## 🧠 AI‑Powered Analysis (Optional)

Enable LLM analysis with `--analyze` (requires Ollama running locally):

```bash
ollama pull llama3.2:latest          # one-time setup
devsecops-radar --trivy sample_trivy.json --semgrep sample_semgrep.json --zizmor sample_zizmor.json --analyze
```

*Generates `findings_ai_summary.md` with executive summary, attack paths, and remediation tips.*

---

## 🛠️ Usage

### From Source (Python)
```bash
pip install -e .
devsecops-radar --trivy trivy.json --semgrep semgrep.json
devsecops-radar-web
```

### Docker
```bash
docker pull ghcr.io/mehrdoost/devsecops-radar:latest
docker run -p 8080:8080 -v $(pwd)/findings.json:/data/findings.json ghcr.io/mehrdoost/devsecops-radar:latest
```

### Using Sample Data
```bash
devsecops-radar --trivy sample_trivy.json --semgrep sample_semgrep.json --poutine sample_poutine.json --zizmor sample_zizmor.json
```

---

## 🗺️ Roadmap

- [x] Multi‑scanner engine (Trivy, Semgrep, Poutine, Zizmor)
- [x] AI correlation & analysis
- [x] Scan history & trend visualisation
- [x] GitHub Action (composite)
- [x] Docker image (GitHub Container Registry)
- [ ] Security guardrail policies (`policy.yml`)
- [ ] AI remediation advisor (detailed fix guidance)
- [ ] Findings diff/compare between branches
- [ ] Jira / Slack integration

---

## 🤝 Contributing

Pull requests and issues are warmly welcome!
If you’d like to integrate a new scanner, open an issue with a sample of its JSON output.

---

## 👨‍💻 Author

**Mehrdoost** 

[![GitHub](https://img.shields.io/badge/GitHub-Mehrdoost-181717?logo=github)](https://github.com/Mehrdoost)

---

## 📜 License

MIT – see [LICENSE](LICENSE) file.

⭐ **If this project helps your team ship more secure software, please drop a star!**
