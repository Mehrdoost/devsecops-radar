# Prerequisites for Pipeline Sentinel

Pipeline Sentinel can aggregate findings from several security scanners and, when configured, run them directly.  
The dashboard and CLI core require no internet connection – everything works fully offline.

---

## Required for Running Scans (Offline)

To let Pipeline Sentinel execute scans (instead of only importing pre‑existing JSON reports), install the scanners you need:

| Scanner   | Installation                                                                 |
|-----------|-------------------------------------------------------------------------------|
| Trivy     | [Installation guide](https://github.com/aquasecurity/trivy#installation)     |
| Semgrep   | [Installation guide](https://semgrep.dev/docs/getting-started/)              |
| Poutine   | [Installation guide](https://github.com/uber/poutine#installation)          |
| Zizmor    | [Installation guide](https://github.com/woodruffw/zizmor#installation)      |
| Gitleaks  | [Installation guide](https://github.com/gitleaks/gitleaks#installing)       |

> **Note:** If you already have scan results in JSON format, you can skip installing the scanners and use the `--trivy <file>.json` … flags to load them directly.

---

## Optional Components

### AI Analysis (Ollama)
- [Ollama](https://ollama.com/download) – required only when using the `--analyze` flag.  
  The model `llama3.2:latest` is recommended. Ollama itself runs entirely locally.

### Attack Simulation (Docker)
- [Docker](https://docs.docker.com/get-docker/) – needed to safely execute attack simulations in a sandbox.  
  The simulation script is still displayed even without Docker; only the execution step is skipped.

### SBOM Generation (syft)
- [Syft](https://github.com/anchore/syft#installation) – required for the `--export-cyclonedx` SBOM feature.

### Policy Enforcement (OPA)
- [OPA](https://www.openpolicyagent.org/docs/latest/#running-opa) – required only if using `--rego-policy` for advanced policy checks.

### Jira / Asana Integration
- No extra tools required. Set the appropriate environment variables (`JIRA_URL`, `JIRA_TOKEN`, etc.).

---

## Running the Dashboard

- Python 3.10 or later.
- Flask and Waitress (installed automatically with `devsecops-radar`).
- A modern web browser for the frontend.

---

## Air‑Gapped Environments

All components can be pre‑downloaded and installed offline:
- Scanner binaries (Trivy, Semgrep, …) can be copied as static executables.
- Docker images (e.g., `alpine`) can be pulled on a connected host and exported with `docker save`.
- Ollama models can be pulled once and transferred manually.

Pipeline Sentinel does not initiate any external network requests itself.