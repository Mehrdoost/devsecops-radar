# Prerequisites for Pipeline Sentinel

Pipeline Sentinel relies on external security tools to produce the JSON reports it consumes.  
You must install these tools separately according to your needs.

## Required for offline scanning
- **Trivy** ([installation](https://github.com/aquasecurity/trivy#installation))
- **Semgrep** ([installation](https://semgrep.dev/docs/getting-started/))
- **Poutine** ([installation](https://github.com/uber/poutine#installation))
- **Zizmor** ([installation](https://github.com/woodruffw/zizmor#installation))
- **Gitleaks** ([installation](https://github.com/gitleaks/gitleaks#installing))

## Optional (for AI analysis)
- **Ollama** ([installation](https://ollama.com/download))

## Running the dashboard
Pipeline Sentinel dashboard runs on Python 3.10+ and Flask. It is fully offline – no internet required.