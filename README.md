# 🛡️ DevSecOps Radar

**Unified Security Observability for CI/CD Pipelines**

Stop drowning in alerts from Trivy, Semgrep, and other tools. DevSecOps Radar aggregates, correlates, and visualizes security findings in a single, beautiful dashboard.

![GitHub stars](https://img.shields.io/github/stars/Mehrdoost/devsecops-radar?style=social)
![License](https://img.shields.io/github/license/Mehrdoost/devsecops-radar)
![Docker Pulls](https://img.shields.io/docker/pulls/Mehrdoost/devsecops-radar)

## 🚀 Quick Start

```bash
git clone https://github.com/Mehrdoost/devsecops-radar.git
cd devsecops-radar
docker-compose up
Then open http://localhost:8080. You'll see a demo dashboard with sample findings.

No Docker? Install locally with pip install -e . and run devsecops-radar-web

📸 Screenshot
https://docs/demo.gif

(Replace this with an actual GIF or screenshot of your running dashboard. Put the file in the docs/ folder.)

🔧 Usage
1. Generate security reports
Run your favorite security tools and output JSON:

bash
trivy image --format json --output trivy.json nginx:latest
semgrep --config=auto --json --output semgrep.json .
2. Merge and view
bash
devsecops-radar --trivy trivy.json --semgrep semgrep.json
devsecops-radar-web
Or let the CLI scan directly (requires installed tools):

bash
devsecops-radar --trivy nginx:latest --semgrep .
3. Docker alternative
Mount your findings file:

bash
docker run -v $(pwd)/findings.json:/app/findings.json -p 8080:8080 Mehrdoost/devsecops-radar
🎯 Why DevSecOps Radar?
Correlates findings from multiple scanners into a single risk story.

Filters & searches across all vulnerabilities in real-time.

CI/CD friendly – just pipe JSON outputs, or let it scan directly.

Instant dashboard with severity breakdowns (donut chart) and table.

🤝 Contributing
Contributions are welcome! Feel free to open issues or pull requests.

📜 License
MIT