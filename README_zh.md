<div align="center">

# 🛡️ Pipeline Sentinel

**开源 DevSecOps 指挥中心 — 统一、分析、修复。**

[![PyPI version](https://img.shields.io/pypi/v/devsecops-radar?style=for-the-badge&color=2196F3)](https://pypi.org/project/devsecops-radar/)
[![License](https://img.shields.io/github/license/Mehrdoost/devsecops-radar?style=for-the-badge&color=4CAF50)](LICENSE)
[![GitHub release](https://img.shields.io/github/v/release/Mehrdoost/devsecops-radar?include_prereleases&style=for-the-badge&color=FF9800)](https://github.com/Mehrdoost/devsecops-radar/releases)
[![CI](https://img.shields.io/github/actions/workflow/status/Mehrdoost/devsecops-radar/ci.yml?branch=main&style=for-the-badge&color=9C27B0)](https://github.com/Mehrdoost/devsecops-radar/actions)
[![codecov](https://codecov.io/gh/Mehrdoost/devsecops-radar/branch/main/graph/badge.svg?token=TOKEN&style=for-the-badge)](https://codecov.io/gh/Mehrdoost/devsecops-radar)
[![Stars](https://img.shields.io/github/stars/Mehrdoost/devsecops-radar?style=for-the-badge&color=FFEB3B)](https://github.com/Mehrdoost/devsecops-radar/stargazers)

<br>

> 📖 **阅读其他语言版本:** [English](README.md) | [Русский](README_ru.md) | [العربية](README_ar.md)

<br>

*严重性环形图、趋势折线图、攻击路径图（可点击节点）、拓扑视图、执行摘要和攻击模拟面板 — 全部完全离线运行。*

![Pipeline Sentinel Dashboard](docs/Demo.gif)

</div>

---

<details>
<summary><b>📑 目录（点击展开）</b></summary>

1. [什么是 Pipeline Sentinel？（简单解释）](#-什么是-pipeline-sentinel简单解释)
2. [为什么你需要它](#-为什么你需要它)
3. [在网络中的部署位置](#-在网络中的部署位置)
4. [仪表板预览](#-仪表板预览)
5. [快速开始](#-快速开始)
6. [先决条件](#-先决条件)
7. [安装](#-安装)
8. [如何使用（逐步指南）](#-如何使用逐步指南)
9. [完整命令参考](#-完整命令参考)
10. [核心功能](#-核心功能)
11. [社区规则与在线更新](#-社区规则与在线更新)
12. [攻击模拟与假设分析](#-攻击模拟与假设分析)
13. [安全加固 (v0.4.1)](#-安全加固-v041)
14. [架构](#-架构)
15. [路线图](#-路线图)
16. [测试与 CI](#-测试与-ci)
17. [安全政策](#-安全政策)
18. [贡献指南](#-贡献指南)
19. [行为准则](#-行为准则)
20. [作者](#-作者)
21. [许可证](#-许可证)

</details>

---

## 👨‍👩‍👧 什么是 Pipeline Sentinel？（简单解释）

> **想象一下你有几个保安**，每个人都在看守大楼的不同门。他们用不同的语言大声报告自己的发现，而你不得不四处奔跑才能弄清楚发生了什么。

**Pipeline Sentinel** 将他们全部集中在一个房间里，翻译他们的报告，并通过一个清晰的屏幕为你展示全貌。它连接到 **Trivy**（检查容器）、**Semgrep**（扫描代码）、**Poutine**（审计 GitLab 流水线）、**Zizmor**（保护 GitHub Actions）和 **Gitleaks**（查找机密信息）等工具。

你不再需要挖掘多个 JSON 文件，而是获得一个**精美的暗黑模式指挥中心仪表板**，它告诉你什么是严重的，风险趋势如何，甚至攻击者可能如何将几个小问题链接成一场大灾难。

*你可以把它看作是**整个 CI/CD 流水线的安全摄像头系统** — 它监控一切、发出警报、提出修复建议，甚至让你模拟攻击链，所有这些都可以在不需要互联网连接的情况下完成。*

---

## 💥 为什么你需要它

到2026年，**供应链攻击**已成为头号威胁。像 Trivy 这样的工具本身也遭到过破坏，攻击者现在直接将恶意代码注入构建流水线。**你不能仅仅扫描代码；你必须扫描你的流水线。**

**Pipeline Sentinel 为你提供：**
- ✅ **统一的扫描器屏幕** – 不再需要同时处理多个日志文件。
- ✅ **理解攻击链的 AI** – “泄露的密钥 + 旧库 = 灾难。”
- ✅ **自动修复** – 只需一个标志，它就会修补文件并打开一个包含备份的拉取请求（PR）。
- ✅ **人工审核模式** – 在应用之前检查每个修复程序。
- ✅ **合规报告** – 为你的老板或审计员生成 PDF 报告。
- ✅ **攻击模拟** – 勾选几个发现即可看到生成的攻击脚本。
- ✅ **100% 离线可用** – 在安全至关重要的隔离（air-gapped）网络环境中工作。
- ✅ **交互式向导** – 一个命令即可完成所有设置。
- ✅ **社区规则市场** – 从社区提取精选的检测规则。

---

## 📍 在网络中的部署位置

Pipeline Sentinel 的设计非常**灵活** — 由你决定它最适合的位置：

| 部署方式 | 描述 |
| :--- | :--- |
| 🖥️ **本地开发者机器** | 直接在笔记本电脑上运行 CLI 和仪表板。非常适合需要即时反馈的渗透测试人员或开发人员。 |
| 🔧 **CI/CD 运行器** | 使用 GitHub Action 或直接在 Jenkins/GitLab CI 脚本中调用。如果严重漏洞超出策略，它会使构建失败 (`--policy`)。 |
| 🏢 **中央安全服务器** | 安装在专用服务器上，收集多个团队的扫描结果。仪表板成为共享的安全运营控制台。 |
| 🌐 **物理隔离网络 (Air-Gapped)** | 将 Docker 镜像复制到离线服务器。仪表板零外部调用 — 所有资产均内置。 |

<details>
<summary><b>🔍 查看典型网络拓扑图</b></summary>
<br>

```text
[Trivy 扫描] ──┐
[Semgrep 扫描] ─┤
[Poutine 扫描] ─┼──> devsecops-radar (CLI) ──> findings.json ──> 仪表板 (Flask) ──> 浏览器
[Zizmor 扫描] ─┘
[Gitleaks 扫描] ┘
```
> **📌 示意图占位符:** > ![Network Flow Diagram](docs/architecture-1.png)

</details>

---

## 📸 仪表板预览

*(请查看此 README 顶部的动画演示，以观看 UI 的实际运行情况！)*

---

## 🚀 快速开始

只需3个简单步骤即可启动：

```bash
# 1. 从 PyPI 安装
pip install devsecops-radar

# 2. 提供扫描器数据 (仓库中包含样本数据)
devsecops-radar --trivy sample_trivy.json --semgrep sample_semgrep.json

# 3. 启动仪表板
devsecops-radar-web
```
打开 **http://localhost:8080** — 你的统一指挥中心已通过样本数据上线。

> [!TIP]
> 🧙 **想要完整的引导式设置？** 运行交互式向导：
> ```bash
> devsecops-radar --wizard
> 
```

---

## 📦 安装

<details>
<summary><b>查看所有安装选项 (PyPI, Docker, 源码, 一键安装)</b></summary>
<br>

### 选项 1 — PyPI (推荐)
```bash
pip install devsecops-radar
```

### 选项 2 — 从源码安装
```bash
git clone [https://github.com/Mehrdoost/devsecops-radar.git](https://github.com/Mehrdoost/devsecops-radar.git)
cd devsecops-radar
pip install -e ".[dev]"
```

### 选项 3 — Docker
```bash
docker pull ghcr.io/mehrdoost/devsecops-radar:latest
docker run -p 8080:8080 ghcr.io/mehrdoost/devsecops-radar:latest
```
**挂载你自己的发现文件：**
```bash
docker run -p 8080:8080 -v $(pwd)/findings.json:/data/findings.json ghcr.io/mehrdoost/devsecops-radar:latest
```
**或使用 Docker Compose:**
```bash
docker compose up
```

### 🧙 一键安装命令 (curl)
```bash
curl -fsSL [https://raw.githubusercontent.com/Mehrdoost/devsecops-radar/main/install.sh](https://raw.githubusercontent.com/Mehrdoost/devsecops-radar/main/install.sh) | bash
```
*此脚本安装 Python 依赖项、Ollama，拉取 AI 模型，并启动向导。*

</details>

---

## 📋 先决条件

> [!IMPORTANT]
> Pipeline Sentinel 依赖于外部安全工具生成它使用的 JSON 报告。你必须根据需要单独安装这些工具。

- **离线扫描必需:** Trivy, Semgrep, Poutine, Zizmor, Gitleaks.
- **可选:** Ollama (AI 分析), Docker (沙箱环境), OPA (Rego 策略).

> 📖 **有关这些工具的完整安装详细信息，请参见 `PREREQUISITES.md`。**

---

## 🧭 如何使用（逐步指南）

<details open>
<summary><b>1. 运行你的安全扫描器</b></summary>
<br>

从你的工具生成 JSON 输出：
```bash
trivy image --format json -o trivy.json nginx:latest
semgrep --config=auto --json --output semgrep.json .
poutine scan ./repo --format json --output poutine.json
zizmor scan ./repo --output zizmor.json --format json
gitleaks detect --source . --report-format json --report-path gitleaks.json
```
</details>

<details open>
<summary><b>2. 使用 CLI 合并发现结果</b></summary>
<br>

```bash
devsecops-radar --trivy trivy.json --semgrep semgrep.json --poutine poutine.json --zizmor zizmor.json --gitleaks gitleaks.json
```
*这将生成一个单独的 `findings.json`，其中所有结果都被合并和标准化。*
</details>

<details open>
<summary><b>3. 查看仪表板</b></summary>
<br>

```bash
devsecops-radar-web
```
**仪表板显示：**
* **严重性分类** – 带有总数的环形图
* **随时间变化的趋势** – 扫描历史折线图
* **流水线安全** – Poutine + Zizmor 统计卡
* **攻击路径图** – 交互式 D3.js 图表
* **执行摘要** – 风险评分和 AI 生成的摘要
* **发现结果表** – 可搜索、过滤、分页，带有用于模拟的复选框
</details>

<details>
<summary><b>4. 启用 AI 分析（可选）</b></summary>
<br>

```bash
ollama pull llama3.2:latest
devsecops-radar --trivy trivy.json --analyze
devsecops-radar-web
```
LLM 会生成包含风险评分、攻击路径（带有 MITRE ATT&CK）、顶级修复建议和误报判断的文件。
</details>

<details>
<summary><b>5. 自动修复（带有人工审核）</b></summary>
<br>

```bash
# 自动应用修复
devsecops-radar --trivy trivy.json --analyze --fix

# 交互式逐步审核
devsecops-radar --trivy trivy.json --analyze --fix --review
```
> [!NOTE]
> *所有修改过的文件都会备份到 `~/.devsecops-radar/backups/`。该工具会创建一个新的 git 分支 `auto-fix` 并将其推送以供审核。*
</details>

<details>
<summary><b>6. 策略执行 (Policy Enforcement)</b></summary>
<br>

创建 `policy.json` 文件：
```json
{
  "max_critical": 5, 
  "on_violation": "fail"
}
```
```bash
devsecops-radar --trivy trivy.json --policy policy.json
```
*如果严重发现超过 5 个，命令将以代码 1 退出。你也可以使用 OPA Rego 策略 (`--rego-policy`)。*
</details>

<details>
<summary><b>7. 生成合规性及标准报告</b></summary>
<br>

```bash
# 带有合规性映射的 PDF 报告
devsecops-radar --trivy trivy.json --analyze --compliance CIS --report cis-report.pdf

# 导出为适用于 GitHub Code Scanning 的 SARIF 格式
devsecops-radar --trivy trivy.json --export-sarif report.sarif

# 导出为 CycloneDX SBOM
devsecops-radar --trivy trivy.json --export-cyclonedx report.cdx.json
```
</details>

<details>
<summary><b>8. 项目的安全徽章</b></summary>
<br>

在你的 README 中嵌入动态安全徽章：
```markdown
[![Security Status](https://your-server/badge/1.svg)](https://github.com/Mehrdoost/devsecops-radar)
```
</details>

<details>
<summary><b>9. Jira / Asana 集成（全新功能！）</b></summary>
<br>

设置环境变量以自动创建问题：
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

## 📋 完整命令参考

<details open>
<summary><b>点击展开命令类别</b></summary>
<br>

### 🔎 扫描器与输入
| 标志 | 描述 | 示例 |
| :--- | :--- | :--- |
| `--trivy` | Trivy JSON 文件或镜像名称 | `--trivy` <kbd>results.json</kbd> 或 <kbd>nginx:latest</kbd> |
| `--semgrep` | Semgrep JSON 文件或目录 | `--semgrep` <kbd>results.json</kbd> 或 <kbd>./src</kbd> |
| `--poutine` | Poutine JSON 文件或仓库路径 | `--poutine` <kbd>results.json</kbd> 或 <kbd>./repo</kbd> |
| `--zizmor` | Zizmor JSON 文件或仓库路径 | `--zizmor` <kbd>results.json</kbd> 或 <kbd>./repo</kbd> |
| `--gitleaks`| Gitleaks JSON 文件或仓库路径 | `--gitleaks` <kbd>results.json</kbd> 或 <kbd>./repo</kbd> |
| `--rules` | 包含自定义 JSON 规则的目录 | `--rules` <kbd>~/my-rules/</kbd> |
| `--topology`| 拓扑 JSON 文件的路径 | `--topology` <kbd>topology.json</kbd> |

### 🧠 AI，策略与修复
| 标志 | 描述 | 示例 |
| :--- | :--- | :--- |
| `--analyze` | 启用异步 LLM 分析 (需 Ollama) | `--analyze` |
| `--llm-backend`| `ollama` (默认) 或 `litellm` | `--llm-backend` <kbd>litellm</kbd> |
| `--llm-model` | 模型名称 | `--llm-model` <kbd>gpt-4o-mini</kbd> |
| `--fix` | 自动应用 AI 建议的修复 (带备份) | `--fix` |
| `--review` | 交互式逐步修复审核 | `--review` |
| `--policy` | 用于门控的 JSON 策略文件 | `--policy` <kbd>policy.json</kbd> |
| `--rego-policy`| OPA Rego 策略文件 | `--rego-policy` <kbd>policy.rego</kbd> |

### 📊 报告与导出
| 标志 | 描述 | 示例 |
| :--- | :--- | :--- |
| `--output` | 输出 JSON 文件 (默认: findings.json)| `--output` <kbd>merged.json</kbd> |
| `--report` | 生成 PDF/JSON/HTML 报告 | `--report` <kbd>report.pdf</kbd> |
| `--export-sarif`| 将发现结果导出为 SARIF | `--export-sarif` <kbd>report.sarif</kbd> |
| `--export-cyclonedx`| 将发现结果导出为 CycloneDX | `--export-cyclonedx` <kbd>report.cdx</kbd> |
| `--compliance`| 框架: `CIS`, `PCI-DSS`, `ISO27001` | `--compliance` <kbd>CIS</kbd> |

### ⚙️ 集成与设置
| 标志 | 描述 | 示例 |
| :--- | :--- | :--- |
| `--notify-jira` | 为严重发现创建 Jira 问题 | `--notify-jira` |
| `--notify-asana`| 为严重发现创建 Asana 任务 | `--notify-asana` |
| `--wizard` | 交互式首次设置向导 | `--wizard` |
| `--update-rules`| 下载/更新社区规则 | `--update-rules` |

<br>

> [!TIP]
> ### `devsecops-radar-web` — Web 服务器选项
> ```bash
> devsecops-radar-web                       # 在 http://localhost:8080 启动
> FINDINGS_FILE=my.json devsecops-radar-web # 使用自定义结果文件
> PIPELINE_API_KEY=secret devsecops-radar-web  # 启用 API 身份验证
> 
```

</details>

---

## ✨ 核心功能

<details open>
<summary><b>探索驱动 Pipeline Sentinel 的引擎</b></summary>
<br>

* **🔌 多扫描器插件架构：** 内置支持 Trivy、Semgrep、Poutine、Zizmor 和 Gitleaks。
* **🧩 混合 RuleFusion 引擎：** 在本地加载自定义 JSON 规则，或从可配置的 Git 仓库中提取社区管理的规则 (`--update-rules`)。
* **🧠 LLM 驱动的分析：** 异步、丰富的上下文（NVD/GitHub 链接）、结构化 JSON（带有 MITRE ATT&CK）及逐步修复指南。
* **🕸️ 多步攻击路径可视化：** 交互式 D3.js 力导向图，将发现链接成现实的攻击场景。
* **🛡️ 策略即代码 (JSON & Rego)：** 定义简单的安全门控，或在 Rego 中编写复杂规则。
* **🛠️ 自动修复：** 自动应用或人工审查 AI 建议的修复，每个文件都会安全地备份在新的 Git 分支中。
* **📊 合规性与报告：** 专业 PDF 报告和 SARIF/CycloneDX 导出。
* **🧪 SBOM 与依赖混淆：** 生成 CycloneDX SBOM，应用 VEX 文件，并检测冒充风险。
* **🔍 RAG 安全搜索：** 使用自然语言询问有关扫描历史的问题。
* **📉 动态风险评分：** 基于资产暴露、漏洞利用可用性和威胁情报的上下文感知评分。
* **🔒 隐私与离线优先：** 100% 嵌入式资产，LLM 在本地运行。

</details>

---

## 👨‍💻 作者

**ReverseForge** — ( Mehrdoost And Mi0r4 )  

[![GitHub](https://img.shields.io/badge/GitHub-ReverseForge-181717?style=for-the-badge&logo=github)](https://github.com/ReverseForge) 
[![GitHub](https://img.shields.io/badge/GitHub-Mehrdoost-181717?style=for-the-badge&logo=github)](https://github.com/Mehrdoost) 
[![GitHub](https://img.shields.io/badge/GitHub-miora--sora-181717?style=for-the-badge&logo=github)](https://github.com/miora-sora) 

---

## 📜 许可证

MIT — 请参见 [LICENSE](LICENSE)。

<div align="center">
<br>

⭐ **如果这个项目能帮助你的团队发布更安全的软件，请点亮一颗 Star — 这对我们意义重大。**

</div>