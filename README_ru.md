<div align="center">

# 🛡️ Pipeline Sentinel

**Командный центр DevSecOps с открытым исходным кодом — Объединяйте, Анализируйте, Устраняйте.**

[![PyPI version](https://img.shields.io/pypi/v/devsecops-radar?style=for-the-badge&color=2196F3)](https://pypi.org/project/devsecops-radar/)
[![License](https://img.shields.io/github/license/Mehrdoost/devsecops-radar?style=for-the-badge&color=4CAF50)](LICENSE)
[![GitHub release](https://img.shields.io/github/v/release/Mehrdoost/devsecops-radar?include_prereleases&style=for-the-badge&color=FF9800)](https://github.com/Mehrdoost/devsecops-radar/releases)
[![CI](https://img.shields.io/github/actions/workflow/status/Mehrdoost/devsecops-radar/ci.yml?branch=main&style=for-the-badge&color=9C27B0)](https://github.com/Mehrdoost/devsecops-radar/actions)
[![codecov](https://codecov.io/gh/Mehrdoost/devsecops-radar/branch/main/graph/badge.svg?token=TOKEN&style=for-the-badge)](https://codecov.io/gh/Mehrdoost/devsecops-radar)
[![Stars](https://img.shields.io/github/stars/Mehrdoost/devsecops-radar?style=for-the-badge&color=FFEB3B)](https://github.com/Mehrdoost/devsecops-radar/stargazers)

<br>

> 📖 **Читать на:** [English](README.md) | [中文](README_zh.md) | [العربية](README_ar.md)

<br>

*Круговая диаграмма серьезности, линейный график тенденций, граф путей атак (кликабельные узлы), просмотр топологии, краткий отчет и панель симуляции атак — всё это работает полностью офлайн.*

![Pipeline Sentinel Dashboard](docs/Demo.gif)

</div>

---

<details>
<summary><b>📑 Оглавление (Нажмите, чтобы развернуть)</b></summary>

1. [Что такое Pipeline Sentinel? (Простое объяснение)](#-что-такое-pipeline-sentinel-простое-объяснение)
2. [Зачем вам это нужно](#-зачем-вам-это-нужно)
3. [Где запустить в вашей сети](#-где-запустить-в-вашей-сети)
4. [Предварительный просмотр дашборда](#-предварительный-просмотр-дашборда)
5. [Быстрый старт](#-быстрый-старт)
6. [Требования](#-требования)
7. [Установка](#-установка)
8. [Как использовать (Пошагово)](#-как-использовать-пошагово)
9. [Полный справочник команд](#-полный-справочник-команд)
10. [Основные возможности](#-основные-возможности)
11. [Правила сообщества и онлайн-обновления](#-правила-сообщества-и-онлайн-обновления)
12. [Симуляция атак и анализ "Что если"](#-симуляция-атак-и-анализ-что-если)
13. [Усиление безопасности (v0.4.1)](#-усиление-безопасности-v041)
14. [Архитектура](#-архитектура)
15. [Дорожная карта](#-дорожная-карта)
16. [Тестирование и CI](#-тестирование-и-ci)
17. [Политика безопасности](#-политика-безопасности)
18. [Участие в проекте](#-участие-в-проекте)
19. [Кодекс поведения](#-кодекс-поведения)
20. [Автор](#-автор)
21. [Лицензия](#-лицензия)

</details>

---

## 👨‍👩‍👧 Что такое Pipeline Sentinel? (Простое объяснение)

> **Представьте, что у вас есть несколько охранников**, и каждый следит за отдельной дверью здания. Все они кричат о своих находках на разных языках, и вам приходится бегать кругами, чтобы понять, что происходит.

**Pipeline Sentinel** собирает их всех в одной комнате, переводит их отчеты и показывает вам один понятный экран с полной картиной. Он подключается к таким инструментам, как **Trivy** (проверяет контейнеры), **Semgrep** (сканирует код), **Poutine** (проверяет пайплайны GitLab), **Zizmor** (защищает GitHub Actions) и **Gitleaks** (ищет секреты). 

Вместо того чтобы копаться в многочисленных JSON-файлах, вы получаете **красивый командный центр в темном режиме**, который показывает, что критично, каковы тенденции рисков и даже как злоумышленник может связать несколько мелких проблем в одну большую катастрофу.

*Думайте об этом как о **системе камер видеонаблюдения для всего вашего CI/CD пайплайна** — она за всем следит, предупреждает вас, предлагает исправления и даже позволяет симулировать цепочки атак, причем всё это без доступа к интернету, если вы того пожелаете.*

---

## 💥 Зачем вам это нужно

В 2026 году **атаки на цепочки поставок (supply chain)** стали угрозой №1. Инструменты вроде Trivy сами подвергались компрометации, и злоумышленники теперь внедряют вредоносный код прямо в пайплайны сборки. **Вы больше не можете просто сканировать свой код; вы должны сканировать свой пайплайн.**

**Pipeline Sentinel дает вам:**
- ✅ **Один экран для всех сканеров** – хватит жонглировать лог-файлами.
- ✅ **ИИ, понимающий цепочки атак** – «Утекший секрет + старая библиотека = катастрофа».
- ✅ **Автоматические исправления** – с помощью одного флага инструмент патчит файлы и открывает pull request (с резервным копированием).
- ✅ **Режим ручной проверки** – проверяйте каждое исправление перед применением.
- ✅ **Отчеты о соответствии** – генерируйте PDF для руководства или аудитора.
- ✅ **Симуляция атак** – отметьте несколько уязвимостей и получите готовый скрипт атаки.
- ✅ **100% офлайн работа** – работает в изолированных сетях (air-gapped), где безопасность важнее всего.
- ✅ **Интерактивный мастер** – одна команда для настройки всего.
- ✅ **Маркетплейс правил сообщества** – загружайте проверенные правила обнаружения от сообщества.

---

## 📍 Где запустить в вашей сети

Pipeline Sentinel **гибок** — вы сами решаете, где он лучше всего впишется:

| Развертывание | Описание |
| :--- | :--- |
| 🖥️ **Локальная машина разработчика** | Запускайте CLI и дашборд прямо на ноутбуке. Идеально для пентестеров или разработчиков. |
| 🔧 **CI/CD Runner** | Используйте GitHub Action или вызывайте `devsecops-radar` в скриптах Jenkins/GitLab CI. Может остановить сборку, если превышены лимиты политик (`--policy`). |
| 🏢 **Центральный сервер безопасности** | Установите на выделенный сервер, который собирает результаты сканирования от нескольких команд. |
| 🌐 **Изолированные сети (Air-Gapped)** | Скопируйте Docker-образ на офлайн-сервер. Дашборд работает без внешних запросов — все ресурсы встроены. |

<details>
<summary><b>🔍 Посмотреть типичную схему сети</b></summary>
<br>

```text
[Сканирование Trivy] ──┐
[Сканирование Semgrep] ─┤
[Сканирование Poutine] ─┼──> devsecops-radar (CLI) ──> findings.json ──> Дашборд (Flask) ──> Браузер
[Сканирование Zizmor] ─┘
[Сканирование Gitleaks] ┘
```
> **📌 Место для диаграммы:** > ![Network Flow Diagram](docs/architecture-1.png)

</details>

---

## 📸 Предварительный просмотр дашборда

*(Посмотрите анимированное демо в верхней части этого README, чтобы увидеть интерфейс в действии!)*

---

## 🚀 Быстрый старт

Запуск в 3 простых шага:

```bash
# 1. Установка из PyPI
pip install devsecops-radar

# 2. Загрузка данных сканеров (тестовые данные есть в репозитории)
devsecops-radar --trivy sample_trivy.json --semgrep sample_semgrep.json

# 3. Запуск дашборда
devsecops-radar-web
```
Откройте **http://localhost:8080** — ваш единый командный центр запущен с тестовыми данными.

> [!TIP]
> 🧙 **Хотите пошаговую настройку?** Запустите интерактивный мастер:
> ```bash
> devsecops-radar --wizard
> 
```

---

## 📦 Установка

<details>
<summary><b>Посмотреть все варианты установки (PyPI, Docker, Исходный код)</b></summary>
<br>

### Вариант 1 — PyPI (Рекомендуется)
```bash
pip install devsecops-radar
```

### Вариант 2 — Из исходного кода
```bash
git clone [https://github.com/Mehrdoost/devsecops-radar.git](https://github.com/Mehrdoost/devsecops-radar.git)
cd devsecops-radar
pip install -e ".[dev]"
```

### Вариант 3 — Docker
```bash
docker pull ghcr.io/mehrdoost/devsecops-radar:latest
docker run -p 8080:8080 ghcr.io/mehrdoost/devsecops-radar:latest
```
**Монтирование вашего файла с результатами:**
```bash
docker run -p 8080:8080 -v $(pwd)/findings.json:/data/findings.json ghcr.io/mehrdoost/devsecops-radar:latest
```
**Или используйте Docker Compose:**
```bash
docker compose up
```

### 🧙 Установка одной командой (curl)
```bash
curl -fsSL [https://raw.githubusercontent.com/Mehrdoost/devsecops-radar/main/install.sh](https://raw.githubusercontent.com/Mehrdoost/devsecops-radar/main/install.sh) | bash
```
*Этот скрипт устанавливает зависимости Python, Ollama, загружает ИИ-модель и запускает мастера настройки.*

</details>

---

## 📋 Требования

> [!IMPORTANT]
> Pipeline Sentinel полагается на внешние инструменты безопасности для создания JSON-отчетов. Вы должны установить эти инструменты отдельно в зависимости от ваших потребностей.

- **Обязательно для офлайн-сканирования:** Trivy, Semgrep, Poutine, Zizmor, Gitleaks.
- **Опционально:** Ollama (ИИ-анализ), Docker (Песочница), OPA (Политики Rego).

> 📖 **Смотрите `PREREQUISITES.md` для получения полных инструкций по установке.**

---

## 🧭 Как использовать (Пошагово)

<details open>
<summary><b>1. Запустите сканеры безопасности</b></summary>
<br>

Сгенерируйте JSON-отчеты из ваших инструментов:
```bash
trivy image --format json -o trivy.json nginx:latest
semgrep --config=auto --json --output semgrep.json .
poutine scan ./repo --format json --output poutine.json
zizmor scan ./repo --output zizmor.json --format json
gitleaks detect --source . --report-format json --report-path gitleaks.json
```
</details>

<details open>
<summary><b>2. Объедините результаты через CLI</b></summary>
<br>

```bash
devsecops-radar --trivy trivy.json --semgrep semgrep.json --poutine poutine.json --zizmor zizmor.json --gitleaks gitleaks.json
```
*Это создаст единый файл `findings.json`, где все уязвимости объединены и нормализованы.*
</details>

<details open>
<summary><b>3. Откройте дашборд</b></summary>
<br>

```bash
devsecops-radar-web
```
**На дашборде отображается:**
* **Разбивка по серьезности** – Круговая диаграмма с общим количеством
* **Тренды** – Линейный график истории сканирований
* **Безопасность пайплайна** – Статистика Poutine + Zizmor
* **Граф путей атак** – Интерактивный D3.js граф
* **Краткий отчет** – Оценка рисков и резюме от ИИ
* **Таблица уязвимостей** – С поиском, фильтрами, пагинацией и чекбоксами для симуляции
</details>

<details>
<summary><b>4. Включите ИИ-анализ (Опционально)</b></summary>
<br>

```bash
ollama pull llama3.2:latest
devsecops-radar --trivy trivy.json --analyze
devsecops-radar-web
```
ИИ генерирует `findings_ai_summary.json`, содержащий: оценку рисков, пути атак (с MITRE ATT&CK), топ исправлений и вероятные ложные срабатывания.
</details>

<details>
<summary><b>5. Авто-исправление (с проверкой человеком)</b></summary>
<br>

```bash
# Применить исправления автоматически
devsecops-radar --trivy trivy.json --analyze --fix

# Интерактивный пошаговый обзор
devsecops-radar --trivy trivy.json --analyze --fix --review
```
> [!NOTE]
> *Все измененные файлы сохраняются в резервные копии `~/.devsecops-radar/backups/`. Инструмент создает новую git-ветку `auto-fix` и отправляет её на ревью.*
</details>

<details>
<summary><b>6. Применение политик</b></summary>
<br>

Создайте файл `policy.json`:
```json
{
  "max_critical": 5, 
  "on_violation": "fail"
}
```
```bash
devsecops-radar --trivy trivy.json --policy policy.json
```
*Если критических уязвимостей больше 5, скрипт завершится с кодом 1. Вы также можете использовать политики OPA Rego (`--rego-policy`).*
</details>

<details>
<summary><b>7. Генерация отчетов о соответствии</b></summary>
<br>

```bash
# PDF отчет с привязкой к стандартам
devsecops-radar --trivy trivy.json --analyze --compliance CIS --report cis-report.pdf

# Экспорт в SARIF для GitHub Code Scanning
devsecops-radar --trivy trivy.json --export-sarif report.sarif

# Экспорт в CycloneDX SBOM
devsecops-radar --trivy trivy.json --export-cyclonedx report.cdx.json
```
</details>

<details>
<summary><b>8. Значок безопасности для вашего проекта</b></summary>
<br>

Вставьте динамический бейдж безопасности в ваш README:
```markdown
[![Security Status](https://your-server/badge/1.svg)](https://github.com/Mehrdoost/devsecops-radar)
```
</details>

<details>
<summary><b>9. Интеграция с Jira / Asana (Новое!)</b></summary>
<br>

Настройте переменные окружения для автоматического создания задач:
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

## 📋 Полный справочник команд

<details open>
<summary><b>Нажмите, чтобы развернуть категории команд</b></summary>
<br>

### 🔎 Сканеры и Ввод
| Флаг | Описание | Пример |
| :--- | :--- | :--- |
| `--trivy` | JSON файл Trivy или имя образа | `--trivy` <kbd>results.json</kbd> или <kbd>nginx:latest</kbd> |
| `--semgrep` | JSON файл Semgrep или директория | `--semgrep` <kbd>results.json</kbd> или <kbd>./src</kbd> |
| `--poutine` | JSON файл Poutine или путь к репо | `--poutine` <kbd>results.json</kbd> или <kbd>./repo</kbd> |
| `--zizmor` | JSON файл Zizmor или путь к репо | `--zizmor` <kbd>results.json</kbd> или <kbd>./repo</kbd> |
| `--gitleaks`| JSON файл Gitleaks или путь к репо| `--gitleaks` <kbd>results.json</kbd> или <kbd>./repo</kbd> |
| `--rules` | Директория с кастомными JSON правилами| `--rules` <kbd>~/my-rules/</kbd> |
| `--topology`| Путь к JSON файлу топологии | `--topology` <kbd>topology.json</kbd> |

### 🧠 ИИ, Политики и Исправления
| Флаг | Описание | Пример |
| :--- | :--- | :--- |
| `--analyze` | Включить асинхронный ИИ-анализ | `--analyze` |
| `--llm-backend`| `ollama` (по умолч.) или `litellm` | `--llm-backend` <kbd>litellm</kbd> |
| `--llm-model` | Имя модели | `--llm-model` <kbd>gpt-4o-mini</kbd> |
| `--fix` | Авто-применение исправлений ИИ (с бекапом)| `--fix` |
| `--review` | Интерактивный пошаговый обзор | `--review` |
| `--policy` | JSON файл политик | `--policy` <kbd>policy.json</kbd> |
| `--rego-policy`| Файл политик OPA Rego | `--rego-policy` <kbd>policy.rego</kbd> |

### 📊 Отчеты и Экспорт
| Флаг | Описание | Пример |
| :--- | :--- | :--- |
| `--output` | Выходной JSON файл (по умолч: findings.json)| `--output` <kbd>merged.json</kbd> |
| `--report` | Генерация PDF/JSON/HTML отчета | `--report` <kbd>report.pdf</kbd> |
| `--export-sarif`| Экспорт в SARIF | `--export-sarif` <kbd>report.sarif</kbd> |
| `--export-cyclonedx`| Экспорт в CycloneDX | `--export-cyclonedx` <kbd>report.cdx</kbd> |
| `--compliance`| Стандарт: `CIS`, `PCI-DSS`, `ISO27001` | `--compliance` <kbd>CIS</kbd> |

### ⚙️ Интеграции и Настройка
| Флаг | Описание | Пример |
| :--- | :--- | :--- |
| `--notify-jira` | Создание тикетов в Jira для критических| `--notify-jira` |
| `--notify-asana`| Создание задач в Asana | `--notify-asana` |
| `--wizard` | Интерактивный мастер первой настройки | `--wizard` |
| `--update-rules`| Скачать/обновить правила сообщества | `--update-rules` |

<br>

> [!TIP]
> ### Настройки Web-сервера (`devsecops-radar-web`)
> ```bash
> devsecops-radar-web                       # Запуск на http://localhost:8080
> FINDINGS_FILE=my.json devsecops-radar-web # Использовать кастомный файл результатов
> PIPELINE_API_KEY=secret devsecops-radar-web  # Включить API аутентификацию
> 
```

</details>

---

## ✨ Основные возможности

<details open>
<summary><b>Исследуйте движок, на котором работает Pipeline Sentinel</b></summary>
<br>

* **🔌 Мульти-сканерная архитектура плагинов:** Встроенная поддержка Trivy, Semgrep, Poutine, Zizmor, и Gitleaks.
* **🧩 Гибридный движок RuleFusion:** Загружайте кастомные правила локально или скачивайте из онлайн-репозитория (`--update-rules`).
* **🧠 ИИ-Анализ:** Асинхронный, с обогащенным контекстом (NVD/GitHub), структурированный JSON с MITRE ATT&CK и пошаговым исправлением.
* **🕸️ Визуализация путей атак:** Интерактивный граф D3.js, объединяющий уязвимости в реалистичные сценарии.
* **🛡️ Policy‑as‑Code (JSON & Rego):** Простые гейты безопасности или сложные правила OPA для остановки пайплайнов.
* **🛠️ Авто-исправления:** Применение фиксов автоматически или вручную, с безопасным резервным копированием в новую git-ветку.
* **📊 Отчеты:** Профессиональные PDF, HTML и экспорт в SARIF/CycloneDX.
* **🧪 SBOM и Dependency Confusion:** Генерация SBOM, применение VEX и обнаружение рисков подмены пакетов.
* **🔍 RAG-Поиск безопасности:** Задавайте вопросы о вашей истории сканирований на естественном языке.
* **📉 Динамическая оценка рисков:** Оценка с учетом уязвимости активов и активной разведки угроз.
* **🔒 Приватность (Offline-First):** Все ресурсы встроены. ИИ работает локально через Ollama. Данные не покидают вашу сеть.

</details>

---

## 👨‍💻 Автор

**ReverseForge** — ( Mehrdoost And Mi0r4 )  

[![GitHub](https://img.shields.io/badge/GitHub-ReverseForge-181717?style=for-the-badge&logo=github)](https://github.com/ReverseForge) 
[![GitHub](https://img.shields.io/badge/GitHub-Mehrdoost-181717?style=for-the-badge&logo=github)](https://github.com/Mehrdoost) 
[![GitHub](https://img.shields.io/badge/GitHub-miora--sora-181717?style=for-the-badge&logo=github)](https://github.com/miora-sora) 

---

## 📜 Лицензия

MIT — подробнее в [LICENSE](LICENSE).

<div align="center">
<br>

⭐ **Если этот проект помогает вашей команде создавать более безопасное ПО, поставьте звезду — это действительно важно.**

</div>