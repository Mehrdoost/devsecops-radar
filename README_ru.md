<div align="center">

# 🛡️ Pipeline Sentinel

**Командный центр DevSecOps с открытым исходным кодом — Объединяйте, Анализируйте, Исправляйте.**

[![PyPI version](https://img.shields.io/pypi/v/devsecops-radar?style=flat-square&color=blue)](https://pypi.org/project/devsecops-radar/)
[![License](https://img.shields.io/github/license/Mehrdoost/devsecops-radar?style=flat-square)](LICENSE)
[![GitHub release](https://img.shields.io/github/v/release/Mehrdoost/devsecops-radar?include_prereleases&style=flat-square)](https://github.com/Mehrdoost/devsecops-radar/releases)
[![CI](https://img.shields.io/github/actions/workflow/status/Mehrdoost/devsecops-radar/ci.yml?branch=main&style=flat-square)](https://github.com/Mehrdoost/devsecops-radar/actions)
[![Stars](https://img.shields.io/github/stars/Mehrdoost/devsecops-radar?style=flat-square)](https://github.com/Mehrdoost/devsecops-radar/stargazers)

</div>

> 📖 **Читать на других языках:** [English](README.md) | [中文](README_zh.md)

---

## 📖 Оглавление

1. [Что такое Pipeline Sentinel? (Простое объяснение)](#-что-такое-pipeline-sentinel-простое-объяснение)
2. [Зачем вам это нужно](#-зачем-вам-это-нужно)
3. [Где его запускать в вашей сети](#-где-его-запускать-в-вашей-сети)
4. [Превью дашборда](#-превью-дашборда)
5. [Быстрый старт](#-быстрый-старт)
6. [Требования (Prerequisites)](#-требования-prerequisites)
7. [Установка](#-установка)
8. [Как использовать (Шаг за шагом)](#-как-использовать-шаг-за-шагом)
9. [Полный справочник команд](#-полный-справочник-команд)
10. [Основные возможности](#-основные-возможности)
11. [Правила сообщества и онлайн-обновления](#-правила-сообщества--онлайн-обновления)
12. [Архитектура](#️-архитектура)
13. [Дорожная карта](#️-дорожная-карта)
14. [Тестирование и CI](#-тестирование-и-ci)
15. [Участие в разработке](#-участие-в-разработке)
16. [Автор](#-автор)
17. [Лицензия](#-лицензия)

---

## 👨‍👩‍👧 Что такое Pipeline Sentinel? (Простое объяснение)

Представьте, что у вас есть несколько охранников, каждый из которых следит за своей дверью в здании. Все они выкрикивают свои отчеты на разных языках, и вам приходится бегать, чтобы понять, что происходит. **Pipeline Sentinel** собирает их всех в одной комнате, переводит их отчеты и показывает вам единый и понятный экран с полной картиной. 

Он подключается к таким инструментам, как **Trivy** (проверяет контейнеры), **Semgrep** (сканирует код), **Poutine** (аудит GitLab пайплайнов), **Zizmor** (безопасность GitHub Actions) и **Gitleaks** (поиск секретов). Вместо того чтобы копаться в множестве JSON-файлов, вы получаете **красивый дашборд в темной теме**, который показывает критические уязвимости, тренды рисков и даже то, как злоумышленник может объединить несколько мелких проблем в одну большую атаку. 

Думайте об этом как о **системе камер видеонаблюдения для всего вашего CI/CD конвейера** — она следит за всем, предупреждает вас и даже предлагает исправления, причем работает полностью офлайн, если это необходимо.

---

## 💥 Зачем вам это нужно

В 2026 году **атаки на цепочки поставок** стали угрозой номер один. Такие инструменты, как Trivy, сами подвергались компрометации, и теперь злоумышленники внедряют вредоносный код прямо в конвейеры сборки. **Больше недостаточно просто сканировать код; вы должны сканировать свой конвейер.**

Pipeline Sentinel дает вам:
* **Один экран для всех сканеров** – хватит жонглировать лог-файлами.
* **ИИ, понимающий цепочки атак** – «Утечка секрета + старая библиотека = катастрофа».
* **Автоматические исправления** – с помощью одного флага он исправляет файлы и открывает pull request.
* **Режим ручной проверки** – проверяйте каждое исправление перед применением.
* **Отчеты о соответствии (Compliance)** – создайте PDF для вашего руководителя или аудитора.
* **100% автономность** – работает в изолированных средах (air-gapped), где безопасность важнее всего.
* **Интерактивный мастер** – одна команда для настройки всего проекта.

---

## 📍 Где его запускать в вашей сети

Pipeline Sentinel гибок — вы сами решаете, где он лучше всего подходит:

| Развертывание | Описание |
| :--- | :--- |
| 🖥️ **Локальная машина разработчика** | Запускайте CLI и дашборд прямо на ноутбуке. Идеально для пентестеров или разработчиков, которым нужна мгновенная обратная связь. |
| 🔧 **CI/CD Runner** | Используйте GitHub Action или вызывайте `devsecops-radar` прямо в скриптах Jenkins/GitLab CI. Он может остановить сборку, если превышен лимит критических уязвимостей (`--policy`). |
| 🏢 **Центральный сервер безопасности** | Установите на выделенный сервер (через Docker или pip), который собирает результаты сканирования от нескольких команд. Дашборд становится общей консолью безопасности. |
| 🌐 **Изолированные сети (Air-Gapped)** | Скопируйте Docker-образ и данные на офлайн-сервер. Дашборд работает без внешних вызовов — все ассеты встроены. |

### Типичная схема сети

```text
[Сканирование Trivy] ──┐
[Сканирование Semgrep] ─┤
[Сканирование Poutine] ─┼──> devsecops-radar (CLI) ──> findings.json ──> Дашборд (Flask) ──> Браузер
[Сканирование Zizmor] ─┘
[Сканирование Gitleaks] ┘
```

> **📌 Место для диаграммы:** Добавьте диаграмму сети здесь как `docs/network_flow.png`.
> `![Network Flow Diagram](docs/network_flow.png)`

---

## 📸 Превью дашборда

![Pipeline Sentinel Dashboard](docs/Demo.gif)

*(Диаграмма уязвимостей, график трендов, граф путей атак (кликабельные узлы), просмотр топологии, резюме — всё полностью офлайн.)*

---

## 🚀 Быстрый старт

```bash
# 1. Установка из PyPI
pip install devsecops-radar

# 2. Передача данных сканеров (в репозитории есть примеры)
devsecops-radar --trivy sample_trivy.json --semgrep sample_semgrep.json

# 3. Запуск дашборда
devsecops-radar-web
```

Откройте http://localhost:8080 — ваш единый дашборд готов к работе.

🧙 **Хотите пройти настройку с гидом? Запустите мастера:**
```bash
devsecops-radar --wizard
```

---

## 📋 Требования (Prerequisites)

Pipeline Sentinel полагается на внешние инструменты безопасности для создания JSON-отчетов. Вы должны установить эти инструменты отдельно в соответствии с вашими потребностями.

**Обязательно для офлайн-сканирования:**
* Trivy (установка)
* Semgrep (установка)
* Poutine (установка)
* Zizmor (установка)
* Gitleaks (установка)

**Опционально (для ИИ-анализа):**
* Ollama (установка)

> 📖 **Смотрите файл `PREREQUISITES.md` для более подробной информации.**

---

## 📦 Установка

### Вариант 1 — PyPI (Рекомендуется)
```bash
pip install devsecops-radar
```

### Вариант 2 — Из исходного кода
```bash
git clone [https://github.com/Mehrdoost/devsecops-radar.git](https://github.com/Mehrdoost/devsecops-radar.git)
cd devsecops-radar
pip install -e .
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

*Этот скрипт устанавливает зависимости Python, Ollama, загружает ИИ-модель и запускает мастера.*

---

## 🧭 Как использовать (Шаг за шагом)

### 1. Запустите ваши сканеры безопасности
Сгенерируйте JSON-вывод из ваших инструментов:

```bash
trivy image --format json -o trivy.json nginx:latest
semgrep --config=auto --json --output semgrep.json .
poutine scan ./repo --format json --output poutine.json
zizmor scan ./repo --output zizmor.json --format json
gitleaks detect --source . --report-format json --report-path gitleaks.json
```

### 2. Объедините результаты с помощью CLI
```bash
devsecops-radar --trivy trivy.json --semgrep semgrep.json --poutine poutine.json --zizmor zizmor.json --gitleaks gitleaks.json
```

*Это создаст единый файл `findings.json`, в котором все результаты объединены и нормализованы.*

### 3. Просмотр дашборда
```bash
devsecops-radar-web
```

На дашборде отображаются:
* **Разбивка по критичности** – Кольцевая диаграмма
* **Тренды во времени** – Линейный график из истории сканирований
* **Безопасность пайплайна** – Статистика Poutine + Zizmor
* **Граф путей атак** – Интерактивный D3.js граф (нажмите на узлы для подробностей)
* **Резюме для руководства** – Оценка риска и ИИ-резюме
* **Таблица результатов** – Поиск, фильтрация, пагинация

### 4. Включение ИИ-анализа (Опционально)
```bash
ollama pull llama3.2:latest
devsecops-radar --trivy trivy.json --analyze
devsecops-radar-web
```

ИИ генерирует `findings_ai_summary.json`, содержащий:
* `executive_summary`, `risk_score`
* `attack_paths` с тактиками MITRE ATT&CK
* `top_remediations` (некоторые с `fix_diff`)
* `false_positives_likely`

### 5. Авто-исправление (с ручной проверкой)
```bash
# Автоматическое применение исправлений
devsecops-radar --trivy trivy.json --analyze --fix

# Просмотр каждого исправления перед применением
devsecops-radar --trivy trivy.json --analyze --fix --review
```

*Инструмент создает новую ветку git `auto-fix` и пушит ее для ревью.*

### 6. Применение политик (Policy Enforcement)
Создайте файл `policy.json`:
```json
{"max_critical": 5, "on_violation": "fail"}
```

```bash
devsecops-radar --trivy trivy.json --policy policy.json
```

*Если количество критических уязвимостей превышает 5, команда завершается с кодом 1 — идеально для CI/CD.*

### 7. Создание отчетов о соответствии
```bash
devsecops-radar --trivy trivy.json --analyze --compliance CIS --report cis-report.pdf
```

Создается PDF-отчет с резюме, оценкой риска, таблицей результатов и соответствием стандартам. Чувствительные данные скрываются автоматически.

### 8. Бейдж безопасности для вашего проекта
После сканирования вы можете добавить динамический бейдж в ваш `README`:

```markdown
[![Security Status](https://your-server/badge/1.svg)](https://github.com/Mehrdoost/devsecops-radar)
```

Цвет бейджа меняется в зависимости от количества критических уязвимостей (зеленый/желтый/красный).

---

## 📋 Полный справочник команд

### `devsecops-radar` — Флаги CLI

| Флаг | Описание | Пример |
| :--- | :--- | :--- |
| `--trivy` | JSON файл Trivy или имя образа | `--trivy results.json` или `--trivy nginx:latest` |
| `--semgrep` | JSON файл Semgrep или директория | `--semgrep results.json` или `--semgrep ./src` |
| `--poutine` | JSON файл Poutine или путь к репо | `--poutine results.json` или `--poutine ./repo` |
| `--zizmor` | JSON файл Zizmor или путь к репо | `--zizmor results.json` или `--zizmor ./repo` |
| `--gitleaks` | JSON файл Gitleaks или путь к репо | `--gitleaks results.json` или `--gitleaks ./repo` |
| `--rules` | Директория с JSON правилами | `--rules ~/my-security-rules/` |
| `--policy` | JSON файл политики для блокировки | `--policy policy.json` |
| `--analyze` | Включить ИИ-анализ | `--analyze` |
| `--llm-backend` | `ollama` или `litellm` | `--llm-backend litellm` |
| `--llm-model` | Имя модели | `--llm-model gpt-4o-mini` |
| `--fix` | Авто-применение исправлений от ИИ | `--fix` |
| `--review` | Ревью каждого исправления | `--review` |
| `--topology` | Путь к JSON файлу топологии | `--topology topology.json` |
| `--compliance` | Стандарты: `CIS`, `PCI-DSS`, `ISO27001` | `--compliance CIS` |
| `--report` | Сгенерировать PDF отчет | `--report security_report.pdf` |
| `--output` | Выходной JSON файл | `--output merged.json` |
| `--wizard` | Интерактивный мастер | `--wizard` |

### `devsecops-radar-web` — Веб-сервер

```bash
devsecops-radar-web                       # Запуск на http://localhost:8080
FINDINGS_FILE=my.json devsecops-radar-web # Пользовательский файл
PIPELINE_API_KEY=secret devsecops-radar-web  # API-ключ аутентификации (поддержка JWT)
```

---

## ✨ Основные возможности

### 🔌 Плагинная архитектура для сканеров
Встроенная поддержка пяти сканеров с реальной системой плагинов. Сторонние сканеры могут быть установлены отдельно.

| Сканер | Что сканирует | Флаг |
| :--- | :--- | :--- |
| **Trivy** | Образы контейнеров и зависимости | `--trivy` |
| **Semgrep** | Статический анализ кода (SAST) | `--semgrep` |
| **Poutine** | Безопасность конфигурации GitLab CI/CD | `--poutine` |
| **Zizmor** | Безопасность рабочих процессов GitHub Actions | `--zizmor` |
| **Gitleaks**| Обнаружение секретов | `--gitleaks` |

### 🧩 Гибридный движок RuleFusion
* **Офлайн** – Загрузка пользовательских JSON правил из любой локальной директории (`--rules ~/my-rules/`)
* **Онлайн** – Загрузка правил сообщества из Git-репозитория (`--update-rules`)
* Репозиторий правил сообщества: `devsecops-radar-rules`

### 🧠 ИИ-анализ
* Логика повторных попыток с экспоненциальной задержкой
* Выборка с учетом токенов
* Поддержка Ollama (локально) и LiteLLM (OpenAI, Anthropic и т.д.)

### 🕸️ Визуализация путей атак
Интерактивный D3.js граф, связывающий уязвимости в реалистичные сценарии атак. Принимает файл топологии.

### 🛡️ Политика как код (Policy‑as‑Code)
Идеально для блокировки CI/CD пайплайнов.

### 🛠️ Авто-исправление с участием человека
Инструмент создает новую git-ветку и генерирует `fix.sh`.

### 📊 Отчеты о соответствии (со скрытием данных)
Генерация PDF-отчетов с автоматическим скрытием паролей, токенов, JWT.

### 📈 История сканирований и тренды
БД на основе SQLAlchemy с серверной пагинацией (`/api/findings?page=1&per_page=50`).

### 🧪 Обнаружение SBOM и путаницы зависимостей
* Генерация CycloneDX SBOM
* Обнаружение рисков Dependency Confusion в `package.json` и `requirements.txt`

### 🔍 Поиск по безопасности на основе RAG
Встроенный RAG-эндпоинт (`/api/rag?q=...`) для поиска естественным языком.

### ⚔️ Симуляция атак (Песочница)
Генерация простого PoC-скрипта в Docker-контейнере.

### 📉 Динамическая оценка рисков
Оценка риска на основе уязвимости активов и доступности эксплойтов.

### 🔒 Конфиденциальность и Offline-First
* Все ассеты встроены — нет вызовов CDN
* ИИ работает локально
* Docker работает от имени пользователя не root

---

## 🌍 Правила сообщества и онлайн-обновления

В Pipeline Sentinel есть маркетплейс правил, управляемый сообществом, который находится в отдельном репозитории: `devsecops-radar-rules`.

### Как это работает
Репозиторий содержит тщательно отобранные JSON-файлы правил для всех поддерживаемых сканеров. Пользователи могут получить последние правила с помощью одной команды:

```bash
devsecops-radar --update-rules
```

Правила хранятся локально в `~/.devsecops-radar/community-rules/`. Использование:

```bash
devsecops-radar --trivy scan.json --rules ~/.devsecops-radar/community-rules/
```

Вы можете использовать свой собственный репозиторий, задав переменную среды `COMMUNITY_RULES_REPO`.

### Добавление правила
1. Сделайте форк репозитория `devsecops-radar-rules`.
2. Добавьте новый JSON файл в папку `rules/`.
3. Откройте Pull Request.

---

## 🏗️ Архитектура

```text
devsecops_radar/
├── cli/            # Точка входа CLI – обнаружение плагинов, политики, исправления
├── core/           # Движок RuleFusion, БД (SQLAlchemy), ИИ-анализаторы
├── scanners/       # Классы подключаемых сканеров (наследуют ScannerPlugin)
├── plugins/        # Базовый класс ScannerPlugin и точки входа
└── web/            # Дашборд Flask (модульные Blueprints)
    ├── dashboard/  # Основные маршруты и встроенный HTML
    ├── attack_paths/
    ├── topology/
    ├── summary/
    └── sentry/     # Live webhook агент для CI/CD
```

> **📌 Место для диаграммы:** 
![Architecture Diagram](docs/architecture.png)

---

## 🗺️ Дорожная карта

| Фаза | Функция | Статус |
| :--- | :--- | :--- |
| ✅ Phase 1 | Мультисканерный движок (Trivy, Semgrep, Poutine, Zizmor) | Готово |
| ✅ Phase 1 | ИИ-анализ (Ollama + LiteLLM) | Готово |
| ✅ Phase 1 | История сканирования, графики трендов | Готово |
| ✅ Phase 1 | GitHub Action (composite) | Готово |
| ✅ Phase 1 | Образ Docker (multi‑stage, non‑root) | Готово |
| ✅ Phase 2 | Визуализация путей атак с MITRE ATT&CK и топологией | Готово |
| ✅ Phase 2 | Политика как код (`--policy`) | Готово |
| ✅ Phase 2 | Движок авто-исправления (`--fix`) | Готово |
| ✅ Phase 2 | PDF-отчеты с автоматическим скрытием данных | Готово |
| ✅ Phase 2 | Гибридный движок RuleFusion | Готово |
| ✅ Phase 3 | Рефакторинг дашборда (модульный Flask) | Готово |
| ✅ Phase 3 | Реальная система плагинов через точки входа | Готово |
| ✅ Phase 3 | SQLAlchemy ORM с пагинацией | Готово |
| ✅ Phase 3 | Обнаружение SBOM и путаницы зависимостей | Готово |
| ✅ Phase 3 | RAG-поиск по безопасности | Готово |
| ✅ Phase 3 | Симуляция атак (песочница) | Готово |
| ✅ Phase 3 | Динамическая оценка рисков | Готово |
| ✅ Phase 3 | Интерактивный мастер (`--wizard`) | Готово |
| ✅ Phase 3 | Режим ручной проверки (`--review`) | Готово |
| ✅ Phase 3 | Сканер секретов Gitleaks | Готово |
| ✅ Phase 3 | Эндпоинт бейджа безопасности | Готово |
| ✅ Phase 3 | Полный набор тестов и CI пайплайн | Готово |
| 🔲 Phase 4 | Интеграция с Jira / Slack | Запланировано |
| 🔲 Phase 4 | Поддержка SARIF и CycloneDX | Запланировано |
| 🔲 Phase 4 | Ассистент для Pull Request (GitHub App) | Запланировано |

---

## 🧪 Тестирование и CI

Pipeline Sentinel тщательно тестируется для обеспечения надежности в продакшене.
* **Юнит и интеграционные тесты:** 23 теста, покрывающие сканеры, движок правил, БД, анализатор, API и CLI.
* **CI Пайплайн:** Каждый push и pull request запускает автоматическое тестирование (pytest) и линтинг (ruff) через GitHub Actions.

Вы можете запустить тесты локально:
```bash
pip install -e .
pip install pytest pytest-flask ruff
pytest tests/ -v
ruff check .
```

---

## 🤝 Участие в разработке

Мы приветствуем любой вклад! Пожалуйста, прочтите наш `CONTRIBUTING.md` для получения подробных рекомендаций о том, как настроить проект, добавить новые сканеры или отправить изменения правил.

---

## 👨‍💻 Автор

**ReverseForge** — ( Mehrdoost And Mi0r4 ) 

[cite_start][![GitHub](https://img.shields.io/badge/GitHub-Mehrdoost-181717?logo=github)](https://github.com/ReverseForge) 
[cite_start][![GitHub](https://img.shields.io/badge/GitHub-Mehrdoost-181717?logo=github)](https://github.com/Mehrdoost) 
[cite_start][![GitHub](https://img.shields.io/badge/GitHub-Mehrdoost-181717?logo=github)](https://github.com/miora-sora) 

---

## 📜 Лицензия

MIT — см. [LICENSE](LICENSE).

<div align="center">
⭐ Если этот проект помогает вашей команде поставлять более безопасное ПО, поставьте звезду — это очень помогает.
</div>