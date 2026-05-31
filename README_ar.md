<div align="center">

# 🛡️ Pipeline Sentinel

**مركز قيادة DevSecOps مفتوح المصدر — توحيد، تحليل، ومعالجة.**

[![PyPI version](https://img.shields.io/pypi/v/devsecops-radar?style=for-the-badge&color=2196F3)](https://pypi.org/project/devsecops-radar/)
[![License](https://img.shields.io/github/license/Mehrdoost/devsecops-radar?style=for-the-badge&color=4CAF50)](LICENSE)
[![GitHub release](https://img.shields.io/github/v/release/Mehrdoost/devsecops-radar?include_prereleases&style=for-the-badge&color=FF9800)](https://github.com/Mehrdoost/devsecops-radar/releases)
[![CI](https://img.shields.io/github/actions/workflow/status/Mehrdoost/devsecops-radar/ci.yml?branch=main&style=for-the-badge&color=9C27B0)](https://github.com/Mehrdoost/devsecops-radar/actions)
[![codecov](https://codecov.io/gh/Mehrdoost/devsecops-radar/branch/main/graph/badge.svg?token=TOKEN&style=for-the-badge)](https://codecov.io/gh/Mehrdoost/devsecops-radar)
[![Stars](https://img.shields.io/github/stars/Mehrdoost/devsecops-radar?style=for-the-badge&color=FFEB3B)](https://github.com/Mehrdoost/devsecops-radar/stargazers)

<br>

> 📖 **اقرأ هذا بـ:** [English](README.md) | [Русский](README_ru.md) | [中文](README_zh.md)

<br>

*رسم بياني دائري للخطورة، مخطط اتجاهي زمني، رسم مسار الهجوم (عقد قابلة للنقر)، عرض الطوبولوجيا، ملخص تنفيذي، ولوحة محاكاة الهجوم — كل ذلك يعمل بالكامل دون اتصال بالإنترنت.*

![Pipeline Sentinel Dashboard](docs/Demo.gif)

</div>

---

<details>
<summary><b>📑 جدول المحتويات (انقر للتوسيع)</b></summary>

1. [ما هو Pipeline Sentinel؟ (شرح مبسط)](#-ما-هو-pipeline-sentinel-شرح-مبسط)
2. [لماذا تحتاجه](#-لماذا-تحتاجه)
3. [أين يمكنك تشغيله في شبكتك](#-أين-يمكنك-تشغيله-في-شبكتك)
4. [معاينة لوحة القيادة](#-معاينة-لوحة-القيادة)
5. [البدء السريع](#-البدء-السريع)
6. [المتطلبات الأساسية](#-المتطلبات-الأساسية)
7. [التثبيت](#-التثبيت)
8. [كيفية الاستخدام (خطوة بخطوة)](#-كيفية-الاستخدام-خطوة-بخطوة)
9. [مرجع الأوامر الكامل](#-مرجع-الأوامر-الكامل)
10. [القدرات الأساسية](#-القدرات-الأساسية)
11. [قواعد المجتمع والتحديثات عبر الإنترنت](#-قواعد-المجتمع-والتحديثات-عبر-الإنترنت)
12. [محاكاة الهجوم وتحليل السيناريوهات](#-محاكاة-الهجوم-وتحليل-السيناريوهات)
13. [تعزيز الأمن (v0.4.1)](#-تعزيز-الأمن-v041)
14. [الهيكلية](#-الهيكلية)
15. [خارطة الطريق](#-خارطة-الطريق)
16. [الاختبار والتكامل المستمر (CI)](#-الاختبار-والتكامل-المستمر-ci)
17. [سياسة الأمان](#-سياسة-الأمان)
18. [المساهمة](#-المساهمة)
19. [مدونة السلوك](#-مدونة-السلوك)
20. [المؤلف](#-المؤلف)
21. [الرخصة](#-الرخصة)

</details>

---

## 👨‍👩‍👧 ما هو Pipeline Sentinel؟ (شرح مبسط)

> **تخيل أن لديك عدة حراس أمن**، كل منهم يراقب بابًا مختلفًا للمبنى. يصرخ جميعهم بما يكتشفونه بلغات مختلفة، وتضطر أنت للركض في كل مكان لفهم ما يحدث.

يجمعهم **Pipeline Sentinel** جميعًا في غرفة واحدة، ويترجم تقاريرهم، ويعرض لك شاشة واحدة واضحة بالصورة الكاملة. يتصل بأدوات مثل **Trivy** (لفحص الحاويات)، **Semgrep** (لفحص الكود)، **Poutine** (لتدقيق خطوط أنابيب GitLab)، **Zizmor** (لتأمين GitHub Actions)، و **Gitleaks** (للبحث عن الأسرار).

بدلًا من التنقيب في ملفات JSON المتعددة، تحصل على **لوحة قيادة جميلة بوضع داكن كمركز تحكم**، تخبرك بما هو حرج، وكيف تتجه المخاطر، وحتى كيف يمكن للمهاجم ربط عدة مشكلات صغيرة لإنشاء كارثة كبيرة.

*فكر فيه كأنه **نظام كاميرات مراقبة لكامل خط أنابيب CI/CD الخاص بك** — فهو يراقب كل شيء، وينبهك، ويقترح إصلاحات، بل ويسمح لك بمحاكاة سلاسل الهجوم، كل ذلك دون الحاجة إلى اتصال بالإنترنت إذا أردت.*

---

## 💥 لماذا تحتاجه

في عام 2026، أصبحت **هجمات سلسلة التوريد** هي التهديد رقم 1. أدوات مثل Trivy نفسها تم اختراقها، وأصبح المهاجمون يدمجون الأكواد الخبيثة مباشرة في خطوط الأنابيب. **لم يعد بإمكانك فحص الكود فقط؛ يجب عليك فحص خط الأنابيب الخاص بك.**

**يمنحك Pipeline Sentinel:**
- ✅ **شاشة واحدة لجميع الماسحات** – توقف عن التنقل بين ملفات السجل.
- ✅ **ذكاء اصطناعي يفهم سلاسل الهجوم** – "سر مسرب + مكتبة قديمة = كارثة."
- ✅ **إصلاحات تلقائية** – بعلامة واحدة، يقوم بترقيع الملفات وفتح طلب سحب (مع أخذ نسخ احتياطية).
- ✅ **وضع المراجعة البشرية** – افحص كل إصلاح قبل تطبيقه.
- ✅ **تقارير الامتثال** – قم بإنشاء ملف PDF لمديرك أو المدقق.
- ✅ **محاكاة الهجوم** – حدد بعض الاكتشافات وشاهد نص الهجوم الذي تم إنشاؤه.
- ✅ **يعمل 100% دون إنترنت** – مثالي للبيئات المعزولة (air-gapped) حيث يكون الأمان الأهم.
- ✅ **معالج تفاعلي (Wizard)** – أمر واحد لإعداد كل شيء.
- ✅ **متجر قواعد المجتمع** – اسحب قواعد الكشف المنتقاة من المجتمع.

---

## 📍 أين يمكنك تشغيله في شبكتك

تم تصميم Pipeline Sentinel ليكون **مرنًا** — أنت تقرر المكان الأنسب له:

| نوع النشر | الوصف |
| :--- | :--- |
| 🖥️ **جهاز المطور المحلي** | قم بتشغيل واجهة سطر الأوامر (CLI) ولوحة القيادة على حاسوبك. مثالي للمطورين الفرديين. |
| 🔧 **مشغل CI/CD** | استخدم GitHub Action أو استدعِ `devsecops-radar` مباشرة في نصوص Jenkins/GitLab CI. يمكنه إيقاف البناء إذا تجاوزت الثغرات سياستك (`--policy`). |
| 🏢 **خادم أمان مركزي** | قم بتثبيته على خادم مخصص لجمع نتائج الفحص من فرق متعددة. |
| 🌐 **الشبكات المعزولة (Air-Gapped)** | انسخ صورة Docker إلى خادم غير متصل بالإنترنت. لوحة القيادة تعمل بدون استدعاءات خارجية. |

<details>
<summary><b>🔍 عرض المخطط النموذجي للشبكة</b></summary>
<br>

```text
[فحص Trivy] ──┐
[فحص Semgrep] ─┤
[فحص Poutine] ─┼──> devsecops-radar (CLI) ──> findings.json ──> لوحة القيادة (Flask) ──> المتصفح
[فحص Zizmor] ─┘
[فحص Gitleaks] ┘
```
> **📌 مكان للمخطط البياني:** > ![Network Flow Diagram](docs/architecture-1.png)

</details>

---

## 📸 معاينة لوحة القيادة

*(شاهد العرض المتحرك في أعلى ملف README هذا لرؤية واجهة المستخدم أثناء العمل!)*

---

## 🚀 البدء السريع

ابدأ التشغيل في 3 خطوات بسيطة:

```bash
# 1. التثبيت من PyPI
pip install devsecops-radar

# 2. تزويد بيانات الماسح (تتضمن المستودعات بيانات نموذجية)
devsecops-radar --trivy sample_trivy.json --semgrep sample_semgrep.json

# 3. إطلاق لوحة القيادة
devsecops-radar-web
```
افتح **http://localhost:8080** — مركز القيادة الموحد الخاص بك يعمل الآن مع البيانات النموذجية.

> [!TIP]
> 🧙 **هل تريد إعدادًا موجهًا بالكامل؟** قم بتشغيل المعالج التفاعلي:
> ```bash
> devsecops-radar --wizard
> 
```

---

## 📦 التثبيت

<details>
<summary><b>عرض جميع خيارات التثبيت (PyPI, Docker, الكود المصدري)</b></summary>
<br>

### الخيار 1 — PyPI (موصى به)
```bash
pip install devsecops-radar
```

### الخيار 2 — من المصدر
```bash
git clone [https://github.com/Mehrdoost/devsecops-radar.git](https://github.com/Mehrdoost/devsecops-radar.git)
cd devsecops-radar
pip install -e ".[dev]"
```

### الخيار 3 — Docker
```bash
docker pull ghcr.io/mehrdoost/devsecops-radar:latest
docker run -p 8080:8080 ghcr.io/mehrdoost/devsecops-radar:latest
```
**ربط ملف النتائج الخاص بك:**
```bash
docker run -p 8080:8080 -v $(pwd)/findings.json:/data/findings.json ghcr.io/mehrdoost/devsecops-radar:latest
```

### 🧙 التثبيت بأمر واحد (curl)
```bash
curl -fsSL [https://raw.githubusercontent.com/Mehrdoost/devsecops-radar/main/install.sh](https://raw.githubusercontent.com/Mehrdoost/devsecops-radar/main/install.sh) | bash
```

</details>

---

## 📋 المتطلبات الأساسية

> [!IMPORTANT]
> يعتمد Pipeline Sentinel على أدوات الأمان الخارجية لإنتاج تقارير JSON. يجب عليك تثبيت هذه الأدوات بشكل منفصل.

- **مطلوب للفحص دون اتصال:** Trivy, Semgrep, Poutine, Zizmor, Gitleaks.
- **اختياري:** Ollama (لتحليل الذكاء الاصطناعي), Docker (لبيئة الرمل), OPA (لسياسة Rego).

---

## 🧭 كيفية الاستخدام (خطوة بخطوة)

<details open>
<summary><b>1. تشغيل ماسحات الأمان الخاصة بك</b></summary>
<br>

توليد مخرجات JSON من أدواتك:
```bash
trivy image --format json -o trivy.json nginx:latest
semgrep --config=auto --json --output semgrep.json .
poutine scan ./repo --format json --output poutine.json
zizmor scan ./repo --output zizmor.json --format json
gitleaks detect --source . --report-format json --report-path gitleaks.json
```
</details>

<details open>
<summary><b>2. دمج النتائج باستخدام CLI</b></summary>
<br>

```bash
devsecops-radar --trivy trivy.json --semgrep semgrep.json --poutine poutine.json --zizmor zizmor.json --gitleaks gitleaks.json
```
</details>

<details open>
<summary><b>3. عرض لوحة القيادة</b></summary>
<br>

```bash
devsecops-radar-web
```
</details>

<details>
<summary><b>4. تمكين تحليل الذكاء الاصطناعي (اختياري)</b></summary>
<br>

```bash
ollama pull llama3.2:latest
devsecops-radar --trivy trivy.json --analyze
devsecops-radar-web
```
</details>

<details>
<summary><b>5. المعالجة التلقائية (مع مراجعة بشرية)</b></summary>
<br>

```bash
# تطبيق الإصلاحات تلقائيًا
devsecops-radar --trivy trivy.json --analyze --fix

# مراجعة تفاعلية خطوة بخطوة
devsecops-radar --trivy trivy.json --analyze --fix --review
```
> [!NOTE]
> *يتم نسخ جميع الملفات المعدلة احتياطيًا إلى `~/.devsecops-radar/backups/`. الأداة تقوم بإنشاء فرع git جديد.*
</details>

---

## 📋 مرجع الأوامر الكامل

<details open>
<summary><b>انقر لتوسيع فئات الأوامر</b></summary>
<br>

### 🔎 الماسحات والمدخلات
| العلامة | الوصف | مثال |
| :--- | :--- | :--- |
| `--trivy` | ملف Trivy JSON أو اسم الصورة | `--trivy` <kbd>results.json</kbd> |
| `--semgrep` | ملف Semgrep JSON أو مسار المجلد | `--semgrep` <kbd>./src</kbd> |
| `--poutine` | ملف Poutine JSON أو مسار المستودع | `--poutine` <kbd>./repo</kbd> |
| `--zizmor` | ملف Zizmor JSON أو مسار المستودع | `--zizmor` <kbd>./repo</kbd> |
| `--gitleaks`| ملف Gitleaks JSON أو مسار المستودع | `--gitleaks` <kbd>./repo</kbd> |
| `--rules` | مجلد يحتوي على قواعد JSON المخصصة | `--rules` <kbd>~/my-rules/</kbd> |
| `--topology`| مسار لملف الطوبولوجيا (JSON) | `--topology` <kbd>topology.json</kbd> |

### 🧠 الذكاء الاصطناعي والسياسات
| العلامة | الوصف | مثال |
| :--- | :--- | :--- |
| `--analyze` | تفعيل تحليل LLM غير المتزامن | `--analyze` |
| `--fix` | تطبيق الإصلاحات المقترحة بالذكاء الاصطناعي | `--fix` |
| `--policy` | ملف JSON لسياسة البوابات | `--policy` <kbd>policy.json</kbd> |

### 📊 التقارير والتصدير
| العلامة | الوصف | مثال |
| :--- | :--- | :--- |
| `--report` | إنشاء تقرير PDF/JSON/HTML | `--report` <kbd>report.pdf</kbd> |
| `--export-sarif`| تصدير النتائج بصيغة SARIF | `--export-sarif` <kbd>report.sarif</kbd> |
| `--compliance`| الإطار: `CIS`, `PCI-DSS` | `--compliance` <kbd>CIS</kbd> |

<br>

> [!TIP]
> ### خيارات خادم الويب (`devsecops-radar-web`)
> ```bash
> devsecops-radar-web                       # إطلاق على http://localhost:8080
> FINDINGS_FILE=my.json devsecops-radar-web # استخدام ملف نتائج مخصص
> PIPELINE_API_KEY=secret devsecops-radar-web  # تفعيل مصادقة API
> 
```

</details>

---

## 👨‍💻 المؤلف

**ReverseForge** — ( Mehrdoost And Mi0r4 )  

[![GitHub](https://img.shields.io/badge/GitHub-ReverseForge-181717?style=for-the-badge&logo=github)](https://github.com/ReverseForge) 
[![GitHub](https://img.shields.io/badge/GitHub-Mehrdoost-181717?style=for-the-badge&logo=github)](https://github.com/Mehrdoost) 
[![GitHub](https://img.shields.io/badge/GitHub-miora--sora-181717?style=for-the-badge&logo=github)](https://github.com/miora-sora) 

---

## 📜 الرخصة

MIT — انظر [LICENSE](LICENSE).

<div align="center">
<br>

⭐ **إذا كان هذا المشروع يساعد فريقك في تقديم برامج أكثر أمانًا، فلا تتردد في دعمه بنجمة — إنها تصنع فرقًا حقيقيًا.**

</div>