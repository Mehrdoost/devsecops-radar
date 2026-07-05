// ══════════════════════════════════════════════════════════════════════════════
// § PIPELINE SENTINEL 
// ══════════════════════════════════════════════════════════════════════════════

// ──────────────────────────────────────────────────────────────
//  §A  MATRIX RAIN (Optimized with requestAnimationFrame)
// ──────────────────────────────────────────────────────────────
function initializeMatrixRain() {
    var canvas = document.getElementById("matrix-rain-canvas");
    if (!canvas) return;
    var ctx = canvas.getContext("2d");
    var width = canvas.width = window.innerWidth;
    var height = canvas.height = window.innerHeight;
    var katakana = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789$+-*/=<>_!#%";
    var alphabet = katakana.split("");
    var fontSize = 16;
    var columns = width / fontSize;
    var rainDrops = Array.from({ length: Math.floor(columns) }).fill(1);
    var lastDrawTime = 0;
    var fps = 30;
    var interval = 1000 / fps;

    function draw(timestamp) {
        requestAnimationFrame(draw);
        if (!document.visibilityState || document.visibilityState === 'hidden') return;
        var delta = timestamp - lastDrawTime;
        if (delta < interval) return;
        lastDrawTime = timestamp - (delta % interval);
        ctx.fillStyle = "rgba(3, 5, 9, 0.05)";
        ctx.fillRect(0, 0, width, height);
        var style = getComputedStyle(document.documentElement);
        ctx.fillStyle = style.getPropertyValue("--accent").trim() || "#00F0FF";
        ctx.font = fontSize + "px 'JetBrains Mono', monospace";
        for (var i = 0; i < rainDrops.length; i++) {
            var text = alphabet[Math.floor(Math.random() * alphabet.length)];
            ctx.fillText(text, i * fontSize, rainDrops[i] * fontSize);
            if (rainDrops[i] * fontSize > height && Math.random() > 0.975) {
                rainDrops[i] = 0;
            }
            rainDrops[i]++;
        }
    }
    requestAnimationFrame(draw);

    window.addEventListener("resize", function() {
        width = canvas.width = window.innerWidth;
        height = canvas.height = window.innerHeight;
        columns = width / fontSize;
        rainDrops = Array.from({ length: Math.floor(columns) }).fill(1);
    });
}

// ──────────────────────────────────────────────────────────────
//  §B  BOOT SEQUENCE
// ──────────────────────────────────────────────────────────────
function runBootSequence() {
    var bootOverlay = document.getElementById('boot-sequence');
    var bootText = document.getElementById('boot-text');
    var bootProg = document.getElementById('boot-progress');
    if (!bootOverlay) return;

    var msgs = [
        "[SYS] INITIATING CRYPTO SECURE CONNECTION...",
        "[SYS] LOADING RADAR COMPONENT ENGINE...",
        "[SYS] ESTABLISHING PARSE ENGINE NET...",
        "[SYS] SECURITY SUBSYSTEM ONLINE."
    ];
    var step = 0;

    var bootInt = setInterval(function() {
        if (step < msgs.length) {
            if (bootText) bootText.textContent = msgs[step];
            if (bootProg) bootProg.style.width = ((step + 1) * 25) + "%";
            step++;
        } else {
            clearInterval(bootInt);
            bootOverlay.classList.add('crt-off');
            setTimeout(function() {
                if (bootOverlay.parentNode) bootOverlay.remove();
                onBootComplete();
            }, 600);
        }
    }, 350);
}

function onBootComplete() {
    if (AUTH_TOKEN) {
        document.getElementById('loginModalOverlay').style.display = 'none';
        var dm = document.getElementById('dashboard-main');
        if (dm) dm.style.display = 'block';
        loadDashboardData();
        startLiveFeedInterval();
        loadScannerStatus();
        if (typeof uiAnimator !== 'undefined' && uiAnimator) {
            uiAnimator.entrance();
        }
    } else {
        document.getElementById('loginModalOverlay').style.display = 'flex';
    }
    buildCLIRef();
    updateClock();
}

// ──────────────────────────────────────────────────────────────
//  §C  AUTH HELPERS
// ──────────────────────────────────────────────────────────────
var AUTH_TOKEN = sessionStorage.getItem('ps_token') || null;

function saveToken(token) {
    AUTH_TOKEN = token;
    sessionStorage.setItem('ps_token', token);
}

function clearToken() {
    AUTH_TOKEN = null;
    sessionStorage.removeItem('ps_token');
}

function getHeaders() {
    return AUTH_TOKEN ? { 'Authorization': 'Bearer ' + AUTH_TOKEN } : {};
}

var _reloginInProgress = false;

function fetchWithAuth(url, options) {
    if (!options) options = {};
    var headers = Object.assign({}, options.headers, getHeaders());
    var opts = Object.assign({}, options, { headers: headers });
    return fetch(url, opts).then(function(resp) {
        if (resp.status === 401 && !_reloginInProgress) {
            _reloginInProgress = true;
            clearToken();
            showToast('Session expired. Please log in again.', 'warning');
            document.getElementById('loginModalOverlay').style.display = 'flex';
            document.getElementById('loginPassword').value = '';
            document.getElementById('loginError').style.display = 'none';
            setTimeout(function() { _reloginInProgress = false; }, 2000);
            throw new Error('Unauthorized');
        }
        return resp;
    });
}

function forceReLogin() {
    stopLiveFeedInterval();
    clearToken();
    document.getElementById('loginModalOverlay').style.display = 'flex';
    document.getElementById('loginPassword').value = '';
    document.getElementById('loginError').style.display = 'none';
    document.getElementById('tableBody').innerHTML = '';
    document.querySelectorAll('#stats-row span[id^="stat-"]').forEach(function(el) {
        el.textContent = '0';
    });
    document.getElementById('policy-status-text').textContent = '—';
    if (severityChartInstance) severityChartInstance.dispose();
    if (trendChartInstance && !isTrend3D) trendChartInstance.dispose();
    
    if (typeof active3DScenes !== 'undefined') {
        active3DScenes.forEach(function(s) {
            if(s.animId) cancelAnimationFrame(s.animId);
            if(s.renderer) s.renderer.dispose();
        });
        active3DScenes = [];
    }

    document.getElementById('attack-graph').innerHTML = '';
    document.getElementById('topology-graph').innerHTML = '';
    document.getElementById('trendChart').innerHTML = '';
    
    document.getElementById('exec-summary').textContent = 'No AI analysis available. Run with --analyze.';
    document.getElementById('live-feed-container').innerHTML = '<p class="text-muted" style="font-family:monospace;">Waiting for CI/CD data...</p>';
    document.getElementById('scanner-status-container').innerHTML = '<p class="text-muted" style="font-family: monospace;">Loading...</p>';
    var remPanel = document.getElementById('remediation-panel');
    if (remPanel) remPanel.style.display = 'none';
    var topoRow = document.getElementById('topology-row');
    if (topoRow) topoRow.style.display = 'none';
    document.getElementById('ai-history-select').style.display = 'none';
    document.getElementById('ai-history-select').innerHTML = '<option value="">Latest analysis</option>';
    updateRagIndicator(false);
    
    var dm = document.getElementById('dashboard-main');
    if (dm) dm.style.display = 'none';
}

function logout() {
    if (typeof audioSynth !== 'undefined' && audioSynth) audioSynth.play('click');
    forceReLogin();
    showToast('Logged out successfully.', 'success');
}

function showLoginError(msg) {
    var errEl = document.getElementById('loginError');
    if (errEl) {
        errEl.textContent = msg;
        errEl.style.display = 'block';
    }
}

async function performLogin(password) {
    var btn = document.getElementById('loginBtn');
    var spinner = document.getElementById('loginSpinner');
    if (btn) btn.disabled = true;
    if (spinner) spinner.classList.remove('d-none');
    try {
        var resp = await fetch('/api/auth/login', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ password: password })
        });
        var data = await resp.json();
        if (resp.ok && data.token) {
            saveToken(data.token);
            if (typeof audioSynth !== 'undefined' && audioSynth) {
                audioSynth.play('loginSuccess');
            }
            var overlay = document.getElementById('loginModalOverlay');
            var dm = document.getElementById('dashboard-main');
            if (typeof uiAnimator !== 'undefined' && uiAnimator) {
                uiAnimator.airlockOpen(overlay, dm, function() {
                    loadDashboardData();
                    startLiveFeedInterval();
                    loadScannerStatus();
                });
            } else {
                overlay.style.display = 'none';
                if (dm) dm.style.display = 'block';
                loadDashboardData();
                startLiveFeedInterval();
                loadScannerStatus();
            }
        } else {
            showLoginError(data.error || 'Authentication failed');
            if (typeof audioSynth !== 'undefined' && audioSynth) {
                audioSynth.play('error');
            }
        }
    } catch (e) {
        showLoginError('Network error – please try again.');
        if (typeof audioSynth !== 'undefined' && audioSynth) {
            audioSynth.play('error');
        }
    } finally {
        if (btn) btn.disabled = false;
        if (spinner) spinner.classList.add('d-none');
    }
}

function escapeHtml(text) {
    if (!text) return '';
    var div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

// ──────────────────────────────────────────────────────────────
//  §D  I18N DICTIONARY & CYBER PROVERBS
// ──────────────────────────────────────────────────────────────
var T = {
    en: {
        critical: "CRITICAL", high: "HIGH", medium: "MEDIUM", low: "LOW",
        policy: "POLICY", severity_breakdown: "Severity Breakdown",
        trend_over_time: "Trend Over Time", attack_paths: "Attack Paths (AI)",
        simulate_selected: "Simulate Selected", findings: "Findings",
        tool: "Tool", id_col: "ID", severity: "Severity",
        target: "Target", description: "Description", close: "Close",
        attack_simulation: "Attack Simulation",
        search_placeholder: "Search findings...",
        simulating: "Simulating attack chain...",
        no_ai: "Run with --analyze", generate_report: "Report",
        clear_filters: "Clear Filters", ai_summary: "AI Executive Summary",
        report_loading: "Generating...", report_success: "Report downloaded!",
        report_failed: "Report generation failed.",
        cli_ref_title: "CLI Quick Reference", show_hide: "Show", hide: "Hide",
        trivy_desc: "Trivy JSON file or image name",
        semgrep_desc: "Semgrep JSON file or target directory",
        poutine_desc: "Poutine JSON file or repository path",
        zizmor_desc: "Zizmor JSON file or repository path",
        gitleaks_desc: "Gitleaks JSON file or repository path",
        rules_desc: "Directory with custom JSON rule files",
        policy_desc: "Policy JSON file for gating",
        analyze_desc: "Enable LLM analysis (requires Ollama)",
        fix_desc: "Auto-apply AI-suggested fixes",
        review_desc: "Review each fix before applying",
        report_desc: "Generate PDF report",
        topology_desc: "Path to topology JSON file",
        compliance_desc: "Compliance framework (CIS/PCI-DSS)",
        output_desc: "Output file for merged findings",
        wizard_desc: "Interactive setup wizard",
        llm_backend_desc: "LLM backend", llm_model_desc: "LLM model name",
        rego_policy_desc: "OPA Rego policy file",
        update_rules_desc: "Download/update community rules",
        docker_missing: "Docker not installed.", total: "TOTAL",
        export_title: "Export Security Report",
        export_sub: "Select format for data mapping.",
        pdf_sub: "Executive Presentation", json_sub: "Automation Merges",
        html_sub: "Instant Viewport", download_now: "Download Now",
        prev_page: "◀ Previous", next_page: "Next ▶",
        no_findings: "No findings match your filters.",
        sim_sub: "Executing sandbox PoC environment",
        sim_results: "Simulation Results", sandbox_out: "Sandbox Output:",
        pdf_doc: "PDF Document", json_data: "JSON Dataset",
        html_view: "HTML Engine", simulate_btn: "⚡ Simulate",
        line: "Line", ai_risk_score: "AI Risk Score",
        export_sarif_desc: "Export findings as SARIF",
        export_cdx_desc: "Export findings as CycloneDX",
        notify_jira_desc: "Create Jira issues",
        notify_asana_desc: "Create Asana tasks",
        live_feed: "Live Sentry Feed",
        waiting_data: "Waiting for CI/CD data...",
        scanner_status: "Scanner Status", loading: "Loading...",
        week: "Week", month: "Month", year: "Year", all: "All",
        ai_remediation: "AI Remediation Plan", apply_fix: "Apply Fix",
        topology: "Infrastructure Topology", all_tools: "All Tools",
        all_severities: "All Severities", send_jira: "Send to Jira",
        send_asana: "Send to Asana", auto: "Auto",
        smart_search: "Smart Search", rag_ready: "RAG Ready",
        text_search: "Text Search Only", rag_title: "Semantic Search",
        rag_placeholder: "e.g., leaked secrets in containers",
        rag_search_btn: "Search",
        rag_no_results: "No similar findings found.",
        ai_history: "AI History"
    },
    ru: {
        critical: "КРИТИЧЕСКИЙ", high: "ВЫСОКИЙ", medium: "СРЕДНИЙ", low: "НИЗКИЙ",
        policy: "ПОЛИТИКА", severity_breakdown: "Распределение",
        trend_over_time: "Тренд по времени", attack_paths: "Пути атак (ИИ)",
        simulate_selected: "Симулировать", findings: "Находки",
        tool: "Инструмент", id_col: "ID", severity: "Серьёзность",
        target: "Цель", description: "Описание", close: "Закрыть",
        attack_simulation: "Симуляция атаки", search_placeholder: "Поиск находок...",
        simulating: "Симуляция...", no_ai: "Запустите с --analyze",
        generate_report: "Отчёт", clear_filters: "Сброс",
        ai_summary: "ИИ Сводка", report_loading: "Генерация...",
        report_success: "Отчёт загружен!", report_failed: "Ошибка генерации.",
        cli_ref_title: "Справка CLI", show_hide: "Показать", hide: "Скрыть",
        trivy_desc: "JSON-файл Trivy", semgrep_desc: "JSON-файл Semgrep",
        poutine_desc: "JSON-файл Poutine", zizmor_desc: "JSON-файл Zizmor",
        gitleaks_desc: "JSON-файл Gitleaks", rules_desc: "Директория с JSON-правилами",
        policy_desc: "JSON-файл политики", analyze_desc: "Включить ИИ-анализ",
        fix_desc: "Авто-применение исправлений", review_desc: "Просмотр перед применением",
        report_desc: "Сгенерировать PDF", topology_desc: "Топология",
        compliance_desc: "Комплаенс", output_desc: "Выходной файл",
        wizard_desc: "Мастер настройки", llm_backend_desc: "LLM-бэкенд",
        llm_model_desc: "Модель LLM", rego_policy_desc: "Политика OPA",
        update_rules_desc: "Обновить правила", docker_missing: "Docker не установлен.",
        total: "ВСЕГО", export_title: "Экспорт Отчета",
        export_sub: "Выберите нужный формат.", pdf_sub: "Презентация",
        json_sub: "Интеграция", html_sub: "Браузер", download_now: "Скачать",
        prev_page: "◀ Назад", next_page: "Вперёд ▶",
        no_findings: "Нет находок.", sim_sub: "Запуск песочницы...",
        sim_results: "Результаты", sandbox_out: "Вывод:",
        pdf_doc: "PDF", json_data: "JSON", html_view: "HTML",
        simulate_btn: "⚡ Симулировать", line: "Строка", ai_risk_score: "Риск ИИ",
        export_sarif_desc: "Экспорт в SARIF", export_cdx_desc: "Экспорт в CycloneDX",
        notify_jira_desc: "Задачи Jira", notify_asana_desc: "Задачи Asana",
        live_feed: "Живой поток Sentry", waiting_data: "Ожидание данных...",
        scanner_status: "Статус сканера", loading: "Загрузка...",
        week: "Неделя", month: "Месяц", year: "Год", all: "Все",
        ai_remediation: "ИИ План Устранения", apply_fix: "Применить",
        topology: "Топология", all_tools: "Все Инструменты",
        all_severities: "Любая Серьёзность", send_jira: "В Jira",
        send_asana: "В Asana", auto: "Авто", smart_search: "Умный Поиск",
        rag_ready: "RAG Готов", text_search: "Текстовый Поиск",
        rag_title: "Семантический Поиск", rag_placeholder: "поиск...",
        rag_search_btn: "Поиск", rag_no_results: "Не найдено.",
        ai_history: "История ИИ"
    },
    zh: {
        critical: "严重", high: "高", medium: "中", low: "低",
        policy: "策略", severity_breakdown: "严重性分布",
        trend_over_time: "时间趋势", attack_paths: "攻击路径 (AI)",
        simulate_selected: "模拟选中", findings: "发现", tool: "工具", id_col: "编号",
        severity: "严重性", target: "目标", description: "描述", close: "关闭",
        attack_simulation: "攻击模拟", search_placeholder: "搜索发现...",
        simulating: "正在模拟...", no_ai: "使用 --analyze",
        generate_report: "报告", clear_filters: "清除", ai_summary: "AI摘要",
        report_loading: "生成中...", report_success: "成功！", report_failed: "失败。",
        cli_ref_title: "CLI 快速参考", show_hide: "显示", hide: "隐藏",
        trivy_desc: "Trivy 文件", semgrep_desc: "Semgrep 文件",
        poutine_desc: "Poutine 文件", zizmor_desc: "Zizmor 文件",
        gitleaks_desc: "Gitleaks 文件", rules_desc: "自定义规则",
        policy_desc: "策略文件", analyze_desc: "启用 LLM 分析",
        fix_desc: "自动修复", review_desc: "检查修复", report_desc: "生成 PDF",
        topology_desc: "拓扑 JSON", compliance_desc: "合规", output_desc: "输出文件",
        wizard_desc: "设置向导", llm_backend_desc: "LLM 后端", llm_model_desc: "LLM 模型",
        rego_policy_desc: "OPA 策略", update_rules_desc: "下载规则",
        docker_missing: "未安装 Docker。", total: "总计",
        export_title: "导出报告", export_sub: "选择格式。",
        pdf_sub: "简报", json_sub: "集成", html_sub: "网页端", download_now: "立即下载",
        prev_page: "◀ 上一页", next_page: "下一页 ▶", no_findings: "没有发现。",
        sim_sub: "执行沙盒", sim_results: "结果", sandbox_out: "输出:",
        pdf_doc: "PDF", json_data: "JSON", html_view: "HTML",
        simulate_btn: "⚡ 模拟", line: "行", ai_risk_score: "AI 评分",
        export_sarif_desc: "导出 SARIF", export_cdx_desc: "导出 CycloneDX",
        notify_jira_desc: "Jira 任务", notify_asana_desc: "Asana 任务",
        live_feed: "Sentry 数据流", waiting_data: "等待数据...",
        scanner_status: "扫描器状态", loading: "加载中...",
        week: "周", month: "月", year: "年", all: "全部",
        ai_remediation: "修复计划", apply_fix: "应用", topology: "拓扑",
        all_tools: "所有工具", all_severities: "所有严重级别",
        send_jira: "Jira", send_asana: "Asana", auto: "自动",
        smart_search: "智能搜索", rag_ready: "RAG 就绪", text_search: "文本搜索",
        rag_title: "语义搜索", rag_placeholder: "例如，秘钥泄露",
        rag_search_btn: "搜索", rag_no_results: "未找到。", ai_history: "AI 历史"
    },
    ar: {
        critical: "حرج", high: "عالي", medium: "متوسط", low: "منخفض",
        policy: "السياسة", severity_breakdown: "توزيع الخطورة",
        trend_over_time: "مخطط الوقت", attack_paths: "مسارات الهجوم",
        simulate_selected: "محاكاة المحدد", findings: "الثغرات",
        tool: "الأداة", id_col: "المعرف", severity: "الخطورة",
        target: "الهدف", description: "الوصف", close: "إغلاق",
        attack_simulation: "محاكاة", search_placeholder: "البحث...",
        simulating: "جاري المحاكاة...", no_ai: "استخدم --analyze",
        generate_report: "التقرير", clear_filters: "مسح الفلاتر",
        ai_summary: "الملخص", report_loading: "جاري الإنشاء...",
        report_success: "نجاح!", report_failed: "فشل.",
        cli_ref_title: "أوامر CLI", show_hide: "عرض", hide: "إخفاء",
        trivy_desc: "ملف Trivy", semgrep_desc: "ملف Semgrep",
        poutine_desc: "ملف Poutine", zizmor_desc: "ملف Zizmor",
        gitleaks_desc: "ملف Gitleaks", rules_desc: "قواعد JSON",
        policy_desc: "قواعد Policy", analyze_desc: "تحليل LLM",
        fix_desc: "تطبيق الإصلاحات", review_desc: "مراجعة",
        report_desc: "إنشاء PDF", topology_desc: "ملف Topology",
        compliance_desc: "إطار الامتثال", output_desc: "ملف الدمج",
        wizard_desc: "معالج الإعداد", llm_backend_desc: "محرك الذكاء",
        llm_model_desc: "النموذج", rego_policy_desc: "ملف OPA",
        update_rules_desc: "تحديث القواعد", docker_missing: "Docker غير مثبت.",
        total: "الإجمالي", export_title: "تصدير التقرير",
        export_sub: "حدد التنسيق.", pdf_sub: "عرض تقديمي",
        json_sub: "أتمتة", html_sub: "معاينة", download_now: "تحميل",
        prev_page: "◀ السابق", next_page: "التالي ▶",
        no_findings: "لا توجد ثغرات.", sim_sub: "بيئة إثبات المفهوم",
        sim_results: "النتائج", sandbox_out: "المخرجات:",
        pdf_doc: "PDF", json_data: "JSON", html_view: "HTML",
        simulate_btn: "⚡ محاكاة", line: "سطر", ai_risk_score: "مخاطر AI",
        export_sarif_desc: "تصدير SARIF", export_cdx_desc: "تصدير CycloneDX",
        notify_jira_desc: "تذاكر Jira", notify_asana_desc: "مهام Asana",
        live_feed: "بث Sentry", waiting_data: "بانتظار البيانات...",
        scanner_status: "حالة الماسح", loading: "جاري التحميل...",
        week: "أسبوع", month: "شهر", year: "سنة", all: "الكل",
        ai_remediation: "خطة العلاج", apply_fix: "تطبيق",
        topology: "طوبولوجيا", all_tools: "جميع الأدوات",
        all_severities: "جميع مستويات الخطورة", send_jira: "إلى Jira",
        send_asana: "إلى Asana", auto: "تلقائي", smart_search: "بحث ذكي",
        rag_ready: "RAG جاهز", text_search: "بحث نصي",
        rag_title: "بحث دلالي", rag_placeholder: "بحث...",
        rag_search_btn: "بحث", rag_no_results: "لم يتم العثور على نتائج.",
        ai_history: "سجل AI"
    }
};

var CL = localStorage.getItem('pipeline-lang') || 'en';

var langCodes = {
    en: 'EN',
    ru: 'RU',
    zh: 'ZH',
    ar: 'AR'
};

var cyberProverbs = {
    en: "Trust, but verify.",
    ru: "Тише едешь, дальше будешь.",
    zh: "居安思危.",
    ar: "درهم وقاية خير من قنطار علاج."
};

function updateLanguageBadge(lang) {
    var badge = document.getElementById('lang-badge');
    if (badge) {
        var code = langCodes[lang] || 'EN';
        if (badge.textContent !== code) {
            badge.classList.add('flipping');
            badge.textContent = code;
            setTimeout(function() { badge.classList.remove('flipping'); }, 600);
        }
    }
    var provEl = document.getElementById('cyber-proverb');
    if (provEl) {
        var txt = cyberProverbs[lang] || cyberProverbs.en;
        typeWriter(provEl, txt, 40);
    }
}

function switchLanguage(l) {
    CL = l;
    localStorage.setItem('pipeline-lang', l);
    document.documentElement.lang = l;
    document.documentElement.dir = (l === 'ar') ? 'rtl' : 'ltr';
    document.body.style.textAlign = (l === 'ar') ? 'right' : 'left';

    document.querySelectorAll('[data-i18n]').forEach(function(el) {
        var k = el.getAttribute('data-i18n');
        if (T[CL] && T[CL][k]) {
            el.textContent = T[CL][k];
        }
    });

    document.querySelectorAll('[data-i18n-placeholder]').forEach(function(el) {
        var k = el.getAttribute('data-i18n-placeholder');
        if (T[CL] && T[CL][k]) {
            el.placeholder = T[CL][k];
        }
    });

    updateLanguageBadge(l);
    var iconEl = document.getElementById('current-lang-icon');
    if (iconEl) iconEl.textContent = langCodes[l] || 'EN';

    var langMenu = document.getElementById('langMenu');
    if (langMenu) langMenu.classList.remove('open');

    buildCLIRef();
    updatePaginationInfo();
    renderTable();
    updateClock();

    var toolSelect = document.getElementById('filter-tool');
    if (toolSelect && toolSelect.options.length > 0) {
        toolSelect.options[0].textContent = T[CL]?.all_tools || 'All Tools';
    }
    var sevSelect = document.getElementById('filter-severity');
    if (sevSelect && sevSelect.options.length > 0) {
        sevSelect.options[0].textContent = T[CL]?.all_severities || 'All Severities';
    }
    if (typeof lastCounts !== 'undefined' && lastCounts) {
        createSeverityChart(lastCounts);
    }
}

function toggleLangMenu() {
    var menu = document.getElementById('langMenu');
    if (menu) menu.classList.toggle('open');
}
// ──────────────────────────────────────────────────────────────
//  §E  TILT CARDS
// ──────────────────────────────────────────────────────────────
function initTiltCards() {
    document.querySelectorAll('.tilt-card').forEach(function(card) {
        var ticking = false;
        card.addEventListener('mousemove', function(e) {
            if (!ticking) {
                window.requestAnimationFrame(function() {
                    var rect = card.getBoundingClientRect();
                    var x = e.clientX - rect.left;
                    var y = e.clientY - rect.top;
                    var centerX = rect.width / 2;
                    var centerY = rect.height / 2;
                    var rotateX = ((y - centerY) / centerY) * -3;
                    var rotateY = ((x - centerX) / centerX) * 3;
                    card.style.transform = 'perspective(1000px) rotateX(' + rotateX + 'deg) rotateY(' + rotateY + 'deg) scale3d(1.01, 1.01, 1.01)';
                    card.style.setProperty('--mouse-x', x + 'px');
                    card.style.setProperty('--mouse-y', y + 'px');
                    ticking = false;
                });
                ticking = true;
            }
        });
        card.addEventListener('mouseleave', function() {
            card.style.transform = 'perspective(1000px) rotateX(0deg) rotateY(0deg) scale3d(1, 1, 1)';
            card.style.setProperty('--mouse-x', '50%');
            card.style.setProperty('--mouse-y', '50%');
        });
    });
}

// ──────────────────────────────────────────────────────────────
//  §F  PARTICLES
// ──────────────────────────────────────────────────────────────
function initParticles() {
    var c = document.getElementById('particles-canvas');
    if (!c) return;
    var ctx = c.getContext('2d');
    var width = c.width = window.innerWidth;
    var height = c.height = window.innerHeight;
    var style = getComputedStyle(document.documentElement);
    var col = style.getPropertyValue('--particle-color').trim() || 'rgba(0, 240, 255, 0.15)';

    var particles = Array.from({ length: 60 }, function() {
        return {
            x: Math.random() * width,
            y: Math.random() * height,
            r: Math.random() * 2 + 0.5,
            dx: (Math.random() - 0.5) * 0.4,
            dy: (Math.random() - 0.5) * 0.4,
            alpha: Math.random(),
            alphaDir: 0.008
        };
    });

    var lastDrawTime = 0;

    function anim(timestamp) {
        requestAnimationFrame(anim);
        if (document.visibilityState === 'hidden') return;
        if (timestamp - lastDrawTime < 16) return;
        lastDrawTime = timestamp;

        ctx.clearRect(0, 0, width, height);

        for (var p = 0; p < particles.length; p++) {
            var particle = particles[p];
            particle.x += particle.dx;
            particle.y += particle.dy;
            if (particle.x < 0 || particle.x > width) particle.dx *= -1;
            if (particle.y < 0 || particle.y > height) particle.dy *= -1;
            particle.alpha += particle.alphaDir;
            if (particle.alpha <= 0.1 || particle.alpha >= 0.7) particle.alphaDir *= -1;

            ctx.beginPath();
            ctx.arc(particle.x, particle.y, particle.r, 0, Math.PI * 2);
            ctx.fillStyle = col.replace(/0\.\d+/, particle.alpha.toFixed(2));
            ctx.fill();
        }

        for (var i = 0; i < particles.length; i++) {
            for (var j = i + 1; j < particles.length; j++) {
                var dx = particles[i].x - particles[j].x;
                var dy = particles[i].y - particles[j].y;
                var distSq = (dx * dx) + (dy * dy);
                if (distSq < 12100) {
                    ctx.beginPath();
                    ctx.moveTo(particles[i].x, particles[i].y);
                    ctx.lineTo(particles[j].x, particles[j].y);
                    ctx.strokeStyle = col.replace(/0\.\d+/, '0.04');
                    ctx.stroke();
                }
            }
        }
    }
    requestAnimationFrame(anim);

    window.addEventListener("resize", function() {
        width = c.width = window.innerWidth;
        height = c.height = window.innerHeight;
    });
}

// ──────────────────────────────────────────────────────────────
//  §G  CLOCK & UTILS
// ──────────────────────────────────────────────────────────────
function updateClock() {
    var now = new Date();
    var options = {
        weekday: 'short',
        month: 'short',
        day: 'numeric',
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit',
        hour12: false
    };
    var timeStr = now.toLocaleString(undefined, options).replace(',', ' \u00B7');
    var el = document.getElementById('clock-text');
    if (el) el.textContent = timeStr;
}
setInterval(updateClock, 1000);

function animateCounter(el, target) {
    var dur = 1500;
    var start = performance.now();
    function tick(now) {
        var p = Math.min((now - start) / dur, 1);
        var v = 1 - Math.pow(1 - p, 4);
        el.textContent = Math.round(v * target);
        if (p < 1) requestAnimationFrame(tick);
    }
    requestAnimationFrame(tick);
}

function typeWriter(el, text, speed) {
    if (speed === undefined) speed = 12;
    el.textContent = '';
    el.classList.add('typewriter-cursor');
    var i = 0;
    function type() {
        if (i < text.length) {
            el.textContent += text.charAt(i);
            i++;
            setTimeout(type, speed);
        } else {
            el.classList.remove('typewriter-cursor');
        }
    }
    type();
}

function showToast(message, type) {
    if (type === undefined) type = 'info';
    var container = document.getElementById('toast-container');
    if (!container) return;
    var toastEl = document.createElement('div');
    toastEl.className = 'toast align-items-center text-bg-' + type + ' border-0 shadow-lg';
    toastEl.style.borderRadius = '12px';
    toastEl.setAttribute('role', 'alert');
    toastEl.innerHTML = '<div class="d-flex"><div class="toast-body fw-bold px-4 py-3" style="font-size:0.95rem;">' + escapeHtml(message) + '</div><button type="button" class="btn-close btn-close-white mx-3 m-auto" data-bs-dismiss="toast"></button></div>';
    container.appendChild(toastEl);
    var toast = new bootstrap.Toast(toastEl, { delay: 4000 });
    toast.show();
    toastEl.addEventListener('hidden.bs.toast', function() {
        toastEl.remove();
    });
}

// ──────────────────────────────────────────────────────────────
//  §H  CLI REFERENCE & ROBUST ACCORDION FIX
// ──────────────────────────────────────────────────────────────
function buildCLIRef() {
    var flags = [
        { flag: '--trivy', desc: 'trivy_desc', icon: '\u{1F433}' },
        { flag: '--semgrep', desc: 'semgrep_desc', icon: '\u{1F50D}' },
        { flag: '--poutine', desc: 'poutine_desc', icon: '\u{1F98A}' },
        { flag: '--zizmor', desc: 'zizmor_desc', icon: '\u26A1' },
        { flag: '--gitleaks', desc: 'gitleaks_desc', icon: '\u{1F511}' },
        { flag: '--rules', desc: 'rules_desc', icon: '\u{1F4C1}' },
        { flag: '--output', desc: 'output_desc', icon: '\u{1F4BE}' },
        { flag: '--policy', desc: 'policy_desc', icon: '\u{1F6E1}\uFE0F' },
        { flag: '--rego-policy', desc: 'rego_policy_desc', icon: '\u{1F4DC}' },
        { flag: '--analyze', desc: 'analyze_desc', icon: '\u{1F9E0}' },
        { flag: '--llm-backend', desc: 'llm_backend_desc', icon: '\u2699\uFE0F' },
        { flag: '--llm-model', desc: 'llm_model_desc', icon: '\u{1F916}' },
        { flag: '--fix', desc: 'fix_desc', icon: '\u{1F527}' },
        { flag: '--review', desc: 'review_desc', icon: '\u{1F441}\uFE0F' },
        { flag: '--report', desc: 'report_desc', icon: '\u{1F4C4}' },
        { flag: '--export-sarif', desc: 'export_sarif_desc', icon: '\u{1F4E4}' },
        { flag: '--export-cyclonedx', desc: 'export_cdx_desc', icon: '\u{1F4E6}' },
        { flag: '--topology', desc: 'topology_desc', icon: '\u{1F5FA}\uFE0F' },
        { flag: '--compliance', desc: 'compliance_desc', icon: '\u2705' },
        { flag: '--notify-jira', desc: 'notify_jira_desc', icon: '\u{1F3AB}' },
        { flag: '--notify-asana', desc: 'notify_asana_desc', icon: '\u{1F4CB}' },
        { flag: '--wizard', desc: 'wizard_desc', icon: '\u{1F9D9}' },
        { flag: '--update-rules', desc: 'update_rules_desc', icon: '\u{1F504}' }
    ];
    var container = document.getElementById('cli-ref-cards');
    if (!container) return;
    container.innerHTML = '';
    flags.forEach(function(f) {
        var col = document.createElement('div');
        col.className = 'col-md-6 col-lg-4 col-xl-3';
        var descText = (T[CL] && T[CL][f.desc]) ? T[CL][f.desc] : f.desc;
        col.innerHTML = '<div class="cli-flag-card"><div class="flag-icon" aria-hidden="true" style="font-size: 1.5rem;">' + escapeHtml(f.icon) + '</div><div><code>' + escapeHtml(f.flag) + '</code><div class="flag-desc">' + escapeHtml(descText) + '</div></div></div>';
        container.appendChild(col);
    });
}

function toggleCLI() {
    var body = document.getElementById('cli-ref-body');
    var toggle = document.getElementById('cli-toggle');
    if (!body || !toggle) return;
    
    if (body.classList.contains('show')) {
        body.classList.remove('show');
        toggle.classList.remove('expanded');
        toggle.querySelector('.arrow').style.transform = 'rotate(0deg)';
        var spanHide = toggle.querySelector('[data-i18n="show_hide"]');
        if (spanHide) spanHide.textContent = T[CL]?.show_hide || 'Show';
    } else {
        body.classList.add('show');
        toggle.classList.add('expanded');
        toggle.querySelector('.arrow').style.transform = 'rotate(90deg)';
        var spanShow = toggle.querySelector('[data-i18n="show_hide"]');
        if (spanShow) spanShow.textContent = T[CL]?.hide || 'Hide';
    }
}

// ──────────────────────────────────────────────────────────────
//  §I  SIMULATION LOGIC (WITH SMART DOCKER ERROR CATCHING)
// ──────────────────────────────────────────────────────────────
async function simulateAttack(ids) {
    var overlay = document.getElementById('simOverlay');
    var terminal = document.getElementById('sim-terminal');
    var output = document.getElementById('sim-output');
    if (!overlay || !terminal || !ids || ids.length === 0) return;

    overlay.classList.add('open');
    terminal.textContent = '';
    output.textContent = '';
    if (typeof audioSynth !== 'undefined' && audioSynth) audioSynth.play('click');

    var lines = [
        '> pipeline-sentinel simulate --targets ' + ids.length + ' finding(s)',
        '> Initializing sandbox environment...',
        '> Loading exploit modules...',
        '> Targeting: ' + ids.slice(0,3).join(', ') + (ids.length > 3 ? '...' : ''),
        '> Compiling proof-of-concept...',
        '> Executing attack chain...',
        '> [\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588] 100%',
        '> Analyzing results...'
    ];

    function typeNext(index) {
        if (index < lines.length) {
            terminal.textContent += lines[index] + '\n';
            terminal.scrollTop = terminal.scrollHeight;
            setTimeout(function() { typeNext(index + 1); }, 400);
        } else {
            fetchWithAuth('/api/simulate', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ finding_ids: ids })
            }).then(function(r) { return r.json(); }).then(function(data) {
                terminal.textContent += '\n> Simulation complete.\n';
                
                // Advanced catch for Docker missing 
                if (data.error && data.error.toLowerCase().includes('docker')) {
                    terminal.innerHTML += '<span style="color:var(--danger); text-shadow: 0 0 10px var(--critical-glow); font-weight:bold;">\n[!] FATAL ERROR: DOCKER ENGINE NOT DETECTED.\n[!] Sandbox execution requires Docker daemon to be running.</span>\n';
                    var glitchEl = document.getElementById('glitch-overlay');
                    if (glitchEl) {
                        glitchEl.classList.add('active');
                        setTimeout(function() { glitchEl.classList.remove('active'); }, 600);
                    }
                    if (typeof audioSynth !== 'undefined' && audioSynth) audioSynth.play('error');
                } else if (data.script) {
                    output.textContent = '[Script]\n' + data.script + '\n\n[Sandbox Output]\n' + (data.sandbox_output || 'No output');
                } else if (data.error) {
                    terminal.innerHTML += '<span style="color:var(--danger);">' + escapeHtml(data.error) + '</span>\n';
                }
            }).catch(function() {
                terminal.textContent += '\n> Simulation failed.\n';
            });
        }
    }
    typeNext(0);
}

function runSimulation(ids) {
    if (!ids) {
        ids = Array.from(selectedFindings);
    }
    if (!ids || ids.length === 0) {
        showToast('Select at least one finding to simulate.', 'warning');
        return;
    }
    simulateAttack(ids);
}

// ──────────────────────────────────────────────────────────────
//  §J  REMEDIATION (Enhanced with Apply Fix buttons)
// ──────────────────────────────────────────────────────────────
function showRemediationFromSummary(summary) {
    var panel = document.getElementById('remediation-panel');
    var content = document.getElementById('remediation-content');
    var eq = document.getElementById('remediation-equalizer');
    var fixBtn = document.getElementById('apply-fix-btn');
    if (!panel || !content) return;
    panel.style.display = 'block';
    content.innerHTML = '';
    if (eq) eq.style.display = 'flex';
    if (fixBtn) fixBtn.style.display = 'none';

    if (summary && summary.top_remediations && summary.top_remediations.length > 0) {
        var html = '';
        summary.top_remediations.forEach(function(rem) {
            var fid = escapeHtml(rem.finding_id || '');
            var patch = rem.patch_content || '';
            html += '<div class="d-flex justify-content-between align-items-start mb-3">';
            html += '<div>';
            html += '<p><strong style="color:var(--accent);">' + fid + '</strong>: ' + escapeHtml(rem.title || '') + '</p>';
            if (rem.remediation_steps && rem.remediation_steps.length) {
                html += '<ul>';
                rem.remediation_steps.forEach(function(step) {
                    html += '<li>' + escapeHtml(step) + '</li>';
                });
                html += '</ul>';
            }
            html += '</div>';
            if (patch) {
                html += '<button class="btn-hud btn-success-hud remediation-fix-btn" data-finding-id="' + fid + '" data-patch-content="' + escapeHtml(patch) + '" style="flex-shrink:0; margin-left:12px;">🔧 Apply Fix</button>';
            }
            html += '</div>';
        });
        content.innerHTML = html;

        // Bind click handlers for Apply Fix buttons
        content.querySelectorAll('.remediation-fix-btn').forEach(function(btn) {
            btn.addEventListener('click', function(e) {
                e.stopPropagation();
                var findingId = this.getAttribute('data-finding-id');
                var patchContent = this.getAttribute('data-patch-content');
                applyRemediation(findingId, patchContent);
            });
        });
    } else {
        content.textContent = 'No remediation available for this finding.';
    }
    if (eq) setTimeout(function() { eq.style.display = 'none'; }, 1000);
}

function applyRemediation(findingId, patchContent) {
    if (!findingId || !patchContent) {
        showToast('Missing finding ID or patch content.', 'warning');
        return;
    }
    fetchWithAuth('/api/apply-fix', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ finding_id: findingId, patch_content: patchContent })
    }).then(function(r) { return r.json(); }).then(function(data) {
        if (data.status === 'applied') {
            showToast('Fix applied successfully!', 'success');
        } else {
            showToast(data.error || 'Failed to apply fix.', 'danger');
        }
    }).catch(function() {
        showToast('Network error while applying fix.', 'danger');
    });
}

// ──────────────────────────────────────────────────────────────
//  §K  FINDINGS TABLE & FILTERS & PAGINATION
// ──────────────────────────────────────────────────────────────
var allFindings = []; var filteredFindings = []; var selectedFindings = new Set();
var currentSeverityFilter = null; var currentPage = 1; var itemsPerPage = 8; var latestAiSummary = {};

function truncate(t, m) { if (!t) return t; return (t.length > m) ? t.substring(0, m) + '...' : t; }
function severityColor(s) { switch (s.toUpperCase()) { case 'CRITICAL': return 'danger'; case 'HIGH': return 'warning text-dark'; case 'MEDIUM': return 'info text-dark'; case 'LOW': return 'success'; default: return 'secondary'; } }

function renderTable() {
    var tb = document.getElementById('tableBody');
    if (!tb) return;
    tb.innerHTML = '';
    if (filteredFindings.length === 0) {
        var msg = T[CL]?.no_findings || 'No findings match your filters.';
        tb.innerHTML = '<tr><td colspan="6" class="text-center py-5 text-muted fw-bold" style="font-size:1.2rem; font-family:var(--font-mono); background-color: transparent !important; border:none;">' + escapeHtml(msg) + '</td></tr>';
        updatePaginationInfo(); return;
    }
    var startIndex = (currentPage - 1) * itemsPerPage;
    var endIndex = Math.min(startIndex + itemsPerPage, filteredFindings.length);
    var pageItems = filteredFindings.slice(startIndex, endIndex);
    var fragment = document.createDocumentFragment();
    var idLbl = T[CL]?.id_col || 'ID'; var sevLbl = T[CL]?.severity || 'Severity'; var toolLbl = T[CL]?.tool || 'Tool';
    var targLbl = T[CL]?.target || 'Target'; var lineLbl = T[CL]?.line || 'Line'; var descLbl = T[CL]?.description || 'Description';

    for (var idx = 0; idx < pageItems.length; idx++) {
        var f = pageItems[idx]; var row = document.createElement('tr');
        var isCrit = f.severity && f.severity.toUpperCase() === 'CRITICAL';
        row.className = isCrit ? 'main-table-row finding-critical' : 'main-table-row';
        row.style.willChange = 'opacity, transform';
        row.style.animation = 'feedSlideDown 0.4s cubic-bezier(0.175, 0.885, 0.32, 1.275) forwards ' + (idx * 0.05) + 's';
        row.style.opacity = '0'; row.setAttribute('data-finding-id', f.id);

        var isChecked = selectedFindings.has(f.id) ? 'checked' : ''; var sColor = severityColor(f.severity);
        var rowHtml = '<td style="text-align:center; padding: 20px;"><input type="checkbox" class="finding-checkbox form-check-input" data-id="' + escapeHtml(f.id) + '" ' + isChecked + ' style="width: 1.5em; height: 1.5em; cursor: pointer; box-shadow: inset 0 0 10px rgba(0,0,0,0.5);"></td>';
        rowHtml += '<td class="fw-bold" style="font-family:var(--font-mono); font-size:1.05rem; text-transform:uppercase;">' + escapeHtml(f.tool) + '</td>';
        rowHtml += '<td><code style="color:var(--accent); font-weight:900; font-size:1rem; text-shadow:0 0 15px var(--accent-glow); background:transparent; border:none; padding:0;">' + escapeHtml(f.id) + '</code></td>';
        rowHtml += '<td><span class="badge bg-' + sColor + ' px-3 py-2 rounded-pill shadow-lg" style="font-size: 0.85rem; font-weight:900; letter-spacing:1px; box-shadow: 0 0 15px var(--' + sColor.split(' ')[0] + ');">' + escapeHtml(f.severity) + '</span></td>';
        rowHtml += '<td class="fw-bold text-truncate" style="max-width: 250px; font-size: 0.95rem;">' + escapeHtml(f.target) + '</td>';
        rowHtml += '<td style="color:var(--text-secondary); font-size: 0.95rem; font-weight:500;">' + escapeHtml(truncate(f.description, 80)) + '</td>';
        row.innerHTML = rowHtml;

        var detailRow = document.createElement('tr'); detailRow.className = 'finding-detail-row'; detailRow.style.display = 'none';
        var lineInfo = f.line ? '<strong style="color:var(--accent); font-size: 1.05rem;">' + lineLbl + ':</strong> <span style="font-size: 1.05rem; font-family:var(--font-mono);">' + escapeHtml(String(f.line)) + '</span><br>' : '';
        var detailHtml = '<td colspan="6" style="padding:0; border:none; background:transparent !important;"><div class="finding-detail mx-4 my-3"><div class="row g-4"><div class="col-md-6">';
        detailHtml += '<strong style="color:var(--accent); font-size: 1.05rem;">' + idLbl + ':</strong> <span style="font-size: 1.05rem; font-family:var(--font-mono); font-weight:900; text-shadow:0 0 10px var(--accent-glow);">' + escapeHtml(f.id) + '</span><br>';
        detailHtml += '<strong style="color:var(--accent); font-size: 1.05rem;">' + sevLbl + ':</strong> <span style="font-size: 1.05rem; font-weight:900; color:var(--' + sColor.split(' ')[0] + '); text-shadow:0 0 10px currentColor;">' + escapeHtml(f.severity) + '</span><br>';
        detailHtml += '<strong style="color:var(--accent); font-size: 1.05rem;">' + toolLbl + ':</strong> <span style="font-size: 1.05rem;">' + escapeHtml(f.tool) + '</span><br>' + lineInfo + '</div><div class="col-md-6">';
        detailHtml += '<strong style="color:var(--accent); font-size: 1.05rem;">' + targLbl + ':</strong> <span style="font-size: 1.05rem;">' + escapeHtml(f.target) + '</span><br>';
        detailHtml += '<strong style="color:var(--accent); font-size: 1.05rem;">' + descLbl + ':</strong> <span style="font-size: 0.95rem; color:var(--text-secondary);">' + escapeHtml(f.description) + '</span>';
        detailHtml += '</div></div></div></td>';
        detailRow.innerHTML = detailHtml;

        row.addEventListener('click', (function(detailRowRef) { return function(e) { if (e.target.classList.contains('finding-checkbox')) return; var detail = detailRowRef; var isVisible = detail.style.display !== 'none'; document.querySelectorAll('.finding-detail-row').forEach(function(dr) { dr.style.display = 'none'; }); if (!isVisible) detail.style.display = 'table-row'; }; })(detailRow));
        fragment.appendChild(row); fragment.appendChild(detailRow);
    }
    tb.appendChild(fragment);
    tb.querySelectorAll('.finding-checkbox').forEach(function(cb) {
        cb.addEventListener('change', function(e) { e.stopPropagation(); var id = this.getAttribute('data-id'); if (this.checked) { selectedFindings.add(id); } else { selectedFindings.delete(id); } });
        cb.addEventListener('click', function(e) { e.stopPropagation(); });
    });
    updatePaginationInfo();
}

function applyFilters() {
    var searchVal = (document.getElementById('search-input').value || '').toLowerCase();
    var toolVal = document.getElementById('filter-tool').value;
    var sevVal = document.getElementById('filter-severity').value;
    filteredFindings = allFindings.filter(function(f) {
        if (searchVal) { var haystack = (f.id + ' ' + f.tool + ' ' + f.target + ' ' + f.description).toLowerCase(); if (haystack.indexOf(searchVal) === -1) return false; }
        if (toolVal && f.tool !== toolVal) return false;
        if (sevVal && f.severity !== sevVal) return false;
        return true;
    });
    currentPage = 1; renderTable();
}

function clearFilters() {
    document.getElementById('search-input').value = ''; document.getElementById('filter-tool').value = ''; document.getElementById('filter-severity').value = '';
    currentSeverityFilter = null; filteredFindings = allFindings.slice(); currentPage = 1; renderTable();
}

function updatePaginationInfo() {
    var infoEl = document.getElementById('pagination-info'); var prevBtn = document.getElementById('page-prev'); var nextBtn = document.getElementById('page-next');
    if (!infoEl) return;
    var total = filteredFindings.length; var totalPages = Math.max(1, Math.ceil(total / itemsPerPage));
    var start = total === 0 ? 0 : (currentPage - 1) * itemsPerPage + 1; var end = Math.min(currentPage * itemsPerPage, total);
    infoEl.textContent = start + '\u2013' + end + ' of ' + total;
    if (prevBtn) prevBtn.disabled = currentPage <= 1; if (nextBtn) nextBtn.disabled = currentPage >= totalPages;
}
function prevPage() { if (currentPage > 1) { currentPage--; renderTable(); } }
function nextPage() { var totalPages = Math.ceil(filteredFindings.length / itemsPerPage); if (currentPage < totalPages) { currentPage++; renderTable(); } }

// ──────────────────────────────────────────────────────────────
//  §L  CHARTS (ECharts for Severity & 2D/3D Trend Toggle)
// ──────────────────────────────────────────────────────────────
var severityChartInstance = null;
var trendChartInstance = null;
var lastCounts = null;
var lastScanData = null;
var lastScanLabels = null;
var isTrend3D = false; 
var active3DScenes = []; 

function updateChartColors(chart) {
    if(!chart || !chart.getOption) return;
    var style = getComputedStyle(document.documentElement);
    var textSecondary = style.getPropertyValue('--text-secondary').trim();
    var option = chart.getOption();
    if (option.legend && option.legend[0]) {
        option.legend[0].textStyle = { color: textSecondary };
    }
    if (option.xAxis && option.xAxis.length > 0) {
        option.xAxis[0].axisLabel = { color: textSecondary };
    }
    if (option.yAxis && option.yAxis.length > 0) {
        option.yAxis[0].axisLabel = { color: textSecondary };
        if(option.yAxis[0].splitLine && option.yAxis[0].splitLine.lineStyle) {
            option.yAxis[0].splitLine.lineStyle.color = style.getPropertyValue('--glass-border').trim();
        }
    }
    chart.setOption(option);
}

// ──────────────────────────────────────────────────────────────
//  §T  THEME SYSTEM
// ──────────────────────────────────────────────────────────────
function initThemeSystem() {
    var saved = localStorage.getItem('pipeline-theme') || 'cyber';
    document.documentElement.setAttribute('data-theme', saved);
    document.querySelectorAll('.theme-dot').forEach(function(dot) {
        dot.classList.toggle('active', dot.getAttribute('data-theme') === saved);
    });
    document.querySelectorAll('.theme-dot').forEach(function(dot) {
        dot.addEventListener('click', function() {
            var theme = this.getAttribute('data-theme');
            document.documentElement.setAttribute('data-theme', theme);
            localStorage.setItem('pipeline-theme', theme);
            document.querySelectorAll('.theme-dot').forEach(function(d) { d.classList.remove('active'); });
            this.classList.add('active');
            if (typeof audioSynth !== 'undefined' && audioSynth) audioSynth.play('click');
            if (severityChartInstance) updateChartColors(severityChartInstance);
            if (trendChartInstance && !isTrend3D) updateChartColors(trendChartInstance);
        });
    });
}

function createSeverityChart(counts) {
    lastCounts = counts;
    var dom = document.getElementById('severityChart');
    if (!dom) return;
    if (severityChartInstance) severityChartInstance.dispose();
    severityChartInstance = echarts.init(dom);
    var style = getComputedStyle(document.documentElement);
    var textColor = style.getPropertyValue('--text').trim();
    var bgTertiary = style.getPropertyValue('--bg-tertiary').trim();
    var total = (counts.CRITICAL || 0) + (counts.HIGH || 0) + (counts.MEDIUM || 0) + (counts.LOW || 0);
    
    var tNames = [
        T[CL]?.critical || 'CRITICAL',
        T[CL]?.high || 'HIGH',
        T[CL]?.medium || 'MEDIUM',
        T[CL]?.low || 'LOW'
    ];
    
    var numEl = document.getElementById('chart-total-num');
    if (numEl) animateCounter(numEl, total);

    var option = {
        tooltip: {
            trigger: 'item',
            backgroundColor: bgTertiary,
            borderColor: 'var(--accent)',
            textStyle: { color: textColor },
            padding: 14,
            formatter: function(p) {
                return '<div style="font-weight:900; border-bottom:1px solid var(--glass-border); margin-bottom:8px; padding-bottom:6px;">' + escapeHtml(p.name) + '</div><span style="color:' + escapeHtml(p.color) + '; font-size:1.5rem; vertical-align:middle; filter:drop-shadow(0 0 8px ' + escapeHtml(p.color) + ');">\u25CF</span> <b style="font-size:1.3rem;">' + escapeHtml(String(p.value)) + '</b> <span style="color:var(--text-secondary)">(' + escapeHtml(String(p.percent)) + '%)</span>';
            }
        },
        series: [{
            type: 'pie',
            radius: ['68%', '88%'],
            center: ['50%', '50%'],
            avoidLabelOverlap: false,
            itemStyle: { borderRadius: 12, borderColor: 'var(--bg-primary)', borderWidth: 5 },
            label: { show: false },
            emphasis: { scaleSize: 12, itemStyle: { shadowBlur: 25, shadowColor: 'rgba(0,0,0,0.9)', borderWidth: 0 } },
            data: [
                { value: counts.CRITICAL || 0, name: tNames[0], itemStyle: { color: '#FF003C' } },
                { value: counts.HIGH || 0, name: tNames[1], itemStyle: { color: '#FFB800' } },
                { value: counts.MEDIUM || 0, name: tNames[2], itemStyle: { color: '#00E1FF' } },
                { value: counts.LOW || 0, name: tNames[3], itemStyle: { color: '#00FF9D' } }
            ]
        }]
    };
    severityChartInstance.setOption(option);
}

var currentTrendRange = 'all';

function toggleTrendView() {
    isTrend3D = !isTrend3D;
    var btn = document.getElementById('trend-3d-btn');
    if (btn) {
        btn.style.color = isTrend3D ? 'var(--accent)' : 'var(--text-secondary)';
        btn.style.borderColor = isTrend3D ? 'var(--accent)' : 'transparent';
        btn.style.boxShadow = isTrend3D ? '0 0 10px var(--accent-glow)' : 'none';
    }
    renderTrendChart();
}

function updateTrendRange(range) {
    currentTrendRange = range;
    document.querySelectorAll('.trend-filter-btn').forEach(function(btn) {
        btn.classList.remove('active');
        btn.style.background = 'transparent';
        btn.style.color = 'var(--text-secondary)';
        btn.style.fontWeight = '800';
        btn.style.boxShadow = 'none';
    });
    var activeBtn = document.querySelector('.trend-filter-btn[data-range="' + range + '"]');
    if (activeBtn) {
        activeBtn.classList.add('active');
        activeBtn.style.background = 'var(--accent)';
        activeBtn.style.color = 'var(--bg-primary)';
        activeBtn.style.fontWeight = '900';
        activeBtn.style.boxShadow = '0 0 20px var(--accent-glow)';
    }
    fetchWithAuth('/api/history?range=' + range).then(function(r) {
        return r.json();
    }).then(function(scans) {
        if (scans && scans.length) {
            lastScanLabels = scans.map(function(s) { return s.timestamp ? s.timestamp.substring(0, 10) : ''; });
            lastScanData = scans;
            renderTrendChart();
        } else {
            lastScanLabels = [];
            lastScanData = [];
            renderTrendChart();
        }
    }).catch(function() {
        showToast('Failed to load trend data.', 'warning');
    });
}

function renderTrendChart() {
    cleanup3DScene('trendChart');
    if (trendChartInstance) {
        trendChartInstance.dispose();
        trendChartInstance = null;
    }
    document.getElementById('trendChart').innerHTML = ''; 

    if (!lastScanData || lastScanData.length === 0) return;

    if (isTrend3D) {
        create3DTrendChart(lastScanLabels, lastScanData);
    } else {
        create2DTrendChart(lastScanLabels, lastScanData);
    }
}

function create2DTrendChart(labels, scans) {
    var dom = document.getElementById('trendChart');
    if (!dom) return;
    trendChartInstance = echarts.init(dom);
    var style = getComputedStyle(document.documentElement);
    var textColor = style.getPropertyValue('--text').trim();
    var textSecondary = style.getPropertyValue('--text-secondary').trim();
    var glassBorder = style.getPropertyValue('--glass-border').trim();
    var bgTertiary = style.getPropertyValue('--bg-tertiary').trim();

    var tCritical = T[CL]?.critical || 'CRITICAL';
    var tHigh = T[CL]?.high || 'HIGH';
    var tMedium = T[CL]?.medium || 'MEDIUM';
    var tLow = T[CL]?.low || 'LOW';

    var safeScans = scans.map(function(s) {
        return { critical: Number(s.critical) || 0, high: Number(s.high) || 0, medium: Number(s.medium) || 0, low: Number(s.low) || 0 };
    });

    var option = {
        tooltip: {
            trigger: 'axis', backgroundColor: bgTertiary, borderColor: 'var(--accent)', textStyle: { color: textColor }, padding: 16, borderRadius: 12,
            axisPointer: { type: 'line', lineStyle: { color: 'var(--accent)', type: 'dashed', width: 2, shadowBlur: 10, shadowColor: 'var(--accent)' } }
        },
        legend: { data: [tCritical, tHigh, tMedium, tLow], textStyle: { color: textSecondary, fontWeight: 800, fontSize: 12 }, top: 0, icon: 'circle', itemGap: 25 },
        grid: { left: '2%', right: '4%', bottom: '3%', top: '18%', containLabel: true },
        xAxis: { type: 'category', boundaryGap: false, data: labels, axisLabel: { color: textSecondary, margin: 15, fontWeight: 700, fontSize: 11 }, axisLine: { lineStyle: { color: glassBorder } } },
        yAxis: { type: 'value', axisLabel: { color: textSecondary, fontWeight: 700, fontSize: 11 }, splitLine: { lineStyle: { color: glassBorder, type: 'dashed' } } },
        series: [
            { name: tCritical, type: 'line', data: safeScans.map(function(s) { return s.critical; }), smooth: 0.4, symbol: 'none', lineStyle: { width: 3, shadowBlur: 12, shadowColor: 'rgba(255,0,60,0.6)' }, areaStyle: { color: new echarts.graphic.LinearGradient(0, 0, 0, 1, [{ offset: 0, color: 'rgba(255,0,60,0.4)' }, { offset: 1, color: 'rgba(255,0,60,0.01)' }]) }, itemStyle: { color: '#FF003C' } },
            { name: tHigh, type: 'line', data: safeScans.map(function(s) { return s.high; }), smooth: 0.4, symbol: 'none', lineStyle: { width: 3, shadowBlur: 12, shadowColor: 'rgba(255,184,0,0.6)' }, areaStyle: { color: new echarts.graphic.LinearGradient(0, 0, 0, 1, [{ offset: 0, color: 'rgba(255,184,0,0.4)' }, { offset: 1, color: 'rgba(255,184,0,0.01)' }]) }, itemStyle: { color: '#FFB800' } },
            { name: tMedium, type: 'line', data: safeScans.map(function(s) { return s.medium; }), smooth: 0.4, symbol: 'none', lineStyle: { width: 3, shadowBlur: 12, shadowColor: 'rgba(0,225,255,0.6)' }, areaStyle: { color: new echarts.graphic.LinearGradient(0, 0, 0, 1, [{ offset: 0, color: 'rgba(0,225,255,0.4)' }, { offset: 1, color: 'rgba(0,225,255,0.01)' }]) }, itemStyle: { color: '#00E1FF' } },
            { name: tLow, type: 'line', data: safeScans.map(function(s) { return s.low; }), smooth: 0.4, symbol: 'none', lineStyle: { width: 3, shadowBlur: 12, shadowColor: 'rgba(0,255,157,0.6)' }, areaStyle: { color: new echarts.graphic.LinearGradient(0, 0, 0, 1, [{ offset: 0, color: 'rgba(0,255,157,0.4)' }, { offset: 1, color: 'rgba(0,255,157,0.01)' }]) }, itemStyle: { color: '#00FF9D' } }
        ]
    };
    trendChartInstance.setOption(option);
}

// ──────────────────────────────────────────────────────────────
//  §M  MODALS & ACTIONS
// ──────────────────────────────────────────────────────────────
var selectedReportFormat = null;

function openReportModal() {
    document.getElementById('reportModal').classList.add('open');
    if (typeof audioSynth !== 'undefined' && audioSynth) audioSynth.play('click');
}

function closeReportModal() {
    document.getElementById('reportModal').classList.remove('open');
    selectedReportFormat = null;
    document.querySelectorAll('.report-card-opt').forEach(function(c) { c.classList.remove('selected'); });
    document.getElementById('modal-download-btn').disabled = true;
}

function selectReportFormat(fmt) {
    selectedReportFormat = fmt;
    document.querySelectorAll('.report-card-opt').forEach(function(c) { c.classList.remove('selected'); });
    document.getElementById('opt-' + fmt).classList.add('selected');
    document.getElementById('modal-download-btn').disabled = false;
    if (typeof audioSynth !== 'undefined' && audioSynth) audioSynth.play('click');
}

function executeModalDownload() {
    if (!selectedReportFormat) return;
    var dlBtn = document.getElementById('modal-download-btn');
    var spinner = document.getElementById('modal-download-spinner');
    dlBtn.disabled = true; spinner.classList.remove('d-none');
    fetchWithAuth('/api/report?format=' + selectedReportFormat).then(function(resp) {
        if (!resp.ok) throw new Error('Failed'); return resp.blob();
    }).then(function(blob) {
        var url = URL.createObjectURL(blob); var a = document.createElement('a'); a.href = url;
        a.download = 'pipeline_sentinel_report.' + (selectedReportFormat === 'json' ? 'json' : selectedReportFormat === 'html' ? 'html' : 'pdf');
        document.body.appendChild(a); a.click(); a.remove(); URL.revokeObjectURL(url);
        showToast(T[CL]?.report_success || 'Report downloaded', 'success'); closeReportModal();
    }).catch(function() { showToast(T[CL]?.report_failed || 'Report failed', 'danger'); }).finally(function() {
        dlBtn.disabled = false; spinner.classList.add('d-none');
    });
}

function sendToJira() {
    var ids = Array.from(selectedFindings);
    if (ids.length === 0) { showToast('Please select at least one finding.', 'warning'); return; }
    fetchWithAuth('/api/notify-jira', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ finding_ids: ids }) }).then(function(r) { return r.json(); }).then(function(d) { showToast(d.error || d.status || 'Sent to Jira', d.error ? 'danger' : 'success'); }).catch(function() { showToast('Failed to send to Jira', 'danger'); });
}

function sendToAsana() {
    var ids = Array.from(selectedFindings);
    if (ids.length === 0) { showToast('Please select at least one finding.', 'warning'); return; }
    fetchWithAuth('/api/notify-asana', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ finding_ids: ids }) }).then(function(r) { return r.json(); }).then(function(d) { showToast(d.error || d.status || 'Sent to Asana', d.error ? 'danger' : 'success'); }).catch(function() { showToast('Failed to send to Asana', 'danger'); });
}

function closeSimPanel() { document.getElementById('simOverlay').classList.remove('open'); }

function openRagModal() {
    document.getElementById('ragModal').classList.add('open');
    document.getElementById('rag-search-input').value = '';
    document.getElementById('rag-results-container').innerHTML = '<p class="text-muted text-center" style="font-family: var(--font-mono); font-size:1.1rem; margin-top:20px;">Enter a query and press Search.</p>';
    if (typeof audioSynth !== 'undefined' && audioSynth) audioSynth.play('click');
}

function closeRagModal() { document.getElementById('ragModal').classList.remove('open'); }

async function performRagSearch() {
    var query = document.getElementById('rag-search-input').value.trim();
    if (!query) return;
    var container = document.getElementById('rag-results-container');
    container.innerHTML = '<div class="text-center py-5"><div class="spinner-border" style="color: var(--accent); width: 3rem; height: 3rem; border-width: 4px;"></div></div>';
    try {
        var resp = await fetchWithAuth('/api/rag?q=' + encodeURIComponent(query));
        var data = await resp.json();
        if (!data || !data.length) { container.innerHTML = '<p class="text-warning text-center fw-bold" style="font-family: var(--font-mono); font-size:1.1rem; margin-top:20px;">' + (T[CL]?.rag_no_results || 'No similar findings found.') + '</p>'; return; }
        var htmlParts = [];
        for (var idx = 0; idx < data.length; idx++) {
            var item = data[idx]; var sColor = severityColor(item.severity || 'UNKNOWN');
            var sim = item.similarity ? '<span class="badge bg-info ms-3 px-2 py-1 shadow-sm" style="font-size:0.8rem; box-shadow:0 0 10px var(--info);">' + (item.similarity * 100).toFixed(0) + '% Match</span>' : '';
            htmlParts.push('<div class="p-4 mb-3 rounded" style="background:var(--bg-tertiary); border:1px solid var(--glass-border); box-shadow:inset 0 2px 15px rgba(0,0,0,0.4); animation: feedSlideDown 0.4s ease forwards; opacity:0; transform:translateY(10px); animation-delay:' + (idx * 0.08) + 's;"><div class="d-flex justify-content-between align-items-start"><div><strong style="color:var(--accent); font-family:var(--font-mono); font-size:1.1rem;">' + escapeHtml(item.id) + '</strong> ' + sim + '<span class="badge bg-' + sColor + ' ms-3 px-3 py-1 shadow-sm" style="font-size:0.8rem; font-weight:900;">' + escapeHtml(item.severity) + '</span></div><small style="color:var(--text-secondary); font-weight:800; text-transform:uppercase;">' + escapeHtml(item.tool) + '</small></div><div style="font-weight:900; margin-top:10px; font-size:1.05rem; color:var(--text);">' + escapeHtml(item.title) + '</div><small style="color:var(--text-secondary); font-family:var(--font-mono); font-size:0.9rem;">' + escapeHtml(item.target || '') + '</small></div>');
        }
        container.innerHTML = htmlParts.join('');
    } catch (e) { container.innerHTML = '<p class="text-danger text-center fw-bold mt-4">Search failed. Please try again.</p>'; }
}

var ragAvailable = false;
function updateRagIndicator(available) {
    ragAvailable = available;
    var indicator = document.getElementById('rag-indicator');
    if (!indicator) return;
    if (available) { indicator.textContent = '\u{1F9E0} ' + (T[CL]?.rag_ready || 'RAG Ready'); indicator.className = 'rag-indicator rag-ready'; } else { indicator.textContent = '\u{1F4C4} ' + (T[CL]?.text_search || 'Text Search Only'); indicator.className = 'rag-indicator rag-text'; }
}
function checkRagAvailability() {
    fetchWithAuth('/api/rag?q=test').then(function(r) { return r.json(); }).then(function(data) { if (data && data.length > 0 && data[0].similarity !== undefined) { updateRagIndicator(true); } else { updateRagIndicator(false); } }).catch(function() { updateRagIndicator(false); });
}

// ──────────────────────────────────────────────────────────────
//  §N  DASHBOARD DATA LOADING
// ──────────────────────────────────────────────────────────────
function loadDashboardData() {
    fetchWithAuth('/api/findings?per_page=99999').then(function(r) { return r.json(); }).then(function(data) {
        allFindings = data.data || []; filteredFindings = allFindings.slice(); renderTable();
        fetchWithAuth('/api/severity-counts').then(function(r) { return r.json(); }).then(function(counts) {
            var c = counts.CRITICAL || 0, h = counts.HIGH || 0, m = counts.MEDIUM || 0, l = counts.LOW || 0;
            document.getElementById('stat-critical') && animateCounter(document.getElementById('stat-critical'), c);
            document.getElementById('stat-high') && animateCounter(document.getElementById('stat-high'), h);
            document.getElementById('stat-medium') && animateCounter(document.getElementById('stat-medium'), m);
            document.getElementById('stat-low') && animateCounter(document.getElementById('stat-low'), l);
            document.getElementById('stat-total') && animateCounter(document.getElementById('stat-total'), c + h + m + l);
            createSeverityChart(counts);
        }).catch(function(){});
    }).catch(function() {
        document.getElementById('tableBody').innerHTML = '<tr><td colspan="6" class="text-center py-5 text-danger fw-bold" style="font-family:var(--font-mono); background:transparent !important; border:none;">[ CONNECTION SEVERED ]</td></tr>';
    });

    fetchWithAuth('/api/summary').then(function(r) { return r.json(); }).then(function(data) {
        latestAiSummary = data || {};
        var el = document.getElementById('exec-summary');
        if (el && data.executive_summary) typeWriter(el, data.executive_summary, 8);
    }).catch(function(){});

    fetchWithAuth('/api/policy-status').then(function(r) { return r.json(); }).then(function(data) {
        var el = document.getElementById('policy-status-text');
        if (!el) return;
        if (data && data.violated !== undefined) {
            if (data.violated) el.innerHTML = '<span style="color:var(--danger); text-shadow:0 0 10px var(--critical-glow);">\u274C VIOLATED</span><br><small style="color:var(--text-secondary);">' + data.current_critical + ' / ' + data.max_critical + '</small>';
            else el.innerHTML = '<span style="color:var(--success); text-shadow:0 0 10px var(--low-glow);">\u2705 PASSED</span><br><small style="color:var(--text-secondary);">' + data.current_critical + ' / ' + data.max_critical + '</small>';
        }
    }).catch(function(){});

    // 3D Neural Web (Crystals & Hover Drag)
    fetchWithAuth('/api/attack-paths').then(function(r) { return r.json(); }).then(function(data) {
        if (data && data.nodes && data.nodes.length) render3DAttackPaths(data);
    }).catch(function(){});

    // 3D Cyber City Topology
    fetchWithAuth('/api/topology').then(function(r) { return r.json(); }).then(function(data) {
        var topoRow = document.getElementById('topology-row');
        if (topoRow && data && data.assets && data.assets.length) { topoRow.style.display = 'block'; render3DTopology(data); }
    }).catch(function(){});

    fetchWithAuth('/api/scans-with-ai').then(function(r) { return r.json(); }).then(function(data) {
        var sel = document.getElementById('ai-history-select');
        if (!sel || !Array.isArray(data)) return;
        sel.innerHTML = '<option value="">Latest analysis</option>';
        data.forEach(function(scan) {
            var opt = document.createElement('option'); opt.value = scan.scan_id; opt.textContent = scan.timestamp ? scan.timestamp.substring(0, 19) : ('Scan ' + scan.scan_id); sel.appendChild(opt);
        });
        sel.style.display = 'inline-block';
        sel.onchange = function() { if (this.value) loadAIHistoryScan(this.value); };
    }).catch(function(){});

    checkRagAvailability();
    updateTrendRange('all');
    
    // Bind toggle button for 3D Trend View
    var trendBtn = document.getElementById('trend-3d-btn');
    if (trendBtn) {
        trendBtn.addEventListener('click', toggleTrendView);
    }
}

function loadAIHistoryScan(scanId) {
    fetchWithAuth('/api/summary/' + scanId).then(function(r) { return r.json(); }).then(function(data) {
        latestAiSummary = data || {};
        var el = document.getElementById('exec-summary');
        if (el && data.executive_summary) {
            typeWriter(el, data.executive_summary, 8);
        }
        fetchWithAuth('/api/attack-paths?scan_id=' + scanId).then(function(r) { return r.json(); }).then(function(graphData) {
            if (graphData && graphData.nodes && graphData.nodes.length) {
                render3DAttackPaths(graphData);
            }
        }).catch(function(){});
        if (data.top_remediations && data.top_remediations.length) {
            showRemediationFromSummary(data);
        }
    }).catch(function() {
        showToast('Failed to load historical analysis.', 'warning');
    });
}

// ──────────────────────────────────────────────────────────────
//  §O  LIVE FEED & SCANNER STATUS
// ──────────────────────────────────────────────────────────────
var liveFeedInterval = null;

function startLiveFeedInterval() { stopLiveFeedInterval(); loadLiveFeed(); liveFeedInterval = setInterval(loadLiveFeed, 5000); }
function stopLiveFeedInterval() { if (liveFeedInterval) { clearInterval(liveFeedInterval); liveFeedInterval = null; } }

function loadLiveFeed() {
    fetchWithAuth('/api/live-feed?limit=20').then(function(r) { return r.json(); }).then(function(items) {
        var container = document.getElementById('live-feed-container');
        if (!container || !Array.isArray(items) || items.length === 0) return;
        container.innerHTML = '';
        for (var i = 0; i < Math.min(items.length, 20); i++) {
            var item = items[i];
            var isCrit = item.severity && item.severity.toUpperCase() === 'CRITICAL';
            var div = document.createElement('div');
            div.className = 'live-feed-item' + (isCrit ? ' feed-critical' : '');
            div.style.animation = 'feedSlideDown 0.3s ease forwards ' + (i * 0.04) + 's';
            div.style.opacity = '0';
            var sevBadge = item.severity ? '<span class="badge bg-' + severityColor(item.severity) + ' me-2" style="font-size:0.65rem; font-weight:900;">' + escapeHtml(item.severity) + '</span>' : '';
            div.innerHTML = '<span class="feed-time">' + escapeHtml(item.timestamp ? item.timestamp.substring(11,19) : '') + '</span> ' + sevBadge + '<strong>' + escapeHtml(item.id) + '</strong>: ' + escapeHtml(item.title || item.target || '');
            container.appendChild(div);
        }
    }).catch(function(){});
}

function loadScannerStatus() {
    fetchWithAuth('/api/scanner-status').then(function(r) { return r.json(); }).then(function(data) {
        var container = document.getElementById('scanner-status-container');
        if (!container) return;
        var tools = ['trivy', 'semgrep', 'poutine', 'zizmor', 'gitleaks'];
        var html = '';
        tools.forEach(function(tool) {
            var available = data[tool] === true;
            html += '<div style="display:flex; align-items:center; gap:10px; padding:8px 0; border-bottom:1px solid var(--glass-border);">' +
                '<span style="width:12px; height:12px; border-radius:50%; background:' + (available ? 'var(--success)' : 'var(--danger)') + '; box-shadow:0 0 10px ' + (available ? 'var(--success)' : 'var(--danger)') + ';"></span>' +
                '<span style="font-weight:700; text-transform:uppercase; font-size:0.85rem;">' + tool + '</span>' +
                '<span style="margin-left:auto; color:' + (available ? 'var(--success)' : 'var(--danger)') + '; font-weight:600;">' + (available ? 'Ready' : 'Offline') + '</span></div>';
        });
        container.innerHTML = html;
    }).catch(function() {
        var c = document.getElementById('scanner-status-container');
        if(c) c.innerHTML = '<p style="color:var(--danger);">Failed to load scanner status.</p>';
    });
}

// ──────────────────────────────────────────────────────────────
//  §P  3D ENGINE CORE (Drag Controls & Cinematic Cameras)
// ──────────────────────────────────────────────────────────────
function cleanup3DScene(containerId) {
    var container = document.getElementById(containerId);
    if (!container) return;
    active3DScenes = active3DScenes.filter(function(sceneObj) {
        if (sceneObj.containerId === containerId) {
            if (sceneObj.animId) cancelAnimationFrame(sceneObj.animId);
            if (sceneObj.renderer) {
                sceneObj.renderer.dispose();
                var canvas = sceneObj.container.querySelector('canvas');
                if (canvas) canvas.remove();
            }
            var tooltips = sceneObj.container.querySelectorAll('.scene-tooltip');
            tooltips.forEach(function(tt) { tt.remove(); });
            return false;
        }
        return true; 
    });
}

function init3DEnvironment(containerId) {
    var container = document.getElementById(containerId);
    if (!container || !window.THREE) return null;
    cleanup3DScene(containerId);

    var width = container.clientWidth || 800;
    var height = container.clientHeight || 400;

    var scene = new THREE.Scene();
    var camera = new THREE.PerspectiveCamera(60, width / height, 1, 2000);
    
    var renderer = new THREE.WebGLRenderer({ alpha: true, antialias: true });
    renderer.setPixelRatio(window.devicePixelRatio);
    renderer.setSize(width, height);
    container.appendChild(renderer.domElement);

    var tooltip = document.createElement('div');
    tooltip.className = 'scene-tooltip';
    tooltip.style.cssText = 'position:absolute; padding:10px 14px; background:var(--glass-bg-heavy); border:1px solid var(--accent); border-radius:10px; color:#fff; font-family:var(--font-mono); font-size:11px; pointer-events:none; opacity:0; transition:opacity 0.2s; z-index:100; box-shadow:0 0 20px rgba(0,240,255,0.2); backdrop-filter:blur(10px);';
    container.style.position = 'relative';
    container.appendChild(tooltip);

    // Manual Drag Logic System
    var isDragging = false;
    var prevMouse = { x: 0, y: 0 };
    var rotationOffset = { x: 0, y: 0 };

    container.addEventListener('mousedown', function(e) {
        isDragging = true;
        prevMouse = { x: e.clientX, y: e.clientY };
        container.style.cursor = 'grabbing';
    });
    
    container.addEventListener('mouseup', function() {
        isDragging = false;
        container.style.cursor = 'grab';
    });

    return { scene: scene, camera: camera, renderer: renderer, container: container, tooltip: tooltip, width: width, height: height, isDragging: isDragging, prevMouse: prevMouse, rotationOffset: rotationOffset };
}

var sevColors = { CRITICAL: 0xFF003C, HIGH: 0xFFB800, MEDIUM: 0x00E1FF, LOW: 0x00FF9D, UNKNOWN: 0x6b7a94 };

// 1. DATA MOUNTAIN (3D Trend Chart)
function create3DTrendChart(labels, scans) {
    var env = init3DEnvironment('trendChart');
    if (!env) return;

    env.camera.position.set(0, 80, 150);
    env.camera.lookAt(0, 0, 0);

    var safeScans = scans.map(function(s) {
        return { crit: Number(s.critical)||0, high: Number(s.high)||0, med: Number(s.medium)||0, low: Number(s.low)||0 };
    });

    var numPoints = safeScans.length;
    if (numPoints === 0) return;

    var spacingX = 140 / Math.max(1, numPoints);
    var group = new THREE.Group();
    env.scene.add(group);

    var grid = new THREE.GridHelper(200, 20, 0x334455, 0x112233);
    grid.position.y = -5;
    env.scene.add(grid);

    var zOffsets = { crit: -15, high: -5, med: 5, low: 15 };
    var boxes = [];

    safeScans.forEach(function(s, i) {
        var xPos = (i - numPoints/2) * spacingX;
        ['crit', 'high', 'med', 'low'].forEach(function(level) {
            var val = s[level];
            if (val > 0) {
                var h = Math.log(val + 1) * 12; 
                var col = level === 'crit' ? sevColors.CRITICAL : level === 'high' ? sevColors.HIGH : level === 'med' ? sevColors.MEDIUM : sevColors.LOW;
                
                var geo = new THREE.BoxGeometry(spacingX * 0.6, h, 6);
                var mat = new THREE.MeshBasicMaterial({ color: col, transparent: true, opacity: 0.7, wireframe: false });
                var mesh = new THREE.Mesh(geo, mat);
                mesh.position.set(xPos, h/2 - 5, zOffsets[level]);
                
                var edges = new THREE.EdgesGeometry(geo);
                var line = new THREE.LineSegments(edges, new THREE.LineBasicMaterial({ color: 0xffffff, opacity: 0.3, transparent: true }));
                mesh.add(line);
                
                group.add(mesh);
                boxes.push({ mesh: mesh, data: val, label: labels[i], level: level.toUpperCase() });
            }
        });
    });

    var raycaster = new THREE.Raycaster();
    var mouse = new THREE.Vector2(-1000, -1000);
    var hoveredBox = null;
    
    env.container.addEventListener('mouseleave', function() { 
        env.isDragging = false; env.container.style.cursor = 'grab';
        mouse.x = -1000; mouse.y = -1000; env.tooltip.style.opacity='0';
    });

    env.container.addEventListener('mousemove', function(e) {
        if (env.isDragging) {
            var deltaX = e.clientX - env.prevMouse.x;
            var deltaY = e.clientY - env.prevMouse.y;
            env.rotationOffset.y += deltaX * 0.005;
            env.rotationOffset.x += deltaY * 0.005;
            env.prevMouse = { x: e.clientX, y: e.clientY };
        }

        var rect = env.container.getBoundingClientRect();
        var mx = e.clientX - rect.left; var my = e.clientY - rect.top;
        mouse.x = (mx / env.width) * 2 - 1; mouse.y = -(my / env.height) * 2 + 1;
        env.tooltip.style.left = (mx + 15) + 'px'; env.tooltip.style.top = (my - 20) + 'px';
    });

    function animate() {
        var animId = requestAnimationFrame(animate);
        
        group.rotation.y += (env.rotationOffset.y - group.rotation.y) * 0.1;
        group.rotation.x += (env.rotationOffset.x - group.rotation.x) * 0.1;
        
        raycaster.setFromCamera(mouse, env.camera);
        var intersects = raycaster.intersectObjects(boxes.map(function(b){return b.mesh;}));
        
        if (intersects.length > 0 && !env.isDragging) {
            var hit = intersects[0].object;
            var boxData = boxes.find(function(b){return b.mesh === hit;});
            if (hoveredBox !== boxData) {
                if (hoveredBox) hoveredBox.mesh.material.opacity = 0.7;
                hoveredBox = boxData;
                if (hoveredBox) {
                    hoveredBox.mesh.material.opacity = 1;
                    env.tooltip.innerHTML = '<strong style="color:#fff;">Date:</strong> ' + hoveredBox.label + '<br><span style="color:var(--accent)">' + hoveredBox.level + ':</span> ' + hoveredBox.data + ' findings';
                    env.tooltip.style.opacity = '1';
                }
            }
        } else {
            if (hoveredBox) { hoveredBox.mesh.material.opacity = 0.7; hoveredBox = null; env.tooltip.style.opacity = '0'; }
        }
        env.renderer.render(env.scene, env.camera);
        var selfObj = active3DScenes.find(s => s.containerId === 'trendChart');
        if(selfObj) selfObj.animId = animId;
    }
    animate();
    active3DScenes.push({ containerId: 'trendChart', renderer: env.renderer, camera: env.camera, container: env.container, animId: null });
}

// 2. FLOATING CYBER CRYSTALS (Attack Paths with Drag & GSAP Fly-by)
function render3DAttackPaths(data) {
    var env = init3DEnvironment('attack-graph');
    if (!env) return;
    
    env.camera.position.set(0, 100, 150);
    env.camera.lookAt(0, 0, 0);
    
    env.scene.background = new THREE.Color(0x06080d);
    env.scene.fog = new THREE.FogExp2(0x06080d, 0.005);
    
    var ambientLight = new THREE.AmbientLight(0xffffff, 0.6);
    env.scene.add(ambientLight);
    var lightFront = new THREE.SpotLight(0xffffff, 3, 1000);
    lightFront.position.set(50, 200, 50);
    env.scene.add(lightFront);

    var nodesData = data.nodes || [];
    var edgesData = data.edges || data.links || [];
    edgesData = edgesData.map(function(e) {
        return { source: typeof e.source === 'object' ? e.source.id : e.source, target: typeof e.target === 'object' ? e.target.id : e.target };
    });

    var nodeMeshes = [];
    var nodeMap = {};
    var smokeParticles = [];
    var radarRings = [];

    var gridHelper = new THREE.GridHelper(250, 50, 0x00F0FF, 0x001122);
    gridHelper.position.y = -5;
    gridHelper.material.opacity = 0.2;
    gridHelper.material.transparent = true;
    env.scene.add(gridHelper);

    // Build Floating Crystals (Octahedrons) — fixed spawn radius
    nodesData.forEach(function(nd) {
        var color = sevColors[nd.severity] || sevColors.UNKNOWN;
        
        var geo = new THREE.OctahedronGeometry(8, 0);
        var mat = new THREE.MeshStandardMaterial({ 
            color: 0x111111, transparent: true, opacity: 0.85, roughness: 0.2, metalness: 0.8
        });
        var mesh = new THREE.Mesh(geo, mat);

        var wMat = new THREE.MeshLambertMaterial({
            color: color, wireframe: true, transparent: true, opacity: 0.6
        });
        var wire = new THREE.Mesh(geo, wMat);
        mesh.add(wire);

        // FIX: Reduced spawn radius from 140 → 70 to keep nodes inside the viewport
        mesh.position.set(
            (Math.random() - 0.5) * 70,
            15 + Math.random() * 25,
            (Math.random() - 0.5) * 70
        );
        env.scene.add(mesh);
        
        var nObj = { id: nd.id, data: nd, mesh: mesh, wire: wire, vx: 0, vy: 0, vz: 0, color: color };
        nodeMeshes.push(nObj);
        nodeMap[nd.id] = nObj;

        // Smoke and Radar for CRITICAL nodes
        if (nd.severity === 'CRITICAL') {
            var smokeGeo = new THREE.CircleGeometry(1.5, 6);
            var smokeMat = new THREE.MeshBasicMaterial({ color: 0xFF003C, transparent: true, opacity: 0.5, side: THREE.DoubleSide });
            for(var i=0; i<4; i++) {
                var sMesh = new THREE.Mesh(smokeGeo, smokeMat);
                sMesh.position.set(mesh.position.x, mesh.position.y + 5, mesh.position.z);
                sMesh.userData = { baseY: mesh.position.y + 5, speed: 0.2 + Math.random()*0.3 };
                env.scene.add(sMesh);
                smokeParticles.push(sMesh);
            }

            var ringGeo = new THREE.RingGeometry(10, 12, 32);
            var ringMat = new THREE.MeshBasicMaterial({ color: 0xFF003C, transparent: true, opacity: 0.6, side: THREE.DoubleSide });
            var ring = new THREE.Mesh(ringGeo, ringMat);
            ring.rotation.x = Math.PI / 2;
            ring.position.set(mesh.position.x, -4.9, mesh.position.z);
            env.scene.add(ring);
            radarRings.push({mesh: ring, baseX: mesh.position.x, baseZ: mesh.position.z});
        }
    });

    var lines = [];
    var lineMat = new THREE.LineBasicMaterial({ color: 0x00F0FF, transparent: true, opacity: 0.2 });
    var critLineMat = new THREE.LineBasicMaterial({ color: 0xFF003C, transparent: true, opacity: 0.6 });

    var pulses = [];
    var pulseGeo = new THREE.BoxGeometry(1.5, 1.5, 1.5);

    edgesData.forEach(function(ed) {
        var sNode = nodeMap[ed.source]; var tNode = nodeMap[ed.target];
        if (sNode && tNode) {
            var isCritPath = sNode.data.severity === 'CRITICAL' || tNode.data.severity === 'CRITICAL';
            var p1 = sNode.mesh.position;
            var p2 = tNode.mesh.position;

            var lGeo = new THREE.BufferGeometry().setFromPoints([p1, p2]);
            var line = new THREE.Line(lGeo, isCritPath ? critLineMat : lineMat);
            env.scene.add(line);
            lines.push({ source: sNode, target: tNode, line: line });

            var pMat = new THREE.MeshBasicMaterial({ color: isCritPath ? 0xFF003C : 0x00F0FF });
            var pulse = new THREE.Mesh(pulseGeo, pMat);
            env.scene.add(pulse);
            pulses.push({ mesh: pulse, source: p1, target: p2, progress: Math.random() });
        }
    });

    var raycaster = new THREE.Raycaster();
    var mouse = new THREE.Vector2(-1000, -1000);
    var hoveredNode = null;
    var isCameraFlying = false;

    env.container.addEventListener('mouseleave', function() { 
        env.isDragging = false; env.container.style.cursor = 'grab';
        mouse.x = -1000; mouse.y = -1000; env.tooltip.style.opacity='0'; 
    });

    env.container.addEventListener('mousemove', function(e) {
        if (env.isDragging && !isCameraFlying) {
            var deltaX = e.clientX - env.prevMouse.x;
            var deltaY = e.clientY - env.prevMouse.y;
            env.rotationOffset.y += deltaX * 0.005;
            env.rotationOffset.x += deltaY * 0.005;
            env.prevMouse = { x: e.clientX, y: e.clientY };
        }

        var rect = env.container.getBoundingClientRect();
        var mx = e.clientX - rect.left; var my = e.clientY - rect.top;
        mouse.x = (mx / env.width) * 2 - 1; mouse.y = -(my / env.height) * 2 + 1;
        env.tooltip.style.left = (mx + 15) + 'px'; env.tooltip.style.top = (my + 15) + 'px';
    });

    function animate() {
        var animId = requestAnimationFrame(animate);
        var time = Date.now();

        if (!isCameraFlying && !env.isDragging) {
            // Apply physics
            nodeMeshes.forEach(function(n1) {
                n1.vx = 0; n1.vz = 0;
                nodeMeshes.forEach(function(n2) {
                    if (n1 === n2) return;
                    var dx = n2.mesh.position.x - n1.mesh.position.x;
                    var dz = n2.mesh.position.z - n1.mesh.position.z;
                    var distSq = dx*dx + dz*dz + 1;
                    var force = 12000 / distSq;
                    var dist = Math.sqrt(distSq);
                    n1.vx -= (dx/dist) * force; n1.vz -= (dz/dist) * force;
                });
                // Centering force (keeps nodes inside the container)
                n1.vx -= n1.mesh.position.x * 0.05;
                n1.vz -= n1.mesh.position.z * 0.05;
            });

            // Spring force from edges
            lines.forEach(function(l) {
                var dx = l.target.mesh.position.x - l.source.mesh.position.x;
                var dz = l.target.mesh.position.z - l.source.mesh.position.z;
                var dist = Math.sqrt(dx*dx + dz*dz + 1);
                var force = (dist - 60) * 0.02;
                var fx = (dx/dist) * force; var fz = (dz/dist) * force;
                l.source.vx += fx; l.source.vz += fz;
                l.target.vx -= fx; l.target.vz -= fz;
            });

            nodeMeshes.forEach(function(n) {
                n.vx *= 0.85; n.vz *= 0.85;
                n.mesh.position.x += n.vx; n.mesh.position.z += n.vz;
                // Cyber crystal spin
                n.mesh.rotation.y += 0.01;
                n.mesh.rotation.x += 0.005;
                // Float up and down
                n.mesh.position.y += Math.sin(time * 0.002 + n.mesh.position.x) * 0.05;
            });
        }

        // Always update lines and pulses
        lines.forEach(function(l, i) {
            var p1 = l.source.mesh.position;
            var p2 = l.target.mesh.position;
            var pos = l.line.geometry.attributes.position.array;
            pos[0] = p1.x; pos[1] = p1.y; pos[2] = p1.z;
            pos[3] = p2.x; pos[4] = p2.y; pos[5] = p2.z;
            l.line.geometry.attributes.position.needsUpdate = true;

            if (pulses[i]) {
                pulses[i].progress += 0.015;
                if (pulses[i].progress > 1) pulses[i].progress = 0;
                pulses[i].mesh.position.lerpVectors(p1, p2, pulses[i].progress);
                pulses[i].mesh.rotation.x += 0.1;
                pulses[i].mesh.rotation.y += 0.1;
            }
        });

        // Animate Smoke & Radar
        smokeParticles.forEach(function(sp) {
            sp.position.y += sp.userData.speed;
            sp.position.x += (Math.random() - 0.5) * 0.5;
            sp.rotation.z += 0.05;
            sp.scale.x = sp.scale.y -= 0.02;
            if (sp.scale.x <= 0) {
                var parentNode = nodeMeshes.find(n => Math.abs(n.mesh.position.x - sp.position.x) < 15);
                if(parentNode) sp.position.set(parentNode.mesh.position.x, parentNode.mesh.position.y + 5, parentNode.mesh.position.z);
                sp.scale.set(1, 1, 1);
            }
        });
        radarRings.forEach(function(r) {
            var scale = 1 + Math.sin(time * 0.005) * 0.3;
            r.mesh.scale.set(scale, scale, 1);
            r.mesh.material.opacity = 0.5 - Math.sin(time * 0.005) * 0.5;
            // follow node X/Z
            var parentNode = nodeMeshes.find(n => Math.abs(n.mesh.position.x - r.baseX) < 20);
            if(parentNode) {
                r.mesh.position.x = parentNode.mesh.position.x;
                r.mesh.position.z = parentNode.mesh.position.z;
            }
        });

        // Apply manual drag rotation
        if (!isCameraFlying) {
            env.scene.rotation.y += (env.rotationOffset.y - env.scene.rotation.y) * 0.1;
            env.scene.rotation.x += (env.rotationOffset.x - env.scene.rotation.x) * 0.1;
        }

        // Raycasting & Hover (Disabled during fly-by)
        if (!isCameraFlying && !env.isDragging) {
            raycaster.setFromCamera(mouse, env.camera);
            var intersects = raycaster.intersectObjects(nodeMeshes.map(function(n){return n.mesh;}));
            if (intersects.length > 0) {
                var hitNode = nodeMeshes.find(function(n){return n.mesh === intersects[0].object;});
                if (hoveredNode !== hitNode) {
                    if (hoveredNode) hoveredNode.wire.material.opacity = 0.6;
                    hoveredNode = hitNode;
                    if (hoveredNode) {
                        hoveredNode.wire.material.opacity = 1;
                        var hex = '#' + hoveredNode.color.toString(16).padStart(6,'0');
                        env.tooltip.innerHTML = '<strong style="color:var(--accent)">' + escapeHtml(hoveredNode.data.label||hoveredNode.id) + '</strong><br>Severity: <span style="color:'+hex+';font-weight:900;">' + hoveredNode.data.severity + '</span><br><br><span style="color:#aaa;font-size:9px;">[CLICK TO SIMULATE]</span>';
                        env.tooltip.style.opacity = '1';
                        env.container.style.cursor = 'pointer';

                        if (!env._clickBound) {
                            env.container.addEventListener('click', function() {
                                if (hoveredNode && typeof gsap !== 'undefined' && !isCameraFlying) {
                                    isCameraFlying = true;
                                    env.tooltip.style.opacity = '0';
                                    if (typeof audioSynth !== 'undefined' && audioSynth) audioSynth.play('hover');
                                    
                                    // Cinematic Fly-by
                                    var targetPos = hoveredNode.mesh.position.clone();
                                    targetPos.applyMatrix4(env.scene.matrixWorld);
                                    
                                    gsap.to(env.camera.position, {
                                        x: targetPos.x,
                                        y: targetPos.y + 15,
                                        z: targetPos.z + 40,
                                        duration: 1.5,
                                        ease: 'power3.inOut',
                                        onComplete: function() {
                                            simulateAttack([hoveredNode.data.id || hoveredNode.id]);
                                            // Reset camera gently after simulation trigger
                                            setTimeout(function() {
                                                gsap.to(env.camera.position, { x: 0, y: 100, z: 150, duration: 2, ease: 'power2.out', onComplete: function() { isCameraFlying = false; }});
                                            }, 2000);
                                        }
                                    });
                                }
                            });
                            env._clickBound = true;
                        }
                    }
                }
            } else {
                if (hoveredNode) { 
                    hoveredNode.wire.material.opacity = 0.6; 
                    hoveredNode = null; 
                    env.tooltip.style.opacity = '0'; 
                    env.container.style.cursor = 'grab'; 
                }
            }
        }

        env.renderer.render(env.scene, env.camera);
        var selfObj = active3DScenes.find(s => s.containerId === 'attack-graph');
        if(selfObj) selfObj.animId = animId;
    }
    animate();
    active3DScenes.push({ containerId: 'attack-graph', renderer: env.renderer, camera: env.camera, container: env.container, animId: null });
}

// 3. CYBER CITY MATRIX (3D Topology with Drag)
function render3DTopology(data) {
    var env = init3DEnvironment('topology-graph');
    if (!env) return;

    env.camera.position.set(0, 100, 200);
    env.camera.lookAt(0, 0, 0);

    env.scene.background = new THREE.Color(0x06080d);
    env.scene.fog = new THREE.FogExp2(0x06080d, 0.005);
    
    var ambientLight = new THREE.AmbientLight(0xffffff, 0.5);
    env.scene.add(ambientLight);
    var lightFront = new THREE.SpotLight(0xffffff, 2, 1000);
    lightFront.position.set(50, 200, 50);
    env.scene.add(lightFront);

    var assets = data.assets || [];
    var nodeMeshes = [];
    var nodeMap = {};
    var smokeParticles = [];

    var grid = new THREE.GridHelper(300, 30, 0x00F0FF, 0x002233);
    grid.position.y = -10;
    grid.material.opacity = 0.3;
    grid.material.transparent = true;
    env.scene.add(grid);

    var numNodes = assets.length;
    var radius = Math.max(50, numNodes * 5); 

    assets.forEach(function(a, idx) {
        var isExposed = a.exposed || false;
        var color = isExposed ? sevColors.CRITICAL : 0x00E1FF;
        var h = 15 + Math.random() * 40; 
        
        var geo = new THREE.BoxGeometry(8, h, 8);
        var mat = new THREE.MeshStandardMaterial({ color: 0x111111, transparent: true, opacity: 0.9, roughness: 0.2 });
        var mesh = new THREE.Mesh(geo, mat);

        var wMat = new THREE.MeshLambertMaterial({ color: color, wireframe: true, transparent: true, opacity: 0.5 });
        var wire = new THREE.Mesh(geo, wMat);
        mesh.add(wire);

        var angle = (idx / numNodes) * Math.PI * 2;
        mesh.position.set(Math.cos(angle) * radius, h/2 - 10, Math.sin(angle) * radius);
        
        env.scene.add(mesh);
        var nObj = { id: a.name || a.id, data: a, mesh: mesh, wire: wire, color: color, height: h };
        nodeMeshes.push(nObj);
        nodeMap[nObj.id] = nObj;

        if (isExposed) {
            var smokeGeo = new THREE.CircleGeometry(2, 6);
            var smokeMat = new THREE.MeshBasicMaterial({ color: 0xFF003C, transparent: true, opacity: 0.5, side: THREE.DoubleSide });
            for(var i=0; i<4; i++) {
                var sMesh = new THREE.Mesh(smokeGeo, smokeMat);
                sMesh.position.set(mesh.position.x, mesh.position.y + h/2, mesh.position.z);
                sMesh.userData = { baseY: mesh.position.y + h/2, speed: 0.3 + Math.random()*0.4 };
                env.scene.add(sMesh);
                smokeParticles.push(sMesh);
            }
        }
    });

    var lineMat = new THREE.LineBasicMaterial({ color: 0x00F0FF, transparent: true, opacity: 0.2 });
    var redMat = new THREE.LineBasicMaterial({ color: 0xFF003C, transparent: true, opacity: 0.6 });

    assets.forEach(function(a) {
        var sId = a.name || a.id;
        (a.connections || []).forEach(function(tId) {
            var sNode = nodeMap[sId];
            var tNode = nodeMap[tId];
            if (sNode && tNode) {
                var isDanger = sNode.data.exposed || tNode.data.exposed;
                var p1 = sNode.mesh.position.clone(); p1.y += sNode.height/2;
                var p2 = tNode.mesh.position.clone(); p2.y += tNode.height/2;
                var lGeo = new THREE.BufferGeometry().setFromPoints([p1, p2]);
                var line = new THREE.Line(lGeo, isDanger ? redMat : lineMat);
                env.scene.add(line);
            }
        });
    });

    var raycaster = new THREE.Raycaster();
    var mouse = new THREE.Vector2(-1000, -1000);
    var hoveredNode = null;

    env.container.addEventListener('mouseleave', function() { 
        env.isDragging = false; env.container.style.cursor = 'grab';
        mouse.x = -1000; mouse.y = -1000; env.tooltip.style.opacity='0'; 
    });

    env.container.addEventListener('mousemove', function(e) {
        if (env.isDragging) {
            var deltaX = e.clientX - env.prevMouse.x;
            var deltaY = e.clientY - env.prevMouse.y;
            env.rotationOffset.y += deltaX * 0.005;
            env.rotationOffset.x += deltaY * 0.005;
            env.prevMouse = { x: e.clientX, y: e.clientY };
        }

        var rect = env.container.getBoundingClientRect();
        var mx = e.clientX - rect.left; var my = e.clientY - rect.top;
        mouse.x = (mx / env.width) * 2 - 1; mouse.y = -(my / env.height) * 2 + 1;
        env.tooltip.style.left = (mx + 15) + 'px'; env.tooltip.style.top = (my + 15) + 'px';
    });

    function animate() {
        var animId = requestAnimationFrame(animate);

        env.scene.rotation.y += (env.rotationOffset.y - env.scene.rotation.y) * 0.1;
        env.scene.rotation.x += (env.rotationOffset.x - env.scene.rotation.x) * 0.1;

        smokeParticles.forEach(function(sp) {
            sp.position.y += sp.userData.speed;
            sp.position.x += (Math.random() - 0.5) * 0.5;
            sp.rotation.z += 0.05;
            sp.scale.x = sp.scale.y -= 0.02;
            if (sp.scale.x <= 0) {
                sp.position.y = sp.userData.baseY;
                sp.scale.set(1, 1, 1);
            }
        });

        if (!env.isDragging) {
            raycaster.setFromCamera(mouse, env.camera);
            var intersects = raycaster.intersectObjects(nodeMeshes.map(function(n){return n.mesh;}));
            if (intersects.length > 0) {
                var hit = intersects[0].object;
                var hitNode = nodeMeshes.find(function(n){return n.mesh === hit;});
                if (hoveredNode !== hitNode) {
                    if (hoveredNode) hoveredNode.wire.material.opacity = 0.5;
                    hoveredNode = hitNode;
                    if (hoveredNode) {
                        hoveredNode.wire.material.opacity = 1;
                        var hex = '#' + hoveredNode.color.toString(16).padStart(6,'0');
                        var status = hoveredNode.data.exposed ? 'EXPOSED' : 'SECURE';
                        env.tooltip.innerHTML = '<strong style="color:var(--accent)">' + escapeHtml(hoveredNode.data.name||hoveredNode.id) + '</strong><br>Status: <span style="color:'+hex+';font-weight:900;">' + status + '</span>';
                        env.tooltip.style.opacity = '1';
                    }
                }
            } else {
                if (hoveredNode) { hoveredNode.wire.material.opacity = 0.5; hoveredNode = null; env.tooltip.style.opacity = '0'; }
            }
        }

        env.renderer.render(env.scene, env.camera);
        var selfObj = active3DScenes.find(s => s.containerId === 'topology-graph');
        if(selfObj) selfObj.animId = animId;
    }
    animate();
    active3DScenes.push({ containerId: 'topology-graph', renderer: env.renderer, camera: env.camera, container: env.container, animId: null });
}
// ══════════════════════════════════════════════════════════════════════════
// §U  WEBGL ENGINE — Volumetric Background
// ══════════════════════════════════════════════════════════════════════════
class WebGLEngine {
    constructor() {
        this.canvas = document.getElementById('webgl-bg-canvas');
        this.scene = null;
        this.camera = null;
        this.renderer = null;
        this.mesh = null;
        this.clock = null;
        this.isActive = false;
        this.animId = null;
        this.uniforms = null;
        this.init();
    }

    init() {
        if (!this.canvas) { this.fallback(); return; }
        if (!window.THREE || !THREE.ShaderMaterial) { this.fallback(); return; }
        try {
            var pixelRatio = Math.min(window.devicePixelRatio, 2);
            var w = this.canvas.clientWidth;
            var h = this.canvas.clientHeight;
            if (w === 0 || h === 0) { this.fallback(); return; }

            this.renderer = new THREE.WebGLRenderer({
                canvas: this.canvas,
                alpha: true,
                antialias: false
            });
            this.renderer.setPixelRatio(pixelRatio);
            this.renderer.setSize(w, h, false);

            this.scene = new THREE.Scene();
            this.camera = new THREE.OrthographicCamera(-1, 1, 1, -1, 0, 1);

            this.uniforms = {
                uTime: { value: 0 },
                uResolution: { value: new THREE.Vector2(w * pixelRatio, h * pixelRatio) },
                uColor: { value: new THREE.Color(0x00F0FF) }
            };

            var vertexShader = [
                'varying vec2 vUv;',
                'void main() {',
                '    vUv = uv;',
                '    gl_Position = projectionMatrix * modelViewMatrix * vec4(position, 1.0);',
                '}'
            ].join('\n');

            var fragmentShader = [
                'precision mediump float;',
                'uniform float uTime;',
                'uniform vec2 uResolution;',
                'uniform vec3 uColor;',
                'varying vec2 vUv;',
                'float hash(vec2 p) {',
                '    return fract(sin(dot(p, vec2(127.1, 311.7))) * 43758.5453123);',
                '}',
                'float noise(vec2 p) {',
                '    vec2 i = floor(p);',
                '    vec2 f = fract(p);',
                '    f = f * f * (3.0 - 2.0 * f);',
                '    float a = hash(i);',
                '    float b = hash(i + vec2(1.0, 0.0));',
                '    float c = hash(i + vec2(0.0, 1.0));',
                '    float d = hash(i + vec2(1.0, 1.0));',
                '    return mix(mix(a, b, f.x), mix(c, d, f.x), f.y);',
                '}',
                'float fbm(vec2 p) {',
                '    float v = 0.0;',
                '    float a = 0.5;',
                '    vec2 shift = vec2(100.0);',
                '    for (int i = 0; i < 4; ++i) {',
                '        v += a * noise(p);',
                '        p = p * 2.0 + shift;',
                '        a *= 0.5;',
                '    }',
                '    return v;',
                '}',
                'void main() {',
                '    vec2 uv = vUv;',
                '    float t = uTime * 0.08;',
                '    float n1 = fbm(uv * 3.0 + vec2(t, -t * 0.7));',
                '    float n2 = fbm(uv * 5.0 - vec2(t * 0.5, t * 0.3) + n1 * 0.5);',
                '    float n = (n1 + n2) * 0.5;',
                '    float breath = sin(uTime * 0.4) * 0.5 + 0.5;',
                '    float alpha = n * 0.12 * (0.6 + breath * 0.4);',
                '    vec3 col = uColor * n * 0.4;',
                '    float vignette = 1.0 - length((uv - 0.5) * 1.4);',
                '    vignette = clamp(vignette, 0.0, 1.0);',
                '    alpha *= vignette;',
                '    gl_FragColor = vec4(col, alpha);',
                '}'
            ].join('\n');

            var material = new THREE.ShaderMaterial({
                uniforms: this.uniforms,
                vertexShader: vertexShader,
                fragmentShader: fragmentShader,
                transparent: true,
                depthWrite: false
            });

            var geometry = new THREE.PlaneGeometry(2, 2);
            this.mesh = new THREE.Mesh(geometry, material);
            this.scene.add(this.mesh);
            this.clock = new THREE.Clock();
            this.isActive = true;
            this.animate();

            var self = this;
            this._resizeObserver = new ResizeObserver(function() { self.resize(); });
            this._resizeObserver.observe(this.canvas);
        } catch (e) {
            this.fallback();
        }
    }

    resize() {
        if (!this.isActive || !this.renderer) return;
        var w = this.canvas.clientWidth;
        var h = this.canvas.clientHeight;
        if (w === 0 || h === 0) return;
        var pixelRatio = Math.min(window.devicePixelRatio, 2);
        this.renderer.setSize(w, h, false);
        this.uniforms.uResolution.value.set(w * pixelRatio, h * pixelRatio);
    }

    animate() {
        if (!this.isActive) return;
        var self = this;
        this.animId = requestAnimationFrame(function() { self.animate(); });
        if (document.visibilityState === 'hidden') return;
        if (this.clock) this.uniforms.uTime.value = this.clock.getElapsedTime();
        if (this.renderer) this.renderer.render(this.scene, this.camera);
    }

    pause() {
        if (this.animId) {
            cancelAnimationFrame(this.animId);
            this.animId = null;
        }
    }

    resume() {
        if (this.isActive && !this.animId) this.animate();
    }

    updateColor(hexColor) {
        if (this.uniforms && this.uniforms.uColor) {
            this.uniforms.uColor.value.set(hexColor);
        }
    }

    fallback() {
        if (this.canvas) {
            this.canvas.style.display = 'none';
        }
        document.body.style.background = 'radial-gradient(ellipse at 50% 0%, rgba(0,240,255,0.04) 0%, var(--bg-primary) 70%)';
    }

    destroy() {
        this.pause();
        if (this._resizeObserver) this._resizeObserver.disconnect();
        if (this.renderer) this.renderer.dispose();
        if (this.mesh) {
            if (this.mesh.geometry) this.mesh.geometry.dispose();
            if (this.mesh.material) this.mesh.material.dispose();
        }
        this.isActive = false;
    }
}

// ══════════════════════════════════════════════════════════════════════════
// §V  UI ANIMATOR
// ══════════════════════════════════════════════════════════════════════════
class UIAnimator {
    constructor() {
        this.hasGSAP = typeof gsap !== 'undefined';
    }

    entrance() {
        if (!this.hasGSAP) return;
        var cards = document.querySelectorAll('#dashboard-main .hud-card, #dashboard-main .stat-pill');
        gsap.fromTo(cards,
            { opacity: 0, y: 30, scale: 0.96 },
            {
                opacity: 1, y: 0, scale: 1,
                duration: 0.6,
                stagger: 0.06,
                ease: 'power3.out',
                clearProps: 'transform'
            }
        );
    }

    airlockOpen(overlayEl, dashboardEl, onComplete) {
        if (!this.hasGSAP) {
            overlayEl.style.display = 'none';
            if (dashboardEl) dashboardEl.style.display = 'block';
            if (onComplete) onComplete();
            return;
        }
        var orb = document.getElementById('airlock-orb');
        var tl = gsap.timeline({ onComplete: onComplete });

        if (orb) {
            tl.to(orb, { scale: 2, opacity: 0, duration: 0.5, ease: 'power2.in' }, 0);
        }
        tl.to(overlayEl, { opacity: 0, scale: 1.05, duration: 0.4, ease: 'power2.in' }, 0.1);
        tl.call(function() {
            overlayEl.style.display = 'none';
        }, null, 0.5);
        tl.call(function() {
            if (dashboardEl) dashboardEl.style.display = 'block';
        }, null, 0.5);
        tl.fromTo(dashboardEl,
            { opacity: 0, y: 40 },
            { opacity: 1, y: 0, duration: 0.7, ease: 'power3.out' },
            0.55
        );
        tl.add(function() { this.entrance(); }.bind(this), 0.7);
    }
}

// ══════════════════════════════════════════════════════════════════════════
// §W  AUDIO SYNTH
// ══════════════════════════════════════════════════════════════════════════
class AudioSynth {
    constructor() {
        this.ctx = null;
        this.muted = true;
    }

    _ensureCtx() {
        if (!this.ctx) {
            try {
                this.ctx = new (window.AudioContext || window.webkitAudioContext)();
            } catch (e) {
                return false;
            }
        }
        if (this.ctx.state === 'suspended') this.ctx.resume();
        return true;
    }

    play(type) {
        if (this.muted) return;
        if (!this._ensureCtx()) return;
        switch (type) {
            case 'hover':
                this._tone(800, 0.03, 0.008, 'sine');
                break;
            case 'click':
                this._tone(1200, 0.04, 0.015, 'square');
                break;
            case 'loginSuccess':
                this._tone(600, 0.08, 0.02, 'sine');
                setTimeout(function() { this._tone(900, 0.1, 0.02, 'sine'); }.bind(this), 100);
                setTimeout(function() { this._tone(1200, 0.12, 0.02, 'sine'); }.bind(this), 200);
                break;
            case 'error':
                this._tone(200, 0.15, 0.03, 'sawtooth');
                break;
            case 'glitch':
                this._noise(0.3);
                break;
            case 'gameCrash':
                this._tone(100, 0.2, 0.5, 'sawtooth');
                this._noise(0.5);
                break;
            case 'gamePoint':
                this._tone(1500, 0.05, 0.05, 'sine');
                break;
            case 'laser':
                this._tone(1800, 0.08, 0.08, 'square');
                break;
            case 'explosion':
                this._noise(0.15);
                this._tone(300, 0.1, 0.2, 'sawtooth');
                break;
            case 'powerup':
                this._tone(800, 0.1, 0.1, 'sine');
                setTimeout(function() { this._tone(1200, 0.1, 0.2, 'sine'); }.bind(this), 100);
                break;
        }
    }

    _tone(freq, vol, dur, waveType) {
        try {
            var osc = this.ctx.createOscillator();
            var gain = this.ctx.createGain();
            osc.type = waveType || 'sine';
            osc.frequency.setValueAtTime(freq, this.ctx.currentTime);
            gain.gain.setValueAtTime(vol, this.ctx.currentTime);
            gain.gain.exponentialRampToValueAtTime(0.001, this.ctx.currentTime + dur);
            osc.connect(gain).connect(this.ctx.destination);
            osc.start(this.ctx.currentTime);
            osc.stop(this.ctx.currentTime + dur + 0.01);
        } catch (e) {}
    }

    _noise(dur) {
        try {
            var bufferSize = this.ctx.sampleRate * dur;
            var buffer = this.ctx.createBuffer(1, bufferSize, this.ctx.sampleRate);
            var bufferData = buffer.getChannelData(0);
            for (var i = 0; i < bufferSize; i++) {
                bufferData[i] = (Math.random() * 2 - 1) * 0.3;
            }
            var source = this.ctx.createBufferSource();
            source.buffer = buffer;
            var gain = this.ctx.createGain();
            gain.gain.setValueAtTime(0.08, this.ctx.currentTime);
            gain.gain.exponentialRampToValueAtTime(0.001, this.ctx.currentTime + dur);
            source.connect(gain).connect(this.ctx.destination);
            source.start(this.ctx.currentTime);
        } catch (e) {}
    }

    toggle() {
        this.muted = !this.muted;
        return this.muted;
    }
}

// ══════════════════════════════════════════════════════════════════════════
// §X  CURSOR SYSTEM
// ══════════════════════════════════════════════════════════════════════════
class CursorSystem {
    constructor() {
        this.dot = document.getElementById('cursor-dot');
        this.aura = document.getElementById('cursor-aura');
        this.mx = -100; this.my = -100;
        this.ax = -100; this.ay = -100;
        this.active = !window.matchMedia('(max-width: 768px)').matches;
        if (!this.active) return;
        this.init();
    }

    init() {
        var self = this;
        document.addEventListener('mousemove', function(e) {
            self.mx = e.clientX; self.my = e.clientY;
            if (self.dot) { self.dot.style.left = self.mx + 'px'; self.dot.style.top = self.my + 'px'; }
        });
        this._animate();
        this._bindHover();
    }

    _animate() {
        if (!this.active) return;
        var self = this;
        requestAnimationFrame(function() { self._animate(); });
        this.ax += (this.mx - this.ax) * 0.15;
        this.ay += (this.my - this.ay) * 0.15;
        if (this.aura) {
            this.aura.style.left = this.ax + 'px';
            this.aura.style.top = this.ay + 'px';
        }
    }

    _bindHover() {
        var self = this;
        var hoverables = 'a, button, input, select, .tilt-card, .report-card-opt, .theme-dot, .lang-item, .cli-flag-card, .finding-checkbox, .trend-filter-btn, .filter-btn, .btn-hud, .icon-btn, #trend-3d-btn';
        document.addEventListener('mouseover', function(e) {
            if (e.target.closest(hoverables)) {
                if (self.dot) self.dot.classList.add('hovering');
                if (self.aura) self.aura.classList.add('hovering');
                if (typeof audioSynth !== 'undefined' && audioSynth) audioSynth.play('hover');
            }
        });
        document.addEventListener('mouseout', function(e) {
            if (e.target.closest(hoverables)) {
                if (self.dot) self.dot.classList.remove('hovering');
                if (self.aura) self.aura.classList.remove('hovering');
            }
        });
    }
}

// ════════════════════════════════════════════════════════════════════════
// §Y  DATA SCRAMBLE
// ════════════════════════════════════════════════════════════════════════
class DataScramble {
    constructor() {
        this.chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789$+-*/=<>_!#%@&';
    }

    scramble(el, finalText, duration) {
        if (!el) return;
        if (duration === undefined) duration = 600;
        var len = finalText.length;
        var startTime = performance.now();

        var tick = (now) => {
            var elapsed = now - startTime;
            var progress = Math.min(elapsed / duration, 1);
            var display = '';
            for (var i = 0; i < len; i++) {
                var charProgress = Math.min(1, (progress * len - i) / 3);
                if (charProgress >= 1) {
                    display += finalText[i];
                } else {
                    display += this.chars[Math.floor(Math.random() * this.chars.length)];
                }
            }
            el.textContent = display;
            if (progress < 1) requestAnimationFrame(tick);
        };
        requestAnimationFrame(tick);
    }
}

// ══════════════════════════════════════════════════════════════════════════
// §Z  EXPLODED VIEW
// ════════════════════════════════════════════════════════════════════════
class ExplodedView {
    constructor() {
        this.isExploded = false;
        this.cards = [];
        this.hasGSAP = typeof gsap !== 'undefined';
    }

    toggle() {
        this.cards = Array.from(document.querySelectorAll('#dashboard-main .hud-card'));
        if (this.isExploded) {
            this.collapse();
        } else {
            this.explode();
        }
        this.isExploded = !this.isExploded;
    }

    explode() {
        if (!this.hasGSAP) return;
        for (var i = 0; i < this.cards.length; i++) {
            (function(card, idx) {
                var zOffset = (idx % 3 - 1) * 30;
                var yShift = (Math.floor(idx / 3) % 2) * -8;
                gsap.to(card, {
                    transform: 'translateZ(' + zOffset + 'px) translateY(' + yShift + 'px) scale(0.97)',
                    opacity: 0.85,
                    duration: 0.7,
                    ease: 'power3.out',
                    delay: idx * 0.03
                });
                card.style.transformStyle = 'preserve-3d';
                card.style.perspective = '1200px';
            })(this.cards[i], i);
        }
        if (typeof audioSynth !== 'undefined' && audioSynth) audioSynth.play('click');
    }

    collapse() {
        if (!this.hasGSAP) return;
        for (var i = 0; i < this.cards.length; i++) {
            (function(card, idx) {
                gsap.to(card, {
                    transform: 'translateZ(0px) translateY(0px) scale(1)',
                    opacity: 1,
                    duration: 0.5,
                    ease: 'power2.inOut',
                    delay: idx * 0.02,
                    onComplete: function() {
                        card.style.transformStyle = '';
                        card.style.perspective = '';
                    }
                });
            })(this.cards[i], i);
        }
        if (typeof audioSynth !== 'undefined' && audioSynth) audioSynth.play('click');
    }
}

// ══════════════════════════════════════════════════════════════════════════
// §AB  IDLE MINI-GAME (2-Min Timer, Boss Mode, Powerups)
// ══════════════════════════════════════════════════════════════════════════
class IdleMiniGame {
    constructor() {
        this.idleWaitTime = 120000; // 2 minutes
        this.countdownTime = 5;     // 5 seconds warning
        this.idleTimer = null;
        this.countdownInterval = null;
        this.isCountingDown = false;
        
        this.isActive = false;
        this.gameWon = false;
        
        // Engine Vars
        this.scene = null;
        this.camera = null;
        this.renderer = null;
        this.ship = null;
        this.tunnel = null;
        
        this.obstacles = [];
        this.lasers = [];
        this.particles = [];
        this.elixirs = [];
        
        this.score = 0;
        this.speed = 2.0;
        this.lives = 3;
        this.invulnerable = false;
        this.invulnerableTimer = 0;
        this.elixirSpawnedForScore = {};
        
        this.animId = null;
        this.mouse = { x: 0, y: 0 };
        this.target = { x: 0, y: 0 };
        this.tunnelRadius = 38;
        
        this.initOverlay();
        this.bindEvents();
        this.resetIdleTimer();
    }

    initOverlay() {
        // Warning Overlay is already in HTML, we just grab it
        this.warningOverlay = document.getElementById('idle-warning-overlay');
        this.countdownSpan = document.getElementById('idle-countdown');

        // Game Overlay
        this.overlay = document.createElement('div');
        this.overlay.id = 'idle-game-overlay';
        this.overlay.style.cssText = 'position:fixed; inset:0; z-index:100000; background:#06080d; display:none; flex-direction:column; align-items:center; justify-content:center; cursor:crosshair; opacity:0; transition:opacity 0.8s ease;';
        
        this.uiContainer = document.createElement('div');
        this.uiContainer.style.cssText = 'position:absolute; top:40px; width:100%; text-align:center; color:var(--accent); font-family:var(--font-mono); z-index:10; pointer-events:none;';
        
        this.uiContainer.innerHTML = `
            <div style="font-size:1.8rem; font-weight:900; letter-spacing:4px; text-shadow:0 0 15px var(--accent-glow);">SENTRY GLIDER: COMBAT MODE</div>
            <div style="font-size:1rem; color:var(--text-secondary); margin-top:10px;">SCORE: <span id="glider-score" style="color:#00FF9D; font-weight:900; font-size:1.4rem;">0</span></div>
            <div id="glider-lives" style="font-size:1.5rem; margin-top:5px; text-shadow:0 0 10px rgba(0,255,157,0.5);">💚💚💚</div>
            <div style="font-size:0.8rem; color:var(--text-secondary); margin-top:5px; opacity:0.7;">[Mouse] Steer &nbsp;&bull;&nbsp; [Left Click] Shoot Lasers &nbsp;&bull;&nbsp; [ESC] Exit</div>
        `;
        
        this.bossMessage = document.createElement('div');
        this.bossMessage.style.cssText = 'position:absolute; inset:0; display:none; align-items:center; justify-content:center; flex-direction:column; background:rgba(6,8,13,0.9); z-index:20; color:var(--accent); font-family:var(--font-mono); text-align:center;';
        this.bossMessage.innerHTML = '<div style="font-size:3rem; font-weight:900; letter-spacing:5px; text-shadow:0 0 30px var(--accent-glow); animation: glitchFlash 2s infinite;">SYSTEM CLEARED</div><div style="font-size:1.2rem; color:var(--text); margin-top:20px;">BREAK TIME EXPLOIT PATCHED. DEPLOY YOURSELF BACK TO THE PIPELINE, HERO.</div>';

        this.overlay.appendChild(this.uiContainer);
        this.overlay.appendChild(this.bossMessage);
        document.body.appendChild(this.overlay);
    }

    bindEvents() {
        var self = this;
        var resetEvents = ['mousemove', 'mousedown', 'keydown', 'touchstart', 'scroll'];
        
        resetEvents.forEach(function(evt) {
            document.addEventListener(evt, function(e) {
                if (self.isActive) {
                    if (evt === 'keydown' && e.key === 'Escape') {
                        self.stopGame();
                    } else if (evt === 'mousemove') {
                        self.mouse.x = (e.clientX / window.innerWidth) * 2 - 1;
                        self.mouse.y = -(e.clientY / window.innerHeight) * 2 + 1;
                    } else if (evt === 'mousedown') {
                        self.fireLaser();
                    }
                } else {
                    if (self.isCountingDown) {
                        self.cancelCountdown();
                    } else {
                        self.resetIdleTimer();
                    }
                }
            });
        });

        window.addEventListener('resize', function() {
            if (self.isActive && self.renderer) {
                self.camera.aspect = window.innerWidth / window.innerHeight;
                self.camera.updateProjectionMatrix();
                self.renderer.setSize(window.innerWidth, window.innerHeight);
            }
        });
    }

    resetIdleTimer() {
        if (this.isActive || this.isCountingDown) return;
        clearTimeout(this.idleTimer);
        var self = this;
        this.idleTimer = setTimeout(function() {
            self.startCountdown();
        }, this.idleWaitTime);
    }

    startCountdown() {
        if (this.isActive) return;
        this.isCountingDown = true;
        if (this.warningOverlay) this.warningOverlay.style.display = 'flex';
        
        var timeLeft = this.countdownTime;
        if (this.countdownSpan) this.countdownSpan.textContent = timeLeft;

        var self = this;
        this.countdownInterval = setInterval(function() {
            timeLeft--;
            if (self.countdownSpan) self.countdownSpan.textContent = timeLeft;
            if (timeLeft <= 0) {
                clearInterval(self.countdownInterval);
                self.isCountingDown = false;
                if (self.warningOverlay) self.warningOverlay.style.display = 'none';
                self.startGame();
            }
        }, 1000);
    }

    cancelCountdown() {
        if (!this.isCountingDown) return;
        clearInterval(this.countdownInterval);
        this.isCountingDown = false;
        if (this.warningOverlay) this.warningOverlay.style.display = 'none';
        this.resetIdleTimer();
    }

    updateLivesDisplay() {
        var hearts = '';
        for (var i = 0; i < this.lives; i++) hearts += '💚';
        for (var j = this.lives; j < 3; j++) hearts += '🖤';
        var livesEl = document.getElementById('glider-lives');
        if(livesEl) livesEl.innerHTML = hearts;
    }

    startGame() {
        if (this.isActive || !window.THREE) return;
        this.isActive = true;
        this.gameWon = false;
        this.score = 0;
        this.speed = 2.0;
        this.lives = 3;
        this.invulnerable = false;
        this.invulnerableTimer = 0;
        this.elixirSpawnedForScore = {};
        
        this.bossMessage.style.display = 'none';
        document.getElementById('glider-score').textContent = '0';
        this.updateLivesDisplay();
        
        this.overlay.style.display = 'flex';
        setTimeout(() => { this.overlay.style.opacity = '1'; }, 50);
        
        this.initThreeJS();
        this.animate();
    }

    stopGame() {
        if (!this.isActive) return;
        this.isActive = false;
        this.overlay.style.opacity = '0';
        
        var self = this;
        setTimeout(function() {
            self.overlay.style.display = 'none';
            if (self.animId) cancelAnimationFrame(self.animId);
            if (self.renderer) {
                self.renderer.dispose();
                self.overlay.removeChild(self.renderer.domElement);
                self.renderer = null;
            }
            self.scene = null;
            self.camera = null;
            self.resetIdleTimer();
        }, 800);
    }

    initThreeJS() {
        this.scene = new THREE.Scene();
        this.scene.fog = new THREE.FogExp2(0x06080d, 0.003);

        this.camera = new THREE.PerspectiveCamera(75, window.innerWidth / window.innerHeight, 0.1, 1000);
        this.camera.position.set(0, 0, 20);

        this.renderer = new THREE.WebGLRenderer({ alpha: true, antialias: true });
        this.renderer.setSize(window.innerWidth, window.innerHeight);
        this.overlay.appendChild(this.renderer.domElement);

        var tunnelGeo = new THREE.CylinderGeometry(this.tunnelRadius, this.tunnelRadius, 400, 16, 20, true);
        var tunnelMat = new THREE.MeshBasicMaterial({ color: 0x00F0FF, wireframe: true, transparent: true, opacity: 0.15 });
        this.tunnel = new THREE.Mesh(tunnelGeo, tunnelMat);
        this.tunnel.rotation.x = Math.PI / 2;
        this.scene.add(this.tunnel);

        var shipGeo = new THREE.TetrahedronGeometry(1.5, 0);
        var shipMat = new THREE.MeshBasicMaterial({ color: 0x00FF9D, wireframe: true });
        this.ship = new THREE.Mesh(shipGeo, shipMat);
        
        var shipGlowGeo = new THREE.TetrahedronGeometry(2, 0);
        var shipGlowMat = new THREE.MeshBasicMaterial({ color: 0x00FF9D, transparent: true, opacity: 0.3 });
        var shipGlow = new THREE.Mesh(shipGlowGeo, shipGlowMat);
        this.ship.add(shipGlow);
        
        this.ship.rotation.x = Math.PI / 4;
        this.scene.add(this.ship);

        this.obstacles = [];
        this.lasers = [];
        this.particles = [];
        this.elixirs = [];
        
        var obsGeo = new THREE.BoxGeometry(3, 3, 3);
        var obsMat = new THREE.MeshBasicMaterial({ color: 0xFF003C, wireframe: true });
        
        for (var i = 0; i < 20; i++) {
            var obs = new THREE.Mesh(obsGeo, obsMat);
            this.resetObstacle(obs, -200 - (Math.random() * 400));
            this.scene.add(obs);
            this.obstacles.push(obs);
        }
    }

    resetObstacle(obs, zPos) {
        var angle = Math.random() * Math.PI * 2;
        var r = Math.random() * (this.tunnelRadius - 5);
        obs.position.x = Math.cos(angle) * r;
        obs.position.y = Math.sin(angle) * r;
        obs.position.z = zPos;
        obs.rotation.set(Math.random()*Math.PI, Math.random()*Math.PI, 0);
        
        var homingProb = 0.2 + (this.score / 50000); 
        obs.isHoming = Math.random() < homingProb;
        obs.material.color.setHex(obs.isHoming ? 0xFFB800 : 0xFF003C);
    }

    spawnElixir() {
        var eGeo = new THREE.OctahedronGeometry(2, 0);
        var eMat = new THREE.MeshBasicMaterial({ color: 0x00A0FF, wireframe: false, transparent: true, opacity: 0.8 });
        var elix = new THREE.Mesh(eGeo, eMat);
        
        var angle = Math.random() * Math.PI * 2;
        var r = Math.random() * (this.tunnelRadius - 10);
        elix.position.set(Math.cos(angle) * r, Math.sin(angle) * r, -300);
        
        this.scene.add(elix);
        this.elixirs.push(elix);
    }

    fireLaser() {
        if (!this.isActive || !this.ship || this.gameWon) return;
        if (typeof audioSynth !== 'undefined' && audioSynth) audioSynth.play('laser');

        var lGeo = new THREE.CylinderGeometry(0.2, 0.2, 4, 8);
        var lMat = new THREE.MeshBasicMaterial({ color: 0x00FF9D });
        var laser = new THREE.Mesh(lGeo, lMat);
        
        laser.rotation.x = Math.PI / 2;
        laser.position.copy(this.ship.position);
        laser.position.z -= 2; 
        
        this.scene.add(laser);
        this.lasers.push(laser);
    }

    createExplosion(x, y, z, color) {
        if (typeof audioSynth !== 'undefined' && audioSynth) audioSynth.play('explosion');
        var pGeo = new THREE.BoxGeometry(0.5, 0.5, 0.5);
        var pMat = new THREE.MeshBasicMaterial({ color: color || 0xFFB800 });
        for (var i = 0; i < 15; i++) {
            var p = new THREE.Mesh(pGeo, pMat);
            p.position.set(x, y, z);
            p.vx = (Math.random() - 0.5) * 2;
            p.vy = (Math.random() - 0.5) * 2;
            p.vz = (Math.random() - 0.5) * 2;
            p.life = 1.0;
            this.scene.add(p);
            this.particles.push(p);
        }
    }

    takeDamage() {
        this.lives--;
        this.updateLivesDisplay();
        
        if (this.lives <= 0) {
            this.fullCrash();
            return;
        }

        if (typeof audioSynth !== 'undefined' && audioSynth) audioSynth.play('gameCrash');
        this.camera.position.x += (Math.random() - 0.5) * 4;
        this.camera.position.y += (Math.random() - 0.5) * 4;
        this.overlay.style.boxShadow = 'inset 0 0 100px rgba(255,0,60,0.6)';
        setTimeout(() => { this.overlay.style.boxShadow = 'none'; }, 200);

        this.invulnerable = true;
        this.invulnerableTimer = 120; // 2 seconds at 60fps
    }

    fullCrash() {
        if (typeof audioSynth !== 'undefined' && audioSynth) audioSynth.play('gameCrash');
        
        this.camera.position.x += (Math.random() - 0.5) * 8;
        this.camera.position.y += (Math.random() - 0.5) * 8;
        
        this.overlay.style.boxShadow = 'inset 0 0 150px rgba(255,0,60,0.9)';
        setTimeout(() => { this.overlay.style.boxShadow = 'none'; }, 300);

        this.score = 0;
        this.speed = 2.0;
        this.lives = 3;
        this.elixirSpawnedForScore = {};
        this.updateLivesDisplay();
        document.getElementById('glider-score').textContent = '0';
        
        for (var i = 0; i < this.obstacles.length; i++) {
            this.resetObstacle(this.obstacles[i], -200 - (Math.random() * 400));
        }
    }

    showBossMessage() {
        this.gameWon = true;
        this.bossMessage.style.display = 'flex';
        var self = this;
        setTimeout(function() {
            self.stopGame();
        }, 4000);
    }

    animate() {
        if (!this.isActive) return;
        var self = this;
        this.animId = requestAnimationFrame(function() { self.animate(); });

        if (this.gameWon) {
            this.ship.rotation.y += 0.1;
            this.renderer.render(this.scene, this.camera);
            return;
        }

        this.score += 1;
        var currentDisplayScore = Math.floor(this.score / 10);
        
        if (this.score % 60 === 0) {
            document.getElementById('glider-score').textContent = currentDisplayScore;
            this.speed += 0.01; 
        }

        // Spawn Elixir every 200 points
        if (currentDisplayScore > 0 && currentDisplayScore % 200 === 0 && !this.elixirSpawnedForScore[currentDisplayScore]) {
            this.spawnElixir();
            this.elixirSpawnedForScore[currentDisplayScore] = true;
        }

        // Win condition
        if (currentDisplayScore >= 1500) {
            this.showBossMessage();
        }

        // Handle Invulnerability Blink
        if (this.invulnerable) {
            this.invulnerableTimer--;
            this.ship.visible = (this.invulnerableTimer % 10) > 5;
            if (this.invulnerableTimer <= 0) {
                this.invulnerable = false;
                this.ship.visible = true;
            }
        }

        // Steer ship
        this.target.x = this.mouse.x * (this.tunnelRadius - 2);
        this.target.y = this.mouse.y * (this.tunnelRadius - 2);
        
        this.ship.position.x += (this.target.x - this.ship.position.x) * 0.1;
        this.ship.position.y += (this.target.y - this.ship.position.y) * 0.1;
        
        this.ship.rotation.z = (this.target.x - this.ship.position.x) * -0.05;
        this.ship.rotation.x = Math.PI / 4 + (this.target.y - this.ship.position.y) * 0.05;

        // Anti-Cheat Tunnel boundary Check
        var distFromCenter = Math.sqrt(this.ship.position.x**2 + this.ship.position.y**2);
        if (distFromCenter > this.tunnelRadius - 1.5 && !this.invulnerable) {
            this.takeDamage();
            this.ship.position.x = 0;
            this.ship.position.y = 0;
        }

        this.tunnel.rotation.y += 0.005;
        this.tunnel.position.z += this.speed;
        if (this.tunnel.position.z > 20) this.tunnel.position.z = 0;

        // Update Lasers
        for (var i = this.lasers.length - 1; i >= 0; i--) {
            var l = this.lasers[i];
            l.position.z -= this.speed * 4;
            if (l.position.z < -400) {
                this.scene.remove(l);
                this.lasers.splice(i, 1);
            }
        }

        // Update Elixirs
        for (var e = this.elixirs.length - 1; e >= 0; e--) {
            var elx = this.elixirs[e];
            elx.position.z += this.speed * 1.5;
            elx.rotation.x += 0.05; elx.rotation.y += 0.05;

            var dx = elx.position.x - this.ship.position.x;
            var dy = elx.position.y - this.ship.position.y;
            var dz = elx.position.z - this.ship.position.z;
            
            // Collision with ship
            if (dx*dx + dy*dy + dz*dz < 20) {
                if (typeof audioSynth !== 'undefined' && audioSynth) audioSynth.play('powerup');
                this.createExplosion(elx.position.x, elx.position.y, elx.position.z, 0x00A0FF);
                if (this.lives < 3) {
                    this.lives++;
                    this.updateLivesDisplay();
                }
                this.scene.remove(elx);
                this.elixirs.splice(e, 1);
                continue;
            }

            // Collision with lasers
            var hitLaser = false;
            for (var jl = this.lasers.length - 1; jl >= 0; jl--) {
                var lasl = this.lasers[jl];
                var ldxl = elx.position.x - lasl.position.x;
                var ldyl = elx.position.y - lasl.position.y;
                var ldzl = elx.position.z - lasl.position.z;
                if (ldxl*ldxl + ldyl*ldyl + ldzl*ldzl < 15) {
                    if (typeof audioSynth !== 'undefined' && audioSynth) audioSynth.play('powerup');
                    this.createExplosion(elx.position.x, elx.position.y, elx.position.z, 0x00A0FF);
                    if (this.lives < 3) {
                        this.lives++;
                        this.updateLivesDisplay();
                    }
                    this.scene.remove(lasl);
                    this.lasers.splice(jl, 1);
                    this.scene.remove(elx);
                    this.elixirs.splice(e, 1);
                    hitLaser = true;
                    break;
                }
            }

            if (!hitLaser && elx.position.z > 25) {
                this.scene.remove(elx);
                this.elixirs.splice(e, 1);
            }
        }

        // Update Obstacles
        for (var i = 0; i < this.obstacles.length; i++) {
            var obs = this.obstacles[i];
            obs.position.z += this.speed * 1.5;
            obs.rotation.x += 0.02; obs.rotation.y += 0.02;

            if (obs.isHoming) {
                obs.position.x += (this.ship.position.x - obs.position.x) * 0.015;
                obs.position.y += (this.ship.position.y - obs.position.y) * 0.015;
            }

            // Ship Collision
            if (!this.invulnerable) {
                var cdx = obs.position.x - this.ship.position.x;
                var cdy = obs.position.y - this.ship.position.y;
                var cdz = obs.position.z - this.ship.position.z;
                if (cdx*cdx + cdy*cdy + cdz*cdz < 12) {
                    this.takeDamage();
                    this.resetObstacle(obs, -300);
                    continue;
                }
            }

            // Laser Collision
            var hitObsLaser = false;
            for (var j = this.lasers.length - 1; j >= 0; j--) {
                var las = this.lasers[j];
                var ldx = obs.position.x - las.position.x;
                var ldy = obs.position.y - las.position.y;
                var ldz = obs.position.z - las.position.z;
                if (ldx*ldx + ldy*ldy + ldz*ldz < 15) {
                    this.createExplosion(obs.position.x, obs.position.y, obs.position.z, 0xFFB800);
                    this.resetObstacle(obs, -300 - (Math.random() * 200));
                    this.score += 500; 
                    
                    this.scene.remove(las);
                    this.lasers.splice(j, 1);
                    hitObsLaser = true;
                    break;
                }
            }

            if (!hitObsLaser && obs.position.z > 25) {
                this.resetObstacle(obs, -300 - (Math.random() * 200));
            }
        }

        // Update Particles
        for (var p = this.particles.length - 1; p >= 0; p--) {
            var part = this.particles[p];
            part.position.x += part.vx;
            part.position.y += part.vy;
            part.position.z += part.vz;
            part.life -= 0.05;
            part.scale.set(part.life, part.life, part.life);
            if (part.life <= 0) {
                this.scene.remove(part);
                this.particles.splice(p, 1);
            }
        }

        // Camera follow
        this.camera.position.x += (this.ship.position.x * 0.3 - this.camera.position.x) * 0.1;
        this.camera.position.y += (this.ship.position.y * 0.3 - this.camera.position.y) * 0.1;

        this.renderer.render(this.scene, this.camera);
    }
}

// ══════════════════════════════════════════════════════════════════════════
// §AC  INITIALIZATION / BOOTSTRAP
// ══════════════════════════════════════════════════════════════════════════
var webglEngine = null;
var uiAnimator = null;
var audioSynth = null;
var cursorSystem = null;
var dataScramble = null;
var explodedView = null;
var idleMiniGame = null;

document.addEventListener('DOMContentLoaded', function() {
    webglEngine = new WebGLEngine();
    uiAnimator = new UIAnimator();
    audioSynth = new AudioSynth();
    cursorSystem = new CursorSystem();
    dataScramble = new DataScramble();
    explodedView = new ExplodedView();
    idleMiniGame = new IdleMiniGame();

    initThemeSystem();
    runBootSequence();
    initializeMatrixRain();
    initParticles();
    setTimeout(initTiltCards, 100);

    updateLanguageBadge(CL);

    var gameBtn = document.getElementById('mini-game-btn');
    if (gameBtn) {
        gameBtn.addEventListener('click', function() {
            if (idleMiniGame) idleMiniGame.startGame();
        });
    }

    var logoutBtn = document.getElementById('logout-btn');
    if (logoutBtn) {
        logoutBtn.addEventListener('click', function(e) {
            e.preventDefault();
            logout();
        });
    }

    document.querySelectorAll('.lang-item[data-lang]').forEach(function(btn) {
        btn.addEventListener('click', function(e) {
            e.preventDefault();
            e.stopPropagation();
            switchLanguage(this.getAttribute('data-lang'));
        });
    });

    var audioBtn = document.getElementById('audio-toggle-btn');
    if (audioBtn) {
        audioBtn.addEventListener('click', function() {
            var muted = audioSynth.toggle();
            this.textContent = muted ? '\u{1F507}' : '\u{1F50A}';
            this.classList.toggle('muted', muted);
        });
    }

    var explodeBtn = document.getElementById('explode-toggle-btn');
    if (explodeBtn) {
        explodeBtn.addEventListener('click', function() {
            explodedView.toggle();
            this.classList.toggle('active', explodedView.isExploded);
        });
    }

    var cliToggle = document.getElementById('cli-toggle');
    if (cliToggle) {
        cliToggle.addEventListener('click', function() {
            toggleCLI();
        });
    }

    var loginPw = document.getElementById('loginPassword');
    var loginBtnEl = document.getElementById('loginBtn');

    if (loginPw) {
        var katakana = '\u30A2\u30A4\u30A6\u30A8\u30A8\u30A8\u30EB\u30AA\u30AD\u30AF\u30B3\u30B1\u30B3\u30B5\u30B3\u30BD\u30BD\u30BB\u30BD\u30BF\u30BF\u30C1\u30C4\u30C6\u30C8\u30BF\u30BF\u30CA\u30CB\u30CD\u30CE\u30CE\u30CF\u30CF\u30DB\u30DB\u30DE\u30D2\u30D5\u30D8\u30DB\u30DE\u30DB\u30DE\u30DE\u30F3\u30F3\u30F3\u30E0\u30DF\u30E1\u30E2\u30E6\u30E9\u30EA\u30EA\u30EA\u30EA\u30EB\u30EC\u30ED\u30EF\u30F3';
        var pwScrambleTimer = null;

        loginPw.addEventListener('input', function() {
            var real = this.value;
            if (!real) return;
            var len = real.length;
            this.type = 'text';
            this.style.letterSpacing = '3px';
            this.style.color = 'var(--accent)';
            var count = 0;
            clearInterval(pwScrambleTimer);

            pwScrambleTimer = setInterval(function() {
                var display = '';
                for (var si = 0; si < len; si++) {
                    if (si < len - 1) display += katakana[Math.floor(Math.random() * katakana.length)];
                    else display += real[si];
                }
                loginPw.value = display;
                count++;
                if (count > 5) {
                    clearInterval(pwScrambleTimer);
                    loginPw.value = real;
                    loginPw.type = 'password';
                }
            }, 40);
        });

        var orb = document.getElementById('airlock-orb');
        if (orb) {
            loginPw.addEventListener('focus', function() { orb.classList.add('secure'); });
            loginPw.addEventListener('blur', function() { orb.classList.remove('secure'); });
        }
    }

    if (loginBtnEl) {
        loginBtnEl.addEventListener('click', function(e) {
            e.preventDefault();
            var pw = document.getElementById('loginPassword').value;
            if (pw) performLogin(pw);
        });
    }

    if (loginPw) {
        loginPw.addEventListener('keydown', function(e) {
            if (e.key === 'Enter') {
                e.preventDefault();
                if (this.value) performLogin(this.value);
            }
        });
    }

    var airlockOrb = document.getElementById('airlock-orb');
    if (airlockOrb) {
        var airlockContainer = airlockOrb.closest('.airlock-container');
        if (airlockContainer) {
            airlockContainer.addEventListener('mousemove', function(e) {
                var rect = airlockOrb.getBoundingClientRect();
                var cx = rect.left + rect.width / 2;
                var cy = rect.top + rect.height / 2;
                var dx = (e.clientX - cx) * 0.15;
                var dy = (e.clientY - cy) * 0.15;
                airlockOrb.style.transform = 'translate(' + dx + 'px, ' + dy + 'px)';
            });
            airlockContainer.addEventListener('mouseleave', function() {
                airlockOrb.style.transform = '';
            });
        }
    }

    var searchInput = document.getElementById('search-input');
    var filterTool = document.getElementById('filter-tool');
    var filterSev = document.getElementById('filter-severity');
    if (searchInput) searchInput.addEventListener('input', applyFilters);
    if (filterTool) filterTool.addEventListener('change', applyFilters);
    if (filterSev) filterSev.addEventListener('change', applyFilters);

    var chartResizeTimer = null;
    window.addEventListener('resize', function() {
        clearTimeout(chartResizeTimer);
        chartResizeTimer = setTimeout(function() {
            if (severityChartInstance) severityChartInstance.resize();
            if (trendChartInstance && !isTrend3D) trendChartInstance.resize();
            
            if (typeof active3DScenes !== 'undefined') {
                active3DScenes.forEach(function(sceneObj) {
                    var w = sceneObj.container.clientWidth || 800;
                    var h = sceneObj.container.clientHeight || 400;
                    if (sceneObj.renderer) {
                        sceneObj.renderer.setSize(w, h);
                        sceneObj.camera.aspect = w / h;
                        sceneObj.camera.updateProjectionMatrix();
                    }
                });
            }
        }, 200);
    });

    document.addEventListener('visibilitychange', function() {
        if (document.visibilityState === 'hidden') {
            if (webglEngine) webglEngine.pause();
        } else {
            if (webglEngine) webglEngine.resume();
        }
    });

    document.addEventListener('keydown', function(e) {
        if (e.key === 'Escape') {
            if (document.getElementById('reportModal').classList.contains('open')) closeReportModal();
            if (document.getElementById('ragModal').classList.contains('open')) closeRagModal();
            if (document.getElementById('simOverlay').classList.contains('open')) closeSimPanel();
        }
    });

    var modalIds = ['reportModal', 'ragModal', 'simOverlay'];
    modalIds.forEach(function(id) {
        var el = document.getElementById(id);
        if (el) {
            el.addEventListener('click', function(e) {
                if (e.target === this) {
                    if (id === 'reportModal') closeReportModal();
                    else if (id === 'ragModal') closeRagModal();
                    else if (id === 'simOverlay') closeSimPanel();
                }
            });
        }
    });

    var themeColorMap = {
        cyber: 0x00F0FF,
        crimson: 0xFF2D55,
        emerald: 0x00FF9D,
        amber: 0xFFB800
    };
    document.querySelectorAll('.theme-dot').forEach(function(dot) {
        dot.addEventListener('click', function() {
            var theme = this.getAttribute('data-theme');
            if (webglEngine && themeColorMap[theme]) {
                webglEngine.updateColor(themeColorMap[theme]);
            }
        });
    });
});