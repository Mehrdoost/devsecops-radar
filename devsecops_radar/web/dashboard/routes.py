import json
import os

from flask import Blueprint, jsonify, render_template_string, request, send_file

from devsecops_radar.core.auth import login_required
from devsecops_radar.core.database import get_all_scans, get_findings_paginated
from devsecops_radar.core.rag import rag_search
from devsecops_radar.core.reporting import generate_pdf_report

dashboard_bp = Blueprint('dashboard', __name__)

FINDINGS_FILE = os.environ.get('FINDINGS_FILE', 'findings.json')

DASHBOARD_HTML = r"""<!DOCTYPE html>
<html lang="en" data-theme="cyber">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Pipeline Sentinel – Command Center</title>
    <link rel="stylesheet"
          href="{{ url_for('static', filename='css/bootstrap.min.css') }}">
    <style>
        :root, [data-theme="cyber"] {
            --bg-primary: #0A0E17; --bg-secondary: #121C2E;
            --bg-tertiary: #1A2740; --accent: #00E5FF;
            --accent-glow: rgba(0,229,255,0.25); --accent-2: #7C3AED;
            --text: #E2E8F0; --text-secondary: #94A3B8;
            --danger: #FF4D6D; --warning: #FFB100;
            --info: #00B4D8; --success: #06D6A0;
            --glass: rgba(18,28,46,0.7);
            --glass-border: rgba(255,255,255,0.06);
            --card-shadow: 0 4px 24px rgba(0,0,0,0.4);
            --particle-color: rgba(0,229,255,0.15);
            --table-bg: transparent; --table-text: var(--text);
            --table-hover-bg: rgba(255,255,255,0.04);
            --table-border: rgba(255,255,255,0.06);
        }
        [data-theme="midnight"] {
            --bg-primary: #0B0E14; --bg-secondary: #161B24;
            --bg-tertiary: #1E2532; --accent: #6366F1;
            --accent-glow: rgba(99,102,241,0.25); --accent-2: #8B5CF6;
            --text: #F1F5F9; --text-secondary: #64748B;
            --danger: #EF4444; --warning: #F59E0B;
            --info: #3B82F6; --success: #10B981;
            --glass: rgba(22,27,36,0.7);
            --glass-border: rgba(255,255,255,0.05);
            --card-shadow: 0 4px 24px rgba(0,0,0,0.5);
            --particle-color: rgba(99,102,241,0.12);
            --table-bg: transparent; --table-text: var(--text);
            --table-hover-bg: rgba(255,255,255,0.04);
            --table-border: rgba(255,255,255,0.05);
        }
        [data-theme="arctic"] {
            --bg-primary: #F8FAFC; --bg-secondary: #FFFFFF;
            --bg-tertiary: #F1F5F9; --accent: #0284C7;
            --accent-glow: rgba(2,132,199,0.15); --accent-2: #0EA5E9;
            --text: #0F172A; --text-secondary: #475569;
            --danger: #DC2626; --warning: #D97706;
            --info: #0284C7; --success: #059669;
            --glass: rgba(255,255,255,0.85);
            --glass-border: rgba(0,0,0,0.08);
            --card-shadow: 0 4px 24px rgba(0,0,0,0.08);
            --particle-color: rgba(2,132,199,0.1);
            --table-bg: rgba(0,0,0,0.02); --table-text: var(--text);
            --table-hover-bg: rgba(0,0,0,0.04);
            --table-border: rgba(0,0,0,0.08);
        }
        [data-theme="forest"] {
            --bg-primary: #0F1A14; --bg-secondary: #162819;
            --bg-tertiary: #1C3423; --accent: #34D399;
            --accent-glow: rgba(52,211,153,0.25); --accent-2: #6EE7B7;
            --text: #ECFDF5; --text-secondary: #6B7280;
            --danger: #F87171; --warning: #FBBF24;
            --info: #60A5FA; --success: #34D399;
            --glass: rgba(22,40,25,0.7);
            --glass-border: rgba(255,255,255,0.06);
            --card-shadow: 0 4px 24px rgba(0,0,0,0.4);
            --particle-color: rgba(52,211,153,0.12);
            --table-bg: transparent; --table-text: var(--text);
            --table-hover-bg: rgba(255,255,255,0.04);
            --table-border: rgba(255,255,255,0.06);
        }
        [data-theme="dark"] {
            --bg-primary: #111111; --bg-secondary: #1A1A1A;
            --bg-tertiary: #252525; --accent: #3B82F6;
            --accent-glow: rgba(59,130,246,0.3); --accent-2: #1D4ED8;
            --text: #EEEEEE; --text-secondary: #AAAAAA;
            --danger: #EF4444; --warning: #F59E0B;
            --info: #3B82F6; --success: #10B981;
            --glass: rgba(26,26,26,0.7);
            --glass-border: rgba(255,255,255,0.08);
            --card-shadow: 0 4px 24px rgba(0,0,0,0.6);
            --particle-color: rgba(59,130,246,0.15);
            --table-bg: transparent; --table-text: var(--text);
            --table-hover-bg: rgba(255,255,255,0.04);
            --table-border: rgba(255,255,255,0.08);
        }
        body { background: var(--bg-primary); color: var(--text);
            font-family: 'Inter', system-ui, -apple-system, sans-serif;
            margin: 0; padding: 0; overflow-x: hidden;
            font-size: 15px; line-height: 1.6;
            transition: background 0.4s ease, color 0.4s ease; }
        #particles-canvas { position: fixed; top: 0; left: 0;
            width: 100%; height: 100%; z-index: 0; pointer-events: none; }
        .content-layer { position: relative; z-index: 1; }
        .navbar { background: var(--glass) !important;
            border-bottom: 1px solid var(--glass-border);
            backdrop-filter: blur(20px); -webkit-backdrop-filter: blur(20px); }
        .navbar-brand { font-weight: 800; letter-spacing: -1px;
            color: var(--accent) !important; font-size: 1.5rem; }
        .card { background: var(--glass); border: 1px solid var(--glass-border);
            border-radius: 20px; transition: all 0.35s ease;
            backdrop-filter: blur(14px); -webkit-backdrop-filter: blur(14px);
            box-shadow: var(--card-shadow); }
        .card:hover { border-color: var(--accent);
            box-shadow: 0 0 45px var(--accent-glow), var(--card-shadow);
            transform: translateY(-3px); }
        .stat-pill { background: linear-gradient(135deg, var(--glass) 0%,
            rgba(0,0,0,0.35) 100%); border-radius: 18px; padding: 24px 30px;
            font-weight: 600; border: 1px solid var(--glass-border);
            cursor: pointer; transition: all 0.25s; }
        .stat-pill:hover { border-color: var(--accent);
            box-shadow: 0 0 25px var(--accent-glow); }
        .stat-pill span { font-size: 3rem; font-weight: 800; }
        .stat-pill .icon { font-size: 2rem; margin-bottom: 6px; }
        .btn-accent { background: linear-gradient(135deg, var(--accent),
            var(--accent-2)); color: #fff; border: none; font-weight: 600;
            border-radius: 14px; padding: 14px 28px; transition: all 0.25s;
            font-size: 1rem; display: inline-flex; align-items: center; gap: 8px; }
        .btn-accent:hover { box-shadow: 0 0 35px var(--accent-glow);
            transform: scale(1.04); }
        .btn-accent:disabled { opacity: 0.5; cursor: not-allowed; transform: none; }
        .btn-outline-accent { background: transparent; border: 1px solid var(--accent);
            color: var(--accent); border-radius: 14px; padding: 12px 22px;
            font-weight: 600; transition: all 0.2s; font-size: 0.9rem; }
        .btn-outline-accent:hover { background: var(--accent);
            color: #000; box-shadow: 0 0 25px var(--accent-glow); }
        .findings-table { background: var(--table-bg); color: var(--table-text);
            border-radius: 18px; overflow: hidden; }
        .findings-table th { border-bottom: 2px solid var(--table-border);
            color: var(--accent); font-weight: 600; text-transform: uppercase;
            font-size: 0.8rem; letter-spacing: 0.9px; }
        .findings-table td, .findings-table th { padding: 18px 22px;
            vertical-align: middle; }
        .findings-table tbody tr { cursor: pointer; transition: background 0.2s; }
        .findings-table tbody tr:hover { background: var(--table-hover-bg); }
        .finding-detail { display: none; background: var(--bg-tertiary);
            border-radius: 12px; padding: 16px 20px; margin: 8px 0;
            color: var(--text); }
        .finding-detail.show { display: block; }
        #attack-graph { background: var(--bg-tertiary);
            border-radius: 18px; border: 1px solid var(--glass-border); }
        .sim-overlay { position: fixed; top: 0; left: 0; width: 100%; height: 100%;
            background: rgba(0,0,0,0.7); backdrop-filter: blur(6px);
            display: none; z-index: 2000; align-items: center;
            justify-content: center; }
        .sim-overlay.open { display: flex; animation: fadeIn 0.25s ease; }
        .sim-panel { background: var(--glass); border: 1px solid var(--glass-border);
            border-radius: 22px; padding: 32px; max-width: 700px;
            width: 90%; max-height: 80vh; overflow-y: auto;
            backdrop-filter: blur(20px); box-shadow: 0 0 60px var(--accent-glow);
            position: relative; }
        .sim-close { position: absolute; top: 16px; right: 20px;
            background: none; border: none; color: var(--text-secondary);
            font-size: 1.8rem; cursor: pointer; transition: color 0.2s; }
        .sim-close:hover { color: var(--danger); }
        @keyframes fadeIn { from { opacity: 0; } to { opacity: 1; } }
        .clock-pill { font-family: 'SF Mono', 'Fira Code', monospace;
            font-size: 0.9rem; color: var(--text); background: var(--glass);
            border: 1px solid var(--glass-border); border-radius: 12px;
            padding: 6px 16px; display: inline-flex; align-items: center;
            gap: 8px; backdrop-filter: blur(8px); }
        .theme-strip { position: fixed; top: 50%; left: 16px;
            transform: translateY(-50%); z-index: 1030;
            background: var(--glass); border: 1px solid var(--glass-border);
            border-radius: 30px; padding: 10px 8px;
            display: flex; flex-direction: column; gap: 10px;
            backdrop-filter: blur(14px); }
        .theme-strip .theme-dot { width: 24px; height: 24px; border-radius: 50%;
            cursor: pointer; border: 2px solid transparent; transition: all 0.25s; }
        .theme-strip .theme-dot:hover, .theme-strip .theme-dot.active {
            border-color: var(--text); transform: scale(1.3); }
        .theme-strip .theme-dot.active::after { content: ''; position: absolute;
            top: -4px; left: -4px; right: -4px; bottom: -4px;
            border-radius: 50%; border: 2px solid var(--accent); }
        .lang-btn { background: var(--glass); border: 1px solid var(--glass-border);
            color: var(--text); border-radius: 12px; padding: 8px 16px;
            font-size: 0.9rem; cursor: pointer; display: inline-flex;
            align-items: center; gap: 8px; transition: all 0.2s;
            backdrop-filter: blur(8px); }
        .lang-btn:hover { border-color: var(--accent); }
        .lang-menu { position: absolute; top: 100%; right: 0; margin-top: 8px;
            background: var(--bg-secondary); border: 1px solid var(--glass-border);
            border-radius: 12px; padding: 6px; min-width: 130px;
            box-shadow: var(--card-shadow); display: none; z-index: 1050; }
        .lang-menu.open { display: block; animation: slideDown 0.2s ease; }
        @keyframes slideDown {
            from { opacity: 0; transform: translateY(-10px); }
            to { opacity: 1; transform: translateY(0); }
        }
        .lang-menu .lang-item { padding: 8px 14px; border-radius: 8px;
            cursor: pointer; transition: background 0.2s; display: flex;
            align-items: center; gap: 10px; color: var(--text); }
        .lang-menu .lang-item:hover { background: var(--bg-tertiary); }
        .search-toggle { background: transparent; border: none; color: var(--text-secondary);
            font-size: 1.4rem; cursor: pointer; transition: color 0.3s; }
        .search-toggle:hover { color: var(--accent); }
        .search-wrapper { display: flex; align-items: center; gap: 8px; }
        #search-input-row { display: none; margin-top: 12px; }
        #search-input-row.expanded { display: block; }
        #search-input-row input { background: var(--bg-primary); color: var(--text);
            border: 1px solid var(--glass-border); border-radius: 30px;
            padding: 10px 18px; font-size: 0.9rem; width: 100%; }
        .cli-flag-card { background: var(--bg-tertiary); border-radius: 10px;
            padding: 16px; margin-bottom: 10px; transition: all 0.2s;
            border-left: 4px solid transparent; display: flex;
            align-items: flex-start; gap: 14px; }
        .cli-flag-card:hover { border-left-color: var(--accent);
            transform: translateX(4px); }
        .cli-flag-card .flag-icon { font-size: 1.8rem; color: var(--accent); }
        .cli-flag-card code { color: var(--accent); background: transparent;
            font-size: 0.95rem; display: block; margin-bottom: 4px; }
        .cli-flag-card .flag-desc { color: var(--text-secondary);
            font-size: 0.85rem; }
        .toggle-pill { background: var(--bg-tertiary);
            border: 1px solid var(--glass-border);
            color: var(--accent); border-radius: 30px; padding: 6px 18px;
            font-size: 0.85rem; font-weight: 600; transition: all 0.2s;
            display: inline-flex; align-items: center; gap: 8px; cursor: pointer; }
        .toggle-pill:hover { background: var(--accent); color: #000; }
        .toggle-pill .arrow { display: inline-block; transition: transform 0.3s; }
        .toggle-pill.expanded .arrow { transform: rotate(90deg); }
        .version-badge { background: var(--accent); color: #000;
            padding: 2px 10px; border-radius: 20px; font-size: 0.75rem;
            font-weight: 700; margin-left: 8px; }
        .ai-badge { background: var(--bg-tertiary); color: var(--text);
            padding: 4px 12px; border-radius: 20px; font-size: 0.8rem; }
        .report-dropdown { position: relative; display: inline-block; }
        .report-menu { position: absolute; bottom: 100%; left: 0;
            margin-bottom: 8px; background: var(--bg-secondary);
            border: 1px solid var(--glass-border); border-radius: 12px;
            padding: 6px; min-width: 150px;
            box-shadow: var(--card-shadow); display: none; z-index: 1050; }
        .report-menu.open { display: block; animation: slideUp 0.2s ease; }
        @keyframes slideUp {
            from { opacity: 0; transform: translateY(10px); }
            to { opacity: 1; transform: translateY(0); }
        }
        .report-menu .report-item { padding: 10px 16px; border-radius: 8px;
            cursor: pointer; transition: background 0.2s; display: flex;
            align-items: center; gap: 10px; color: var(--text); }
        .report-menu .report-item:hover { background: var(--bg-tertiary); }
        .chart-container { width: 100%; height: 250px; }
    </style>
</head>
<body>
    <canvas id="particles-canvas"></canvas>

    <!-- Vertical theme strip -->
    <div class="theme-strip" id="theme-strip">
        <span class="theme-dot active" data-theme="cyber"
              style="background:#00E5FF;" title="Cyber"
              onclick="switchTheme('cyber')"></span>
        <span class="theme-dot" data-theme="midnight"
              style="background:#6366F1;" title="Midnight"
              onclick="switchTheme('midnight')"></span>
        <span class="theme-dot" data-theme="arctic"
              style="background:#0284C7;" title="Arctic"
              onclick="switchTheme('arctic')"></span>
        <span class="theme-dot" data-theme="forest"
              style="background:#34D399;" title="Forest"
              onclick="switchTheme('forest')"></span>
        <span class="theme-dot" data-theme="dark"
              style="background:#3B82F6;" title="Dark"
              onclick="switchTheme('dark')"></span>
    </div>

    <div class="content-layer">
    <nav class="navbar navbar-dark">
        <div class="container-fluid">
            <span class="navbar-brand mb-0 h1">🛡️ Pipeline Sentinel
                <small style="font-size:0.6em;color:var(--text-secondary);">· Dashboard</small>
            </span>
            <div class="d-flex align-items-center gap-3">
                <div class="clock-pill" id="clock-pill">--</div>
                <div class="position-relative">
                    <button class="lang-btn" id="langDropdownBtn"
                            onclick="toggleLangMenu()">
                        <span>🌐</span>
                        <span id="current-lang-label">EN</span>
                        <span style="font-size:0.7rem;">▼</span>
                    </button>
                    <div class="lang-menu" id="langMenu">
                        <div class="lang-item"
                             onclick="switchLanguage('en')">🇬🇧 English</div>
                        <div class="lang-item"
                             onclick="switchLanguage('ru')">🇷🇺 Русский</div>
                        <div class="lang-item"
                             onclick="switchLanguage('zh')">🇨🇳 中文</div>
                    </div>
                </div>
            </div>
        </div>
    </nav>

    <div class="container py-4 fade-in-up">
        <!-- Stats Row -->
        <div class="row g-3 mb-4" id="stats-row">
            <div class="col-md-3">
                <div class="card p-3 text-center"
                     onclick="filterBySeverity('CRITICAL')">
                    <div class="stat-pill text-danger">
                        <div class="icon">🔥</div>
                        <span id="stat-critical">0</span><br>
                        <small data-i18n="critical">CRITICAL</small>
                    </div>
                </div>
            </div>
            <div class="col-md-3">
                <div class="card p-3 text-center"
                     onclick="filterBySeverity('HIGH')">
                    <div class="stat-pill text-warning">
                        <div class="icon">⚠️</div>
                        <span id="stat-high">0</span><br>
                        <small data-i18n="high">HIGH</small>
                    </div>
                </div>
            </div>
            <div class="col-md-3">
                <div class="card p-3 text-center"
                     onclick="filterBySeverity('MEDIUM')">
                    <div class="stat-pill text-info">
                        <div class="icon">📊</div>
                        <span id="stat-medium">0</span><br>
                        <small data-i18n="medium">MEDIUM</small>
                    </div>
                </div>
            </div>
            <div class="col-md-3">
                <div class="card p-3 text-center"
                     onclick="filterBySeverity('LOW')">
                    <div class="stat-pill text-primary">
                        <div class="icon">ℹ️</div>
                        <span id="stat-low">0</span><br>
                        <small data-i18n="low">LOW</small>
                    </div>
                </div>
            </div>
        </div>

        <!-- Charts Row -->
        <div class="row g-3 mb-4">
            <div class="col-md-6">
                <div class="card p-4">
                    <h5 class="card-title" style="color:var(--accent)">
                        📊 <span data-i18n="severity_breakdown">Severity Breakdown</span>
                    </h5>
                    <div id="severityChart" class="chart-container"></div>
                </div>
            </div>
            <div class="col-md-6">
                <div class="card p-4">
                    <h5 class="card-title" style="color:var(--accent)">
                        📈 <span data-i18n="trend_over_time">Trend Over Time</span>
                    </h5>
                    <div id="trendChart" class="chart-container"></div>
                </div>
            </div>
        </div>

        <!-- Attack Paths -->
        <div class="row g-3 mb-4">
            <div class="col-12">
                <div class="card p-4 pulse-glow">
                    <div class="d-flex justify-content-between align-items-center mb-3">
                        <h5 class="card-title" style="color:var(--accent)">
                            🕸️ <span data-i18n="attack_paths">Attack Paths (AI‑Generated)</span>
                        </h5>
                        <div class="d-flex align-items-center gap-2">
                            <span class="ai-badge" id="ai-status">
                                🤖 <span data-i18n="no_ai">Run with --analyze</span>
                            </span>
                            <button class="btn-accent" id="simulate-selected-btn" disabled>
                                ⚡ <span data-i18n="simulate_selected">Simulate Selected</span>
                            </button>
                        </div>
                    </div>
                    <div id="attack-graph"
                         style="width:100%; height:400px; position:relative;"></div>
                    <div id="attack-detail" class="mt-3 p-3 rounded"
                         style="display:none; background:var(--bg-tertiary);"></div>
                    <div id="attack-error" class="text-warning mt-2"
                         style="display:none;"></div>
                </div>
            </div>
        </div>

        <!-- AI Summary -->
        <div class="row g-3 mb-4">
            <div class="col-12">
                <div class="card p-4">
                    <h5 class="card-title" style="color:var(--accent)">
                        🧠 <span data-i18n="ai_summary">AI Executive Summary</span>
                    </h5>
                    <div id="exec-summary" class="text-muted"
                         data-i18n="no_ai">No AI analysis available. Run with --analyze.</div>
                    <div id="risk-score" class="mt-2"></div>
                </div>
            </div>
        </div>

        <!-- CLI Quick Reference -->
        <div class="row g-3 mb-4">
            <div class="col-12">
                <div class="card p-4">
                    <div class="d-flex justify-content-between align-items-center">
                        <h5 class="card-title mb-0" style="color:var(--accent)">
                            ⚙️ <span data-i18n="cli_ref_title">CLI Quick Reference</span>
                        </h5>
                        <span class="toggle-pill" id="cli-toggle" onclick="toggleCLI()">
                            <span data-i18n="show_hide">Show</span>
                            <span class="arrow">▶</span>
                        </span>
                    </div>
                    <div class="collapse mt-3" id="cli-ref-body">
                        <div class="row" id="cli-ref-cards"></div>
                    </div>
                </div>
            </div>
        </div>

        <!-- Findings Table -->
        <div class="card p-4 mb-4" id="findings-section">
            <div class="d-flex justify-content-between align-items-center mb-3 flex-wrap gap-2">
                <div class="d-flex align-items-center gap-2">
                    <span class="search-toggle" id="search-toggle-btn" title="Search">🔍</span>
                    <h5 class="card-title mb-0" style="color:var(--accent)">
                        <span data-i18n="findings">Findings</span>
                    </h5>
                </div>
                <div class="d-flex align-items-center gap-2">
                    <div class="report-dropdown">
                        <button class="btn-accent" id="report-btn" onclick="toggleReportMenu()">
                            📄 <span data-i18n="generate_report">Report</span>
                        </button>
                        <div class="report-menu" id="reportMenu">
                            <div class="report-item" onclick="downloadReport('pdf')">📕 PDF</div>
                            <div class="report-item" onclick="downloadReport('json')">📦 JSON</div>
                            <div class="report-item" onclick="downloadReport('html')">🌐 HTML</div>
                        </div>
                    </div>
                    <button class="btn-outline-accent" id="clear-filters-btn">
                        ✕ <span data-i18n="clear_filters">Clear</span>
                    </button>
                </div>
            </div>
            <div id="search-input-row">
                <input type="text" id="searchInput"
                       placeholder="Search findings..." data-i18n-placeholder="search_placeholder">
            </div>
            <div class="table-responsive">
                <table class="findings-table table table-hover align-middle">
                    <thead><tr>
                        <th><input type="checkbox" id="select-all"></th>
                        <th data-i18n="tool">Tool</th>
                        <th data-i18n="id_col">ID</th>
                        <th data-i18n="severity">Severity</th>
                        <th data-i18n="target">Target</th>
                        <th data-i18n="description">Description</th>
                    </tr></thead>
                    <tbody id="tableBody"></tbody>
                </table>
            </div>
        </div>

        <!-- Custom Simulation Overlay (no Bootstrap modal) -->
        <div class="sim-overlay" id="simOverlay">
            <div class="sim-panel">
                <button class="sim-close" onclick="closeSimPanel()">&times;</button>
                <div id="sim-panel-content">
                    <div class="text-center">
                        <div class="spinner-border" style="color:var(--accent)"></div>
                        <p class="mt-2" data-i18n="simulating">Simulating attack chain...</p>
                    </div>
                </div>
            </div>
        </div>

        <!-- Toast container -->
        <div class="toast-container position-fixed bottom-0 end-0 p-3" id="toast-container"></div>

        <footer class="text-center text-muted py-3 border-top border-secondary mt-4">
            <small>🛡️ <strong>Pipeline Sentinel</strong> · crafted by
                <a href="https://github.com/Mehrdoost"
                   class="text-decoration-none"
                   style="color:var(--accent)" target="_blank">Mehrdoost</a>
                <span class="version-badge">v0.5.0</span> ·
                <a href="https://github.com/Mehrdoost/devsecops-radar"
                   class="text-decoration-none"
                   style="color:var(--accent)" target="_blank">View on GitHub</a>
            </small>
        </footer>
    </div>
    </div>

    <script src="{{ url_for('static', filename='js/bootstrap.bundle.min.js') }}"></script>
    <script src="{{ url_for('static', filename='js/echarts.min.js') }}"></script>
    <script src="{{ url_for('static', filename='js/d3.v7.min.js') }}"></script>
    <script>
        // --- i18n (full dictionaries) ---
        const T = {
            en: { critical: "CRITICAL", high: "HIGH", medium: "MEDIUM", low: "LOW",
                severity_breakdown: "Severity Breakdown",
                trend_over_time: "Trend Over Time",
                attack_paths: "Attack Paths (AI‑Generated)",
                simulate_selected: "Simulate Selected",
                findings: "Findings", tool: "Tool", id_col: "ID",
                severity: "Severity", target: "Target", description: "Description",
                close: "Close", attack_simulation: "Attack Simulation",
                search_placeholder: "Search findings...",
                simulating: "Simulating attack chain...",
                no_ai: "Run with --analyze to enable AI insights",
                generate_report: "Report",
                clear_filters: "Clear",
                ai_summary: "AI Executive Summary",
                report_loading: "Generating report...",
                report_success: "Report downloaded!",
                report_failed: "Report generation failed.",
                cli_ref_title: "CLI Quick Reference",
                show_hide: "Show",
                hide: "Hide",
                no_format_selected: "No format selected — report not generated.",
                trivy_desc: "Trivy JSON file or image name",
                semgrep_desc: "Semgrep JSON file or target directory",
                poutine_desc: "Poutine JSON file or repository path",
                zizmor_desc: "Zizmor JSON file or repository path",
                gitleaks_desc: "Gitleaks JSON file or repository path",
                rules_desc: "Directory with custom JSON rule files",
                policy_desc: "Policy JSON file for gating",
                analyze_desc: "Enable LLM analysis (requires Ollama)",
                fix_desc: "Auto‑apply AI‑suggested fixes",
                review_desc: "Review each fix before applying",
                report_desc: "Generate PDF report",
                topology_desc: "Path to topology JSON file",
                compliance_desc: "Compliance framework (CIS/PCI‑DSS/ISO27001)",
                output_desc: "Output file for merged findings",
                wizard_desc: "Interactive first‑time setup wizard",
                llm_backend_desc: "LLM backend (ollama or litellm)",
                llm_model_desc: "LLM model name",
                rego_policy_desc: "OPA Rego policy file",
                update_rules_desc: "Download/update community rules"
            },
            ru: { critical: "КРИТИЧЕСКИЙ", high: "ВЫСОКИЙ", medium: "СРЕДНИЙ",
                low: "НИЗКИЙ", severity_breakdown: "Распределение",
                trend_over_time: "Тренд", attack_paths: "Пути атак",
                simulate_selected: "Симулировать",
                findings: "Находки", tool: "Инструмент", id_col: "ID",
                severity: "Серьёзность", target: "Цель", description: "Описание",
                close: "Закрыть", attack_simulation: "Симуляция атаки",
                search_placeholder: "Поиск находок...",
                simulating: "Симуляция...",
                no_ai: "Запустите с --analyze для ИИ‑анализа",
                generate_report: "Отчёт",
                clear_filters: "Сброс",
                ai_summary: "ИИ Сводка",
                report_loading: "Генерация отчёта...",
                report_success: "Отчёт загружен!",
                report_failed: "Ошибка генерации.",
                cli_ref_title: "Справка CLI",
                show_hide: "Показать",
                hide: "Скрыть",
                no_format_selected: "Формат не выбран — отчёт не создан.",
                trivy_desc: "JSON‑файл Trivy или имя образа",
                semgrep_desc: "JSON‑файл Semgrep или директория",
                poutine_desc: "JSON‑файл Poutine или путь к репо",
                zizmor_desc: "JSON‑файл Zizmor или путь к репо",
                gitleaks_desc: "JSON‑файл Gitleaks или путь к репо",
                rules_desc: "Директория с пользовательскими JSON‑правилами",
                policy_desc: "JSON‑файл политики для гейтирования",
                analyze_desc: "Включить ИИ‑анализ (требуется Ollama)",
                fix_desc: "Автоматически применить ИИ‑предложенные исправления",
                review_desc: "Просмотреть каждое исправление перед применением",
                report_desc: "Сгенерировать PDF‑отчёт",
                topology_desc: "Путь к JSON‑файлу топологии",
                compliance_desc: "Фреймворк комплаенса (CIS/PCI‑DSS/ISO27001)",
                output_desc: "Выходной файл для объединённых находок",
                wizard_desc: "Интерактивный мастер первой настройки",
                llm_backend_desc: "LLM‑бэкенд (ollama или litellm)",
                llm_model_desc: "Название модели LLM",
                rego_policy_desc: "Файл политики OPA Rego",
                update_rules_desc: "Загрузить/обновить правила сообщества"
            },
            zh: { critical: "严重", high: "高", medium: "中", low: "低",
                severity_breakdown: "严重性分布", trend_over_time: "趋势",
                attack_paths: "攻击路径", simulate_selected: "模拟选中",
                findings: "发现", tool: "工具", id_col: "编号",
                severity: "严重性", target: "目标", description: "描述",
                close: "关闭", attack_simulation: "攻击模拟",
                search_placeholder: "搜索发现...",
                simulating: "模拟中...",
                no_ai: "使用 --analyze 开启 AI 分析",
                generate_report: "报告",
                clear_filters: "清除",
                ai_summary: "AI摘要",
                report_loading: "正在生成报告...",
                report_success: "报告下载成功！",
                report_failed: "报告生成失败。",
                cli_ref_title: "CLI 快速参考",
                show_hide: "显示",
                hide: "隐藏",
                no_format_selected: "未选择格式 — 未生成报告。",
                trivy_desc: "Trivy JSON 文件或镜像名称",
                semgrep_desc: "Semgrep JSON 文件或目标目录",
                poutine_desc: "Poutine JSON 文件或仓库路径",
                zizmor_desc: "Zizmor JSON 文件或仓库路径",
                gitleaks_desc: "Gitleaks JSON 文件或仓库路径",
                rules_desc: "自定义 JSON 规则文件目录",
                policy_desc: "用于门控的 Policy JSON 文件",
                analyze_desc: "启用 LLM 分析 (需要 Ollama)",
                fix_desc: "自动应用 AI 建议的修复",
                review_desc: "在应用前检查每个修复",
                report_desc: "生成 PDF 报告",
                topology_desc: "拓扑 JSON 文件路径",
                compliance_desc: "合规框架 (CIS/PCI‑DSS/ISO27001)",
                output_desc: "合并发现的输出文件",
                wizard_desc: "交互式首次设置向导",
                llm_backend_desc: "LLM 后端 (ollama 或 litellm)",
                llm_model_desc: "LLM 模型名称",
                rego_policy_desc: "OPA Rego 策略文件",
                update_rules_desc: "下载/更新社区规则"
            }
        };
        let CL = localStorage.getItem('pipeline-lang') || 'en';
        function switchLanguage(l) {
            CL = l; localStorage.setItem('pipeline-lang', l);
            document.querySelectorAll('[data-i18n]').forEach(el => {
                const k = el.getAttribute('data-i18n');
                if (T[CL] && T[CL][k]) el.textContent = T[CL][k];
            });
            document.querySelectorAll('[data-i18n-placeholder]').forEach(el => {
                const k = el.getAttribute('data-i18n-placeholder');
                if (T[CL] && T[CL][k]) el.placeholder = T[CL][k];
            });
            document.getElementById('current-lang-label').textContent =
                l === 'en' ? 'EN' : l === 'ru' ? 'RU' : 'ZH';
            document.getElementById('langMenu').classList.remove('open');
            buildCLIRef();
            // Redraw charts with translated tooltips
            if (typeof lastCounts !== 'undefined') createSeverityChart(lastCounts);
            if (typeof lastScanData !== 'undefined') {
                createTrendChart(lastScanLabels, lastScanData);
            }
        }
        function toggleLangMenu() {
            const menu = document.getElementById('langMenu');
            menu.classList.toggle('open');
        }
        document.addEventListener('click', function(e) {
            const btn = document.getElementById('langDropdownBtn');
            const menu = document.getElementById('langMenu');
            if (!btn.contains(e.target) && !menu.contains(e.target)) {
                menu.classList.remove('open');
            }
        });

        // --- CLI Reference Cards (all flags) ---
        function buildCLIRef() {
            const flags = [
                {flag:'--trivy', desc:'trivy_desc', icon:'🐳'},
                {flag:'--semgrep', desc:'semgrep_desc', icon:'🔍'},
                {flag:'--poutine', desc:'poutine_desc', icon:'🦊'},
                {flag:'--zizmor', desc:'zizmor_desc', icon:'⚡'},
                {flag:'--gitleaks', desc:'gitleaks_desc', icon:'🔑'},
                {flag:'--rules', desc:'rules_desc', icon:'📁'},
                {flag:'--output', desc:'output_desc', icon:'💾'},
                {flag:'--policy', desc:'policy_desc', icon:'🛡️'},
                {flag:'--rego-policy', desc:'rego_policy_desc', icon:'📜'},
                {flag:'--analyze', desc:'analyze_desc', icon:'🧠'},
                {flag:'--llm-backend', desc:'llm_backend_desc', icon:'⚙️'},
                {flag:'--llm-model', desc:'llm_model_desc', icon:'🤖'},
                {flag:'--fix', desc:'fix_desc', icon:'🔧'},
                {flag:'--review', desc:'review_desc', icon:'👁️'},
                {flag:'--report', desc:'report_desc', icon:'📄'},
                {flag:'--topology', desc:'topology_desc', icon:'🗺️'},
                {flag:'--compliance', desc:'compliance_desc', icon:'✅'},
                {flag:'--wizard', desc:'wizard_desc', icon:'🧙'}
            ];
            const container = document.getElementById('cli-ref-cards');
            if (!container) return;
            container.innerHTML = '';
            flags.forEach(f => {
                const col = document.createElement('div');
                col.className = 'col-md-6 col-lg-4';
                const descText = (T[CL] && T[CL][f.desc]) ? T[CL][f.desc] : f.desc;
                col.innerHTML = (
                    '<div class="cli-flag-card">' +
                    '<div class="flag-icon">' + f.icon + '</div>' +
                    '<div>' +
                    '<code>' + f.flag + '</code>' +
                    '<div class="flag-desc">' + descText + '</div>' +
                    '</div></div>'
                );
                container.appendChild(col);
            });
        }

        // --- Toggle CLI ---
        function toggleCLI() {
            const body = document.getElementById('cli-ref-body');
            const toggle = document.getElementById('cli-toggle');
            const bsCollapse = bootstrap.Collapse.getInstance(body);
            if (bsCollapse) {
                bsCollapse.toggle();
            } else {
                new bootstrap.Collapse(body, { toggle: true });
            }
            body.addEventListener('shown.bs.collapse', () => {
                toggle.classList.add('expanded');
                toggle.querySelector('[data-i18n="show_hide"]').textContent =
                    T[CL]?.hide || 'Hide';
            });
            body.addEventListener('hidden.bs.collapse', () => {
                toggle.classList.remove('expanded');
                toggle.querySelector('[data-i18n="show_hide"]').textContent =
                    T[CL]?.show_hide || 'Show';
            });
        }

        // --- themes ---
        let severityChartInstance = null;
        let trendChartInstance = null;
        let lastCounts = null;
        let lastScanData = null;
        let lastScanLabels = null;

        function switchTheme(t) {
            document.documentElement.setAttribute('data-theme', t);
            localStorage.setItem('pipeline-theme', t);
            document.querySelectorAll('.theme-dot').forEach(d =>
                d.classList.remove('active'));
            const dot = document.querySelector(`.theme-dot[data-theme="${t}"]`);
            if (dot) dot.classList.add('active');
            initParticles();
            if (severityChartInstance) updateChartColors(severityChartInstance);
            if (trendChartInstance) updateChartColors(trendChartInstance);
        }

        function updateChartColors(chart) {
            const style = getComputedStyle(document.documentElement);
            const textColor = style.getPropertyValue('--text').trim();
            const textSecondary = style.getPropertyValue('--text-secondary').trim();
            const option = chart.getOption();
            if (option.graphic) {
                option.graphic[0].style.fill = textColor;
                option.graphic[1].style.fill = textSecondary;
            }
            if (option.legend) {
                option.legend.textStyle = { color: textSecondary };
            }
            if (option.xAxis) {
                option.xAxis.axisLabel = { color: textSecondary };
            }
            if (option.yAxis) {
                option.yAxis.axisLabel = { color: textSecondary };
            }
            chart.setOption(option);
        }

        // --- particles (more visible) ---
        function initParticles() {
            const c = document.getElementById('particles-canvas');
            const ctx = c.getContext('2d');
            c.width = window.innerWidth; c.height = window.innerHeight;
            const col = getComputedStyle(document.documentElement)
                .getPropertyValue('--particle-color').trim();
            const particles = Array.from({length: 120}, () => ({
                x: Math.random() * c.width, y: Math.random() * c.height,
                r: Math.random() * 3 + 0.5,
                dx: (Math.random() - 0.5) * 0.5, dy: (Math.random() - 0.5) * 0.5,
                alpha: Math.random(), alphaDir: 0.015
            }));
            function anim() {
                if (document.documentElement.getAttribute('data-theme') !==
                    (localStorage.getItem('pipeline-theme') || 'cyber')) return;
                ctx.clearRect(0, 0, c.width, c.height);
                particles.forEach(p => {
                    p.x += p.dx; p.y += p.dy;
                    if (p.x < 0 || p.x > c.width) p.dx *= -1;
                    if (p.y < 0 || p.y > c.height) p.dy *= -1;
                    p.alpha += p.alphaDir;
                    if (p.alpha <= 0.3 || p.alpha >= 1) p.alphaDir *= -1;
                    ctx.beginPath();
                    ctx.arc(p.x, p.y, p.r, 0, Math.PI * 2);
                    ctx.fillStyle = col.replace(/0\.\d+/, (p.alpha * 0.25).toFixed(2));
                    ctx.fill();
                });
                for (let i = 0; i < particles.length; i++) {
                    for (let j = i + 1; j < particles.length; j++) {
                        const d = Math.hypot(particles[i].x - particles[j].x,
                                             particles[i].y - particles[j].y);
                        if (d < 140) {
                            ctx.beginPath();
                            ctx.moveTo(particles[i].x, particles[i].y);
                            ctx.lineTo(particles[j].x, particles[j].y);
                            ctx.strokeStyle = col.replace(/0\.\d+/, '0.06');
                            ctx.stroke();
                        }
                    }
                }
                requestAnimationFrame(anim);
            }
            anim();
        }

        // --- clock ---
        function updateClock() {
            const now = new Date();
            const options = { weekday: 'short', month: 'short', day: 'numeric',
                              hour: 'numeric', minute: 'numeric', hour12: true };
            document.getElementById('clock-pill').innerHTML =
                '🕐 ' + now.toLocaleDateString('en-US', options).replace(',', ' ·');
        }
        setInterval(updateClock, 1000); updateClock();

        // --- animated counter ---
        function animateCounter(el, target) {
            const dur = 900, start = performance.now();
            function tick(now) {
                const p = Math.min((now - start) / dur, 1);
                const v = 1 - Math.pow(1 - p, 3);
                el.textContent = Math.round(v * target);
                if (p < 1) requestAnimationFrame(tick);
            }
            requestAnimationFrame(tick);
        }

        // --- typewriter ---
        function typeWriter(el, text, speed = 25) {
            el.textContent = ''; el.classList.add('typewriter');
            let i = 0;
            function type() {
                if (i < text.length) {
                    el.textContent += text.charAt(i); i++;
                    setTimeout(type, speed);
                } else el.classList.remove('typewriter');
            }
            type();
        }

        // --- toast ---
        function showToast(message, type = 'info') {
            const container = document.getElementById('toast-container');
            const toastEl = document.createElement('div');
            toastEl.className = `toast align-items-center text-bg-${type} border-0`;
            toastEl.setAttribute('role', 'alert');
            toastEl.innerHTML = `
                <div class="d-flex">
                    <div class="toast-body">${message}</div>
                    <button type="button" class="btn-close btn-close-white me-2 m-auto"
                            data-bs-dismiss="toast"></button>
                </div>`;
            container.appendChild(toastEl);
            const toast = new bootstrap.Toast(toastEl, { delay: 3000 });
            toast.show();
            toastEl.addEventListener('hidden.bs.toast', () => toastEl.remove());
        }

        // --- Report dropdown (no modal, no freeze) ---
        function toggleReportMenu() {
            const menu = document.getElementById('reportMenu');
            menu.classList.toggle('open');
        }
        document.addEventListener('click', function(e) {
            const btn = document.getElementById('report-btn');
            const menu = document.getElementById('reportMenu');
            if (!btn.contains(e.target) && !menu.contains(e.target)) {
                menu.classList.remove('open');
            }
        });

        function downloadReport(fmt) {
            document.getElementById('reportMenu').classList.remove('open');
            const btn = document.getElementById('report-btn');
            const origHTML = btn.innerHTML;
            btn.disabled = true;
            btn.innerHTML = '<span class="spinner-border spinner-border-sm"></span> ' +
                (T[CL]?.report_loading || 'Generating...');
            fetch('/api/report?format=' + fmt, { headers: getHeaders() })
                .then(resp => {
                    if (!resp.ok) throw new Error('Failed');
                    return resp.blob();
                })
                .then(blob => {
                    const url = URL.createObjectURL(blob);
                    const a = document.createElement('a');
                    a.href = url;
                    let ext = 'pdf';
                    if (fmt === 'json') ext = 'json';
                    else if (fmt === 'html') ext = 'html';
                    a.download = 'pipeline_sentinel_report.' + ext;
                    document.body.appendChild(a);
                    a.click();
                    a.remove();
                    URL.revokeObjectURL(url);
                    showToast(T[CL]?.report_success || 'Report downloaded', 'success');
                })
                .catch(() => {
                    showToast(T[CL]?.report_failed || 'Report failed', 'danger');
                })
                .finally(() => {
                    btn.disabled = false;
                    btn.innerHTML = origHTML;
                });
        }

        // --- main app ---
        const AK = "{{ api_key }}";
        function getHeaders() {
            if (AK && AK !== 'disabled') return {'X-API-Key': AK};
            return {};
        }
        let allFindings = [], selectedFindings = new Set();
        let currentSeverityFilter = null;

        function truncate(t, m) {
            if (!t) return t;
            return t.length > m ? t.substring(0, m) + '...' : t;
        }
        function severityColor(s) {
            switch(s.toUpperCase()) {
                case 'CRITICAL': return 'danger';
                case 'HIGH': return 'warning text-dark';
                case 'MEDIUM': return 'info text-dark';
                case 'LOW': return 'primary';
                default: return 'secondary';
            }
        }

        function renderTable(data) {
            const tb = document.getElementById('tableBody');
            tb.innerHTML = '';
            if (data.length === 0) {
                tb.innerHTML = (
                    '<tr><td colspan="6" class="text-center text-muted">' +
                    'No findings match your filters.</td></tr>'
                );
                return;
            }
            data.forEach(f => {
                const row = document.createElement('tr');
                row.setAttribute('data-finding-id', f.id);
                row.innerHTML = (
                    '<td><input type="checkbox" class="finding-checkbox" data-id="'
                    + f.id + '" ' + (selectedFindings.has(f.id) ? 'checked' : '')
                    + '></td><td>' + f.tool + '</td><td><code style="color:var(--accent)">'
                    + f.id + '</code></td><td><span class="badge bg-'
                    + severityColor(f.severity) + '">' + f.severity
                    + '</span></td><td>' + f.target + '</td><td>'
                    + truncate(f.description, 80) + '</td>'
                );
                const detailRow = document.createElement('tr');
                detailRow.className = 'finding-detail-row';
                detailRow.style.display = 'none';
                let detailHtml = '<div class="finding-detail">' +
                    '<strong>ID:</strong> ' + f.id + '<br>' +
                    '<strong>Severity:</strong> ' + f.severity + '<br>' +
                    '<strong>Tool:</strong> ' + f.tool + '<br>' +
                    '<strong>Target:</strong> ' + f.target + '<br>' +
                    '<strong>Description:</strong> ' + (f.description || 'N/A') + '<br>';
                if (f.line) detailHtml += '<strong>Line:</strong> ' + f.line + '<br>';
                detailHtml += '<hr><small class="text-muted">' +
                    '💡 Run <code>--analyze</code> to get AI‑powered attack paths and remediation advice.</small>';
                detailHtml += '</div>';
                detailRow.innerHTML = '<td colspan="6">' + detailHtml + '</td>';
                row.addEventListener('click', function(e) {
                    if (e.target.tagName === 'INPUT') return;
                    if (detailRow.style.display === 'none') {
                        detailRow.style.display = '';
                        row.classList.add('expanded');
                    } else {
                        detailRow.style.display = 'none';
                        row.classList.remove('expanded');
                    }
                });
                tb.appendChild(row);
                tb.appendChild(detailRow);
            });
            document.querySelectorAll('.finding-checkbox').forEach(cb => {
                cb.addEventListener('change', function() {
                    const fid = this.dataset.id;
                    if (this.checked) selectedFindings.add(fid);
                    else selectedFindings.delete(fid);
                    document.getElementById('simulate-selected-btn').disabled =
                        selectedFindings.size === 0;
                });
            });
        }

        function applyFilters() {
            const s = document.getElementById('searchInput').value.toLowerCase();
            let filtered = allFindings;
            if (currentSeverityFilter) {
                filtered = filtered.filter(f =>
                    f.severity.toUpperCase() === currentSeverityFilter);
            }
            if (s) {
                filtered = filtered.filter(f =>
                    String(f.id).toLowerCase().includes(s) ||
                    (f.description && f.description.toLowerCase().includes(s))
                );
            }
            renderTable(filtered);
        }

        function filterBySeverity(sev) {
            if (currentSeverityFilter === sev) {
                currentSeverityFilter = null;
            } else {
                currentSeverityFilter = sev;
            }
            document.querySelectorAll('#stats-row .card').forEach(c => c.style.border = '');
            if (currentSeverityFilter) {
                const activeCard = document.querySelector(
                    `#stats-row .card:has(.stat-pill.${sev.toLowerCase()})`
                );
                if (activeCard) activeCard.style.border = '2px solid var(--accent)';
            }
            applyFilters();
            document.getElementById('findings-section').scrollIntoView({ behavior: 'smooth' });
        }

        document.getElementById('clear-filters-btn').addEventListener('click', () => {
            currentSeverityFilter = null;
            document.getElementById('searchInput').value = '';
            document.querySelectorAll('#stats-row .card').forEach(c => c.style.border = '');
            applyFilters();
        });

        // --- expandable search ---
        const searchToggle = document.getElementById('search-toggle-btn');
        const searchInputRow = document.getElementById('search-input-row');
        const searchInput = document.getElementById('searchInput');
        searchToggle.addEventListener('click', () => {
            if (searchInputRow.classList.contains('expanded')) {
                searchInputRow.classList.remove('expanded');
                searchInput.value = '';
                applyFilters();
            } else {
                searchInputRow.classList.add('expanded');
                searchInput.focus();
            }
        });
        searchInput.addEventListener('blur', () => {
            if (!searchInput.value) {
                searchInputRow.classList.remove('expanded');
            }
        });

        // --- ECharts Severity Breakdown (enhanced) ---
        function createSeverityChart(counts) {
            lastCounts = counts; // store for language/theme updates
            const dom = document.getElementById('severityChart');
            if (severityChartInstance) severityChartInstance.dispose();
            severityChartInstance = echarts.init(dom);
            const style = getComputedStyle(document.documentElement);
            const textColor = style.getPropertyValue('--text').trim();
            const textSecondary = style.getPropertyValue('--text-secondary').trim();
            const total = counts.CRITICAL + counts.HIGH + counts.MEDIUM + counts.LOW;
            // Translate tooltip names
            const tNames = [
                T[CL]?.critical || 'CRITICAL',
                T[CL]?.high || 'HIGH',
                T[CL]?.medium || 'MEDIUM',
                T[CL]?.low || 'LOW'
            ];
            const option = {
                tooltip: {
                    trigger: 'item',
                    formatter: function(params) {
                        return params.name + ': ' + params.value;
                    }
                },
                series: [{
                    type: 'pie',
                    radius: ['45%', '75%'],
                    avoidLabelOverlap: false,
                    itemStyle: {
                        borderRadius: 10,
                        borderColor: 'rgba(0,0,0,0.3)',
                        borderWidth: 2,
                        shadowBlur: 20,
                        shadowColor: 'rgba(0,0,0,0.4)'
                    },
                    label: { show: false },
                    emphasis: {
                        scaleSize: 15,
                        label: { show: true, fontSize: 18, fontWeight: 'bold',
                                 color: textColor }
                    },
                    data: [
                        { value: counts.CRITICAL, name: tNames[0],
                          itemStyle: { color: '#FF4D6D' } },
                        { value: counts.HIGH, name: tNames[1],
                          itemStyle: { color: '#FFB100' } },
                        { value: counts.MEDIUM, name: tNames[2],
                          itemStyle: { color: '#00B4D8' } },
                        { value: counts.LOW, name: tNames[3],
                          itemStyle: { color: '#06D6A0' } }
                    ]
                }],
                graphic: [
                    {
                        type: 'text',
                        left: 'center',
                        top: '44%',
                        style: {
                            text: total.toString(),
                            textAlign: 'center',
                            fill: textColor,
                            fontSize: 32,
                            fontWeight: 'bold',
                            textShadowBlur: 10,
                            textShadowColor: 'rgba(0,0,0,0.5)'
                        }
                    },
                    {
                        type: 'text',
                        left: 'center',
                        top: '52%',
                        style: {
                            text: 'TOTAL',
                            textAlign: 'center',
                            fill: textSecondary,
                            fontSize: 14,
                            fontWeight: 'normal'
                        }
                    }
                ]
            };
            severityChartInstance.setOption(option);
        }

        // --- ECharts Trend Over Time (enhanced) ---
        function createTrendChart(labels, scans) {
            lastScanLabels = labels;
            lastScanData = scans;
            const dom = document.getElementById('trendChart');
            if (trendChartInstance) trendChartInstance.dispose();
            trendChartInstance = echarts.init(dom);
            const style = getComputedStyle(document.documentElement);
            const textSecondary = style.getPropertyValue('--text-secondary').trim();
            const glassBorder = style.getPropertyValue('--glass-border').trim();
            const option = {
                tooltip: { trigger: 'axis' },
                legend: {
                    data: ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'],
                    textStyle: { color: textSecondary }
                },
                grid: { left: '3%', right: '4%', bottom: '3%', containLabel: true },
                xAxis: {
                    type: 'category',
                    data: labels,
                    axisLabel: { color: textSecondary },
                    axisLine: { lineStyle: { color: glassBorder } }
                },
                yAxis: {
                    type: 'value',
                    axisLabel: { color: textSecondary },
                    splitLine: { lineStyle: { color: 'rgba(255,255,255,0.04)' } }
                },
                series: [
                    {
                        name: 'CRITICAL',
                        type: 'line',
                        data: scans.map(s => s.critical),
                        smooth: true,
                        symbol: 'circle',
                        symbolSize: 8,
                        lineStyle: { width: 2, shadowBlur: 10,
                                     shadowColor: 'rgba(255,77,109,0.5)' },
                        areaStyle: { color: new echarts.graphic.LinearGradient(0,0,0,1,[
                            {offset:0, color:'rgba(255,77,109,0.4)'},
                            {offset:1, color:'rgba(255,77,109,0.02)'}
                        ])},
                        itemStyle: { color: '#FF4D6D' }
                    },
                    {
                        name: 'HIGH',
                        type: 'line',
                        data: scans.map(s => s.high),
                        smooth: true,
                        symbol: 'circle',
                        symbolSize: 8,
                        lineStyle: { width: 2, shadowBlur: 10,
                                     shadowColor: 'rgba(255,177,0,0.5)' },
                        areaStyle: { color: new echarts.graphic.LinearGradient(0,0,0,1,[
                            {offset:0, color:'rgba(255,177,0,0.3)'},
                            {offset:1, color:'rgba(255,177,0,0.02)'}
                        ])},
                        itemStyle: { color: '#FFB100' }
                    },
                    {
                        name: 'MEDIUM',
                        type: 'line',
                        data: scans.map(s => s.medium),
                        smooth: true,
                        symbol: 'circle',
                        symbolSize: 8,
                        lineStyle: { width: 2, shadowBlur: 10,
                                     shadowColor: 'rgba(0,180,216,0.5)' },
                        areaStyle: { color: new echarts.graphic.LinearGradient(0,0,0,1,[
                            {offset:0, color:'rgba(0,180,216,0.3)'},
                            {offset:1, color:'rgba(0,180,216,0.02)'}
                        ])},
                        itemStyle: { color: '#00B4D8' }
                    },
                    {
                        name: 'LOW',
                        type: 'line',
                        data: scans.map(s => s.low),
                        smooth: true,
                        symbol: 'circle',
                        symbolSize: 8,
                        lineStyle: { width: 2, shadowBlur: 10,
                                     shadowColor: 'rgba(6,214,160,0.5)' },
                        areaStyle: { color: new echarts.graphic.LinearGradient(0,0,0,1,[
                            {offset:0, color:'rgba(6,214,160,0.3)'},
                            {offset:1, color:'rgba(6,214,160,0.02)'}
                        ])},
                        itemStyle: { color: '#06D6A0' }
                    }
                ]
            };
            trendChartInstance.setOption(option);
        }

        function updateStats(findings) {
            const counts = {CRITICAL:0, HIGH:0, MEDIUM:0, LOW:0};
            findings.forEach(f => {
                const s = f.severity.toUpperCase();
                counts[s] = (counts[s] || 0) + 1;
            });
            ['critical','high','medium','low'].forEach(k => {
                const el = document.getElementById('stat-' + k);
                const val = counts[k.toUpperCase()];
                el.setAttribute('data-target', val);
                animateCounter(el, val);
            });
            createSeverityChart(counts);
        }

        // --- D3 Attack Graph (fixed node drift) ---
        let attackSim = null; // store simulation instance to avoid re-init issues
        function drawAttackGraph(data) {
            const co = document.getElementById('attack-graph');
            co.innerHTML = '';
            const W = co.clientWidth, H = co.clientHeight;
            const svg = d3.select('#attack-graph').append('svg')
                .attr('width', W).attr('height', H);
            const simulation = d3.forceSimulation(data.nodes)
                .force('link', d3.forceLink(data.links).id(d => d.id).distance(100))
                .force('charge', d3.forceManyBody().strength(-300))
                .force('center', d3.forceCenter(W / 2, H / 2))
                .force('collision', d3.forceCollide().radius(12))
                .force('x', d3.forceX(W / 2).strength(0.05))
                .force('y', d3.forceY(H / 2).strength(0.05));
            attackSim = simulation;

            const link = svg.append('g').selectAll('line')
                .data(data.links).enter().append('line')
                .attr('stroke', '#94A3B8').attr('stroke-opacity', 0.5)
                .attr('stroke-width', 1.5);
            const node = svg.append('g').selectAll('circle')
                .data(data.nodes).enter().append('circle')
                .attr('r', 10)
                .attr('fill', d => ({
                    CRITICAL: '#FF4D6D', HIGH: '#FFB100',
                    MEDIUM: '#00B4D8', LOW: '#06D6A0'
                }[d.severity] || '#6c757d'))
                .style('cursor', 'pointer')
                .style('filter', 'drop-shadow(0 0 6px currentColor)')
                .on('click', (e, d) => {
                    const dt = document.getElementById('attack-detail');
                    dt.innerHTML = (
                        '<strong>' + d.id + '</strong><br>Severity: ' +
                        d.severity + '<br>' + d.title + '<br>' +
                        '<button class="btn-accent mt-2" ' +
                        'onclick="simulateAttack([\'' + d.id + '\'])">' +
                        'Simulate this attack</button>'
                    );
                    dt.style.display = 'block';
                })
                .call(d3.drag()
                    .on('start', (event, d) => {
                        if (!event.active) simulation.alphaTarget(0.3).restart();
                        d.fx = d.x; d.fy = d.y;
                    })
                    .on('drag', (event, d) => {
                        d.fx = event.x; d.fy = event.y;
                    })
                    .on('end', (event, d) => {
                        if (!event.active) simulation.alphaTarget(0);
                        d.fx = null; d.fy = null;
                    }));
            const label = svg.append('g').selectAll('text')
                .data(data.nodes).enter().append('text')
                .text(d => d.id)
                .attr('font-size', '9px').attr('dx', 13).attr('dy', 4)
                .attr('fill', 'var(--text-secondary)')
                .style('font-family', 'var(--mono-font)');
            simulation.on('tick', () => {
                link.attr('x1', d => d.source.x).attr('y1', d => d.source.y)
                    .attr('x2', d => d.target.x).attr('y2', d => d.target.y);
                node.attr('cx', d => d.x).attr('cy', d => d.y);
                label.attr('x', d => d.x).attr('y', d => d.y);
            });
            window.addEventListener('resize', () => {
                simulation.force('center', d3.forceCenter(co.clientWidth/2,
                                                           co.clientHeight/2));
                simulation.alpha(0.3).restart();
            });
        }

        // --- Simulation overlay (custom, no Bootstrap modal) ---
        function openSimPanel() {
            document.getElementById('simOverlay').classList.add('open');
            const content = document.getElementById('sim-panel-content');
            content.innerHTML = (
                '<div class="text-center">' +
                '<div class="spinner-border" style="color:var(--accent)"></div>' +
                '<p class="mt-2">' + (T[CL]?.simulating || 'Simulating...') +
                '</p></div>'
            );
        }
        function closeSimPanel() {
            document.getElementById('simOverlay').classList.remove('open');
        }
        // Close on overlay click (outside panel)
        document.getElementById('simOverlay').addEventListener('click', function(e) {
            if (e.target === this) closeSimPanel();
        });

        // --- fetch wrappers ---
        fetch('/api/findings', { headers: getHeaders() })
        .then(r => r.json()).then(data => {
            allFindings = data.items;
            renderTable(allFindings);
            updateStats(allFindings);
            document.getElementById('searchInput')
                .addEventListener('input', applyFilters);
            document.getElementById('select-all')
                .addEventListener('change', function() {
                    document.querySelectorAll('.finding-checkbox').forEach(cb => {
                        cb.checked = this.checked;
                        if (this.checked) selectedFindings.add(cb.dataset.id);
                        else selectedFindings.delete(cb.dataset.id);
                    });
                    document.getElementById('simulate-selected-btn').disabled =
                        selectedFindings.size === 0;
                });
            document.getElementById('simulate-selected-btn')
                .addEventListener('click', () => {
                    const ids = Array.from(selectedFindings);
                    if (ids.length === 0) return;
                    simulateAttack(ids);
                });
        });

        fetch('/api/history', { headers: getHeaders() })
        .then(r => r.json()).then(sc => {
            if (!sc.length) return;
            const labels = sc.map(s => s.timestamp.substring(0, 10));
            createTrendChart(labels, sc);
        });

        fetch('/api/summary', { headers: getHeaders() })
        .then(r => r.json()).then(d => {
            if (d.executive_summary) {
                const el = document.getElementById('exec-summary');
                typeWriter(el, d.executive_summary, 25);
                document.getElementById('ai-status').innerHTML =
                    '🤖 AI Analysis Active';
                if (d.risk_score) {
                    const pct = d.risk_score;
                    const badgeClass = pct > 70 ? 'danger' :
                        pct > 40 ? 'warning text-dark' : 'success';
                    document.getElementById('risk-score').innerHTML =
                        `<span class="badge bg-${badgeClass} fs-6">
                            Risk Score: ${pct}/100</span>`;
                }
            } else {
                document.getElementById('ai-status').innerHTML =
                    '🤖 <span data-i18n="no_ai">Run with --analyze</span>';
            }
        });

        fetch('/api/attack-paths', { headers: getHeaders() })
        .then(r => r.json()).then(d => {
            if (d.error) {
                document.getElementById('attack-error').style.display = 'block';
                document.getElementById('attack-error').textContent = d.error;
                return;
            }
            if (!d.nodes || !d.nodes.length) return;
            drawAttackGraph(d);
        });

        async function simulateAttack(fids) {
            openSimPanel();
            const content = document.getElementById('sim-panel-content');
            try {
                const r = await fetch('/api/simulate', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json',
                               ...getHeaders() },
                    body: JSON.stringify({ finding_ids: fids })
                });
                const d = await r.json();
                const ps = 'color:var(--text);max-height:300px;overflow-y:auto;';
                const so = d.sandbox_output
                    ? '<p><strong>Sandbox Output:</strong><br><pre>'
                      + escapeHtml(d.sandbox_output) + '</pre></p>'
                    : '';
                content.innerHTML = (
                    '<h6 style="color:var(--accent)">Simulation Results</h6>' +
                    '<pre class="bg-dark p-3 rounded" style="' + ps + '">' +
                    escapeHtml(d.script) + '</pre>' +
                    '<p class="mt-2"><strong>Description:</strong> ' +
                    escapeHtml(d.description) + '</p>' + so);
            } catch (err) {
                content.innerHTML = '<div class="alert alert-danger">Simulation failed: '
                    + err.message + '</div>';
            }
        }

        function escapeHtml(text) {
            return text.replace(/&/g, '&amp;').replace(/</g, '&lt;')
                       .replace(/>/g, '&gt;').replace(/"/g, '&quot;');
        }

        // keyboard shortcuts
        document.addEventListener('keydown', function(e) {
            if (e.key === '/' &&
                document.activeElement !== document.getElementById('searchInput')) {
                e.preventDefault();
                if (!searchInputRow.classList.contains('expanded')) {
                    searchInputRow.classList.add('expanded');
                }
                document.getElementById('searchInput').focus();
            }
            if (e.key === 'Escape') {
                document.getElementById('searchInput').value = '';
                document.getElementById('searchInput').blur();
                searchInputRow.classList.remove('expanded');
                currentSeverityFilter = null;
                document.querySelectorAll('#stats-row .card').forEach(c => c.style.border = '');
                applyFilters();
            }
        });

        // --- init ---
        (function() {
            const savedTheme = localStorage.getItem('pipeline-theme') || 'cyber';
            switchTheme(savedTheme);
            document.getElementById('current-lang-label').textContent =
                CL === 'en' ? 'EN' : CL === 'ru' ? 'RU' : 'ZH';
            switchLanguage(CL);
            buildCLIRef();
            initParticles();
            window.addEventListener('resize', () => {
                initParticles();
                if (severityChartInstance) severityChartInstance.resize();
                if (trendChartInstance) trendChartInstance.resize();
            });
        })();
    </script>
</body>
</html>
"""

def load_findings():
    if not os.path.exists(FINDINGS_FILE):
        return []
    with open(FINDINGS_FILE) as f:
        return json.load(f)

@dashboard_bp.route('/')
def index():
    findings = load_findings()
    return render_template_string(
        DASHBOARD_HTML, findings=findings,
        api_key=os.environ.get("PIPELINE_API_KEY", "disabled"))

@dashboard_bp.route('/api/findings')
@login_required
def api_findings():
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 50, type=int)
    return jsonify(get_findings_paginated(page, per_page))

@dashboard_bp.route('/api/history')
@login_required
def api_history():
    return jsonify(get_all_scans())

@dashboard_bp.route('/api/rag')
@login_required
def api_rag():
    q = request.args.get('q', '')
    if not q:
        return jsonify([])
    return jsonify(rag_search(q))

@dashboard_bp.route('/api/simulate', methods=['POST'])
@login_required
def api_simulate():
    data = request.get_json(force=True)
    finding_ids = data.get('finding_ids', [])
    if not finding_ids:
        return jsonify({"error": "No finding IDs"}), 400
    findings = load_findings()
    selected = [f for f in findings if f.get('id') in finding_ids]
    if not selected:
        return jsonify({"error": "Not found"}), 404
    from devsecops_radar.core.attack_simulation import run_sandboxed_poc, simulate_attack
    sp = []
    descs = []
    for f in selected:
        spath = simulate_attack(f)
        with open(spath) as sf:
            sp.append(sf.read())
        descs.append(f"{f.get('id')}: {f.get('title')}")
    fs = "\n".join(sp)
    desc = " → ".join(descs)
    so = None
    try:
        so = run_sandboxed_poc(spath) if spath else None
    except Exception:
        pass
    return jsonify({"script": fs, "description": desc, "sandbox_output": so})

@dashboard_bp.route('/api/report')
@login_required
def api_report():
    fmt = request.args.get('format', 'pdf')
    findings = load_findings()
    ai_summary = {}
    summary_file = os.environ.get('AI_SUMMARY_FILE', 'findings_ai_summary.json')
    if os.path.exists(summary_file):
        with open(summary_file) as f:
            ai_summary = json.load(f)
    if fmt == 'json':
        import io
        data = json.dumps({"findings": findings, "ai_summary": ai_summary}, indent=2)
        return send_file(io.BytesIO(data.encode()), mimetype='application/json',
                         as_attachment=True, download_name='report.json')
    if fmt == 'html':
        html = '<html><head><title>Pipeline Sentinel Report</title></head><body>'
        html += '<h1>Pipeline Sentinel Security Report</h1>'
        if ai_summary.get("executive_summary"):
            html += '<h2>Executive Summary</h2><p>' + ai_summary["executive_summary"] + '</p>'
        html += ('<h2>Findings</h2><table border="1"><tr>'
                 '<th>Tool</th><th>ID</th><th>Severity</th>'
                 '<th>Target</th><th>Title</th></tr>')
        for f in findings:
            html += (f'<tr><td>{f["tool"]}</td><td>{f["id"]}</td>'
                     f'<td>{f["severity"]}</td><td>{f["target"]}</td>'
                     f'<td>{f["title"]}</td></tr>')
        html += '</table></body></html>'
        import io
        return send_file(io.BytesIO(html.encode()), mimetype='text/html',
                         as_attachment=True, download_name='report.html')
    report_path = os.path.join(os.getcwd(), 'report.pdf')
    generate_pdf_report(findings, ai_summary, report_path)
    return send_file(report_path, as_attachment=True,
                     download_name='pipeline_sentinel_report.pdf')
