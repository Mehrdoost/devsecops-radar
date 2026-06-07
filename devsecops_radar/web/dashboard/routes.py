import json
import os

from flask import Blueprint, jsonify, render_template_string, request, send_file

from devsecops_radar.core.auth import require_api_key
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
    <link rel="stylesheet" href="{{ url_for('static', filename='css/bootstrap.min.css') }}">
    <style>
        :root, [data-theme="cyber"] {
            --bg-primary: #0A0E17;
            --bg-secondary: #121C2E;
            --bg-tertiary: #1A2740;
            --accent: #00E5FF;
            --accent-glow: rgba(0,229,255,0.25);
            --accent-2: #7C3AED;
            --text: #E2E8F0;
            --text-secondary: #A0AEC0;
            --danger: #FF4D6D;
            --warning: #FFB100;
            --info: #00B4D8;
            --success: #06D6A0;
            --glass: rgba(18,28,46,0.65);
            --glass-border: rgba(255,255,255,0.08);
            --card-shadow: 0 8px 32px rgba(0,0,0,0.4);
            --particle-color: rgba(0,229,255,0.15);
            --table-row-bg: #1A2740;
            --table-text: var(--text);
            --table-hover-bg: rgba(0,229,255,0.1);
            --table-border: rgba(255,255,255,0.06);
            --muted-color: var(--text-secondary);
        }
        [data-theme="midnight"] {
            --bg-primary: #0B0E14;
            --bg-secondary: #161B24;
            --bg-tertiary: #1E2532;
            --accent: #6366F1;
            --accent-glow: rgba(99,102,241,0.25);
            --accent-2: #8B5CF6;
            --text: #F8FAFC;
            --text-secondary: #CBD5E1;
            --danger: #EF4444;
            --warning: #F59E0B;
            --info: #3B82F6;
            --success: #10B981;
            --glass: rgba(22,27,36,0.7);
            --glass-border: rgba(255,255,255,0.05);
            --card-shadow: 0 8px 32px rgba(0,0,0,0.5);
            --particle-color: rgba(99,102,241,0.12);
            --table-row-bg: #1E2532;
            --table-text: var(--text);
            --table-hover-bg: rgba(99,102,241,0.12);
            --table-border: rgba(255,255,255,0.05);
            --muted-color: var(--text-secondary);
        }
        [data-theme="arctic"] {
            --bg-primary: #F8FAFC;
            --bg-secondary: #FFFFFF;
            --bg-tertiary: #E2E8F0;
            --accent: #0284C7;
            --accent-glow: rgba(2,132,199,0.2);
            --accent-2: #0EA5E9;
            --text: #0F172A;
            --text-secondary: #334155;
            --danger: #DC2626;
            --warning: #D97706;
            --info: #0284C7;
            --success: #059669;
            --glass: rgba(255,255,255,0.9);
            --glass-border: rgba(0,0,0,0.12);
            --card-shadow: 0 8px 30px rgba(0,0,0,0.08);
            --particle-color: rgba(2,132,199,0.15);
            --table-row-bg: #FFFFFF;
            --table-text: #0F172A;
            --table-hover-bg: rgba(2,132,199,0.08);
            --table-border: rgba(0,0,0,0.12);
            --muted-color: #475569;
        }
        [data-theme="forest"] {
            --bg-primary: #0F1A14;
            --bg-secondary: #162819;
            --bg-tertiary: #1C3423;
            --accent: #34D399;
            --accent-glow: rgba(52,211,153,0.25);
            --accent-2: #6EE7B7;
            --text: #ECFDF5;
            --text-secondary: #C1E7D4;
            --danger: #F87171;
            --warning: #FBBF24;
            --info: #60A5FA;
            --success: #34D399;
            --glass: rgba(22,40,25,0.75);
            --glass-border: rgba(255,255,255,0.06);
            --card-shadow: 0 8px 32px rgba(0,0,0,0.4);
            --particle-color: rgba(52,211,153,0.12);
            --table-row-bg: #1C3423;
            --table-text: var(--text);
            --table-hover-bg: rgba(52,211,153,0.1);
            --table-border: rgba(255,255,255,0.06);
            --muted-color: var(--text-secondary);
        }
        [data-theme="dark"] {
            --bg-primary: #09090B;
            --bg-secondary: #18181B;
            --bg-tertiary: #27272A;
            --accent: #3B82F6;
            --accent-glow: rgba(59,130,246,0.3);
            --accent-2: #60A5FA;
            --text: #FAFAFA;
            --text-secondary: #D4D4D8;
            --danger: #EF4444;
            --warning: #F59E0B;
            --info: #3B82F6;
            --success: #10B981;
            --glass: rgba(24,24,27,0.75);
            --glass-border: rgba(255,255,255,0.08);
            --card-shadow: 0 8px 32px rgba(0,0,0,0.6);
            --particle-color: rgba(59,130,246,0.15);
            --table-row-bg: #27272A;
            --table-text: var(--text);
            --table-hover-bg: rgba(59,130,246,0.15);
            --table-border: rgba(255,255,255,0.08);
            --muted-color: var(--text-secondary);
        }
        ::-webkit-scrollbar { width: 8px; height: 8px; }
        ::-webkit-scrollbar-track { background: var(--bg-primary); }
        ::-webkit-scrollbar-thumb { background: var(--accent); border-radius: 10px; }
        ::-webkit-scrollbar-thumb:hover { background: var(--accent-2); }
        body {
            background: var(--bg-primary); color: var(--text);
            font-family: 'Inter', system-ui, -apple-system, sans-serif;
            margin: 0; padding: 0; overflow-x: hidden;
            font-size: 15px; line-height: 1.6;
            transition: background 0.5s ease, color 0.5s ease;
        }
        .text-muted { color: var(--muted-color) !important; }
        .bg-pattern {
            position: fixed; top: 0; left: 0; width: 100vw; height: 100vh; z-index: -2;
            background-image: radial-gradient(var(--glass-border) 1px, transparent 1px);
            background-size: 40px 40px; opacity: 0.3; pointer-events: none;
        }
        .bg-orbs {
            position: fixed; top: 0; left: 0; width: 100vw; height: 100vh;
            z-index: -1; overflow: hidden; pointer-events: none;
        }
        .orb {
            position: absolute; border-radius: 50%; filter: blur(120px);
            opacity: 0.4; animation: floatOrb 20s ease-in-out infinite alternate;
        }
        .orb-1 { top: -10%; left: -10%; width: 50vw; height: 50vw; background: var(--accent-glow); }
        .orb-2 {
            bottom: -10%; right: -10%; width: 40vw; height: 40vw;
            background: var(--accent-glow); animation-delay: -10s; animation-duration: 25s;
        }
        @keyframes floatOrb {
            0% { transform: translate(0, 0) scale(1); }
            100% { transform: translate(15%, 15%) scale(1.3); }
        }
        #particles-canvas {
            position: fixed; top: 0; left: 0; width: 100%;
            height: 100%; z-index: 0; pointer-events: none;
        }
        .content-layer { position: relative; z-index: 1; }
        .navbar { background: transparent !important; padding-top: 1.5rem; padding-bottom: 1.5rem; }
        .navbar-brand {
            font-weight: 800; letter-spacing: -1px; color: var(--text) !important;
            font-size: 1.8rem; text-shadow: 0 0 20px var(--accent-glow);
        }
        .navbar-brand span { color: var(--accent); }
        .top-controls {
            display: flex; align-items: center; background: var(--glass);
            border: 1px solid var(--glass-border); border-radius: 30px;
            padding: 6px 14px; box-shadow: var(--card-shadow);
            backdrop-filter: blur(20px); -webkit-backdrop-filter: blur(20px);
        }
        .clock-display {
            font-family: 'SF Mono', 'Fira Code', monospace; font-size: 0.95rem; color: var(--text);
            padding-right: 14px; border-right: 1px solid var(--glass-border);
            display: flex; align-items: center; gap: 8px; font-weight: 600; cursor: default;
        }
        html[dir="rtl"] .clock-display {
            border-right: none; border-left: 1px solid var(--glass-border);
            padding-right: 0; padding-left: 14px;
        }
        .clock-display .time-icon {
            color: var(--accent); font-size: 1.1rem; display: inline-block;
        }
        .clock-display:hover .time-icon {
            animation: flipHourglass 1.2s ease-in-out infinite;
        }
        @keyframes flipHourglass {
            0% { transform: rotate(0deg); }
            50% { transform: rotate(180deg); }
            100% { transform: rotate(360deg); }
        }
        .lang-selector {
            padding: 0 8px 0 14px; background: transparent; border: none; color: var(--text);
            font-size: 0.9rem; font-weight: 700; display: flex; align-items: center; gap: 6px;
            cursor: pointer; transition: color 0.2s; outline: none;
        }
        html[dir="rtl"] .lang-selector { padding: 0 14px 0 8px; }
        .lang-selector:hover { color: var(--accent); }
        .lang-selector .chevron { font-size: 0.6rem; opacity: 0.7; transition: transform 0.3s; }
        .lang-menu {
            position: absolute; top: 100%; right: 0; margin-top: 12px; background: var(--bg-secondary);
            border: 1px solid var(--glass-border); border-radius: 14px; padding: 8px;
            min-width: 150px; box-shadow: var(--card-shadow); display: none; z-index: 1050;
        }
        html[dir="rtl"] .lang-menu { right: auto; left: 0; }
        .lang-menu.open { display: block; animation: slideDown 0.2s cubic-bezier(0.16, 1, 0.3, 1); }
        .lang-menu .lang-item {
            padding: 10px 14px; border-radius: 8px; cursor: pointer; transition: background 0.2s;
            display: flex; align-items: center; gap: 10px; color: var(--text); font-weight: 500;
        }
        .lang-menu .lang-item:hover { background: var(--bg-tertiary); color: var(--accent); }
        .card {
            background: var(--glass); border: 1px solid var(--glass-border);
            border-radius: 20px; transition: box-shadow 0.4s ease, border-color 0.4s ease;
            backdrop-filter: blur(16px); -webkit-backdrop-filter: blur(16px);
            box-shadow: var(--card-shadow);
        }
        .tilt-card { transition: transform 0.1s ease-out, box-shadow 0.1s ease-out; transform-style: preserve-3d; }
        .tilt-card:hover {
            border-color: var(--accent); z-index: 10;
            box-shadow: 0 20px 40px rgba(0,0,0,0.5), 0 0 30px var(--accent-glow);
        }
        .tilt-card .inner-content { transform: translateZ(30px); }
        .animate-pop { animation: popIn 0.7s cubic-bezier(0.16, 1, 0.3, 1) backwards; }
        .delay-1 { animation-delay: 0.1s; }
        .delay-2 { animation-delay: 0.2s; }
        .delay-3 { animation-delay: 0.3s; }
        .delay-4 { animation-delay: 0.4s; }
        @keyframes popIn {
            0% { opacity: 0; transform: translateY(30px) scale(0.98); }
            100% { opacity: 1; transform: translateY(0) scale(1); }
        }
        .stat-pill {
            background: linear-gradient(135deg, var(--bg-tertiary) 0%, rgba(0,0,0,0.1) 100%);
            border-radius: 18px; padding: 24px 30px; font-weight: 600;
            border: 1px solid var(--glass-border); cursor: pointer; transition: all 0.3s ease;
        }
        .stat-pill span { font-size: 3.2rem; font-weight: 800; line-height: 1.1; display:block; }
        .stat-pill .icon {
            font-size: 2rem; margin-bottom: 8px; animation: pulse 3s infinite; display: inline-block;
        }
        @keyframes pulse {
            0%, 100% { transform: scale(1); }
            50% { transform: scale(1.15); filter: drop-shadow(0 0 10px currentColor); }
        }
        .btn-accent {
            background: linear-gradient(135deg, var(--accent), var(--accent-2));
            color: #fff; border: none; font-weight: 600; border-radius: 14px; padding: 12px 24px;
            transition: all 0.3s cubic-bezier(0.175, 0.885, 0.32, 1.275);
            font-size: 1rem; display: inline-flex; align-items: center; gap: 8px; cursor: pointer;
        }
        .btn-accent:hover:not(:disabled) { box-shadow: 0 0 35px var(--accent-glow); transform: scale(1.05); }
        .btn-accent:disabled {
            opacity: 0.7; cursor: not-allowed; transform: none; box-shadow: none;
            background: var(--bg-tertiary); color: var(--text-secondary);
            border: 1px solid var(--glass-border);
        }
        .btn-outline-accent {
            background: transparent; border: 1px solid var(--accent); color: var(--accent);
            border-radius: 14px; padding: 12px 22px; font-weight: 600; transition: all 0.3s;
            font-size: 0.9rem; cursor: pointer;
        }
        .btn-outline-accent:hover {
            background: var(--accent); color: var(--bg-primary);
            box-shadow: 0 0 25px var(--accent-glow); transform: translateY(-2px);
        }
        .findings-table-container {
            border-radius: 18px; overflow: hidden; border: 1px solid var(--table-border);
            background: var(--table-row-bg);
        }
        .table { margin-bottom: 0; --bs-table-bg: transparent; --bs-table-color: var(--table-text); }
        .table>:not(caption)>*>* {
            background-color: var(--table-row-bg) !important; color: var(--table-text) !important;
            border-bottom-color: var(--table-border) !important; padding: 18px 22px;
            vertical-align: middle; transition: background-color 0.2s ease;
        }
        .table th {
            color: var(--accent) !important; font-weight: 700; text-transform: uppercase;
            font-size: 0.8rem; letter-spacing: 1px; background-color: var(--bg-secondary) !important;
        }
        .table-hover>tbody>tr:hover>* {
            background-color: var(--table-hover-bg) !important; color: var(--table-text) !important;
            box-shadow: none;
        }
        .table tbody tr { cursor: pointer; }
        .finding-detail {
            display: none; background: var(--bg-secondary); border-radius: 12px; padding: 20px;
            margin: 10px 0; color: var(--table-text); border: 1px solid var(--table-border);
            box-shadow: inset 0 2px 15px rgba(0,0,0,0.2);
        }
        .finding-detail.show { display: block; animation: fadeIn 0.3s ease; }
        .pagination-wrap {
            display: flex; justify-content: space-between; align-items: center; margin-top: 20px;
            padding: 10px 20px; background: var(--bg-secondary); border: 1px solid var(--glass-border);
            border-radius: 14px; box-shadow: inset 0 2px 10px rgba(0,0,0,0.1);
        }
        .pagination-info { font-size: 0.95rem; color: var(--text-secondary); font-weight: 600; }
        .pagination-btns { display: flex; gap: 10px; }
        .btn-page {
            background: var(--bg-tertiary); border: 1px solid var(--glass-border); color: var(--text);
            padding: 8px 18px; border-radius: 10px; font-weight: 600; font-size: 0.85rem;
            transition: all 0.2s; cursor: pointer;
        }
        .btn-page:hover:not(:disabled) {
            border-color: var(--accent); color: var(--accent);
            box-shadow: 0 0 15px var(--accent-glow); transform: translateY(-1px);
        }
        .btn-page:disabled { opacity: 0.4; cursor: not-allowed; }
        .report-modal-overlay {
            position: fixed; top: 0; left: 0; width: 100vw; height: 100vh;
            background: rgba(0,0,0,0.85); backdrop-filter: blur(15px); display: none;
            z-index: 2500; align-items: center; justify-content: center;
        }
        .report-modal-overlay.open { display: flex; animation: fadeIn 0.3s ease; }
        .report-modal-panel {
            background: var(--glass); border: 1px solid var(--glass-border); border-radius: 24px;
            padding: 35px; max-width: 650px; width: 90%; backdrop-filter: blur(30px);
            box-shadow: 0 0 80px var(--accent-glow); position: relative;
            animation: popIn 0.4s cubic-bezier(0.175, 0.885, 0.32, 1.275);
        }
        .report-grid { display: flex; gap: 16px; margin: 25px 0; }
        .report-card-opt {
            flex: 1; background: linear-gradient(135deg, var(--bg-secondary) 0%, rgba(0,0,0,0.2) 100%);
            border: 1px solid var(--glass-border); border-radius: 16px; padding: 24px 15px;
            text-align: center; cursor: pointer; transition: all 0.3s ease; display: flex;
            flex-direction: column; align-items: center; gap: 12px;
        }
        .report-card-opt:hover {
            border-color: var(--accent); transform: translateY(-5px);
            box-shadow: 0 10px 20px rgba(0,0,0,0.3), 0 0 15px var(--accent-glow);
        }
        .report-card-opt.selected {
            border-color: var(--accent); background: rgba(0, 229, 255, 0.08);
            box-shadow: 0 0 25px var(--accent-glow);
        }
        .report-card-opt .format-icon { font-size: 2.8rem; filter: drop-shadow(0 4px 8px rgba(0,0,0,0.3)); }
        .report-card-opt .format-title { font-size: 1.1rem; font-weight: 700; color: var(--text); }
        .report-card-opt .format-sub { font-size: 0.75rem; color: var(--text-secondary); font-weight: 500; }
        #attack-graph {
            background: var(--bg-secondary); border-radius: 18px;
            border: 1px solid var(--glass-border); overflow: hidden;
        }
        .sim-overlay {
            position: fixed; top: 0; left: 0; width: 100%; height: 100%;
            background: rgba(0,0,0,0.85); backdrop-filter: blur(12px); display: none;
            z-index: 2000; align-items: center; justify-content: center;
        }
        .sim-overlay.open { display: flex; animation: fadeIn 0.3s ease; }
        .sim-panel {
            background: var(--glass); border: 1px solid var(--glass-border); border-radius: 22px;
            padding: 32px; max-width: 700px; width: 90%; max-height: 80vh; overflow-y: auto;
            backdrop-filter: blur(30px); box-shadow: 0 0 100px var(--accent-glow); position: relative;
        }
        .sim-close {
            position: absolute; top: 16px; right: 20px; background: none; border: none;
            color: var(--text-secondary); font-size: 2.5rem; cursor: pointer;
            transition: color 0.2s; z-index: 10; line-height: 0.8;
        }
        .sim-close:hover { color: var(--danger); }
        @keyframes fadeIn { from { opacity: 0; } to { opacity: 1; } }
        .theme-strip {
            position: fixed; top: 50%; left: 16px; transform: translateY(-50%); z-index: 1030;
            background: var(--glass); border: 1px solid var(--glass-border); border-radius: 30px;
            padding: 12px 10px; display: flex; flex-direction: column; gap: 12px;
            backdrop-filter: blur(14px); box-shadow: var(--card-shadow);
        }
        html[dir="rtl"] .theme-strip { left: auto; right: 16px; }
        .theme-strip .theme-dot {
            width: 26px; height: 26px; border-radius: 50%; cursor: pointer;
            border: 2px solid transparent; transition: all 0.3s;
        }
        .theme-strip .theme-dot:hover, .theme-strip .theme-dot.active {
            border-color: var(--text); transform: scale(1.4); box-shadow: 0 0 15px currentColor;
        }
        #search-input-row { display: none; margin-top: 16px; }
        #search-input-row.expanded { display: block; animation: slideDown 0.3s ease; }
        #search-input-row input {
            background: var(--bg-secondary); color: var(--text); border: 1px solid var(--glass-border);
            border-radius: 30px; padding: 12px 20px; font-size: 0.95rem; width: 100%; transition: all 0.3s;
        }
        #search-input-row input:focus {
            outline: none; border-color: var(--accent); box-shadow: 0 0 20px var(--accent-glow);
        }
        .cli-flag-card {
            background: var(--bg-secondary); border-radius: 12px; padding: 18px; margin-bottom: 12px;
            transition: all 0.3s; border-left: 4px solid transparent; display: flex; align-items: flex-start;
            gap: 14px; border: 1px solid var(--glass-border);
        }
        html[dir="rtl"] .cli-flag-card { border-left: none; border-right: 4px solid transparent; }
        .cli-flag-card:hover {
            border-color: var(--accent); transform: translateY(-4px); box-shadow: var(--card-shadow);
        }
        .cli-flag-card code {
            color: var(--accent); background: transparent; font-size: 1rem;
            display: block; margin-bottom: 6px; font-weight: 700;
        }
        .cli-flag-card .flag-desc {
            color: var(--text-secondary) !important; font-weight: 500; font-size: 0.88rem;
        }
        .toggle-pill {
            background: var(--bg-tertiary); border: 1px solid var(--glass-border); color: var(--accent);
            border-radius: 30px; padding: 8px 20px; font-size: 0.85rem; font-weight: 600;
            transition: all 0.3s; display: inline-flex; align-items: center; gap: 8px; cursor: pointer;
        }
        .toggle-pill:hover { background: var(--accent); color: var(--bg-primary); }
        .toggle-pill.expanded .arrow { transform: rotate(90deg); }
        .chart-center-text {
            position: absolute; top: 50%; left: 50%; transform: translate(-50%, -50%);
            text-align: center; background: var(--glass); border: 1px solid var(--glass-border);
            border-radius: 50%; width: 110px; height: 110px; display: flex; flex-direction: column;
            align-items: center; justify-content: center; box-shadow: 0 8px 25px rgba(0,0,0,0.3);
            backdrop-filter: blur(12px); transition: all 0.4s;
            pointer-events: auto; cursor: default;
        }
        .chart-center-text:hover {
            transform: translate(-50%, -50%) scale(1.2);
            box-shadow: 0 0 35px var(--accent-glow); border-color: var(--accent);
        }
        .chart-total-num { font-size: 2.2rem; font-weight: 800; color: var(--text); line-height: 1; }
        .chart-total-label {
            font-size: 0.75rem; color: var(--text-secondary); text-transform: uppercase;
            margin-top: 6px; font-weight: 700; letter-spacing: 1px;
        }
        .typewriter-cursor::after {
            content: '▋'; display: inline-block; color: var(--accent);
            animation: blink 1s step-end infinite; margin-left: 4px;
        }
        @keyframes blink { 0%, 100% { opacity: 1; } 50% { opacity: 0; } }
        .custom-progress {
            height: 10px; background: var(--glass-border); border-radius: 10px;
            overflow: hidden; margin-top: 10px; width: 100%;
        }
        .custom-progress-bar {
            height: 100%; border-radius: 10px; transition: width 1s cubic-bezier(0.16, 1, 0.3, 1);
        }
        .ai-meta-badge {
            font-size: 0.8rem; font-weight: 700; padding: 6px 12px; border-radius: 12px;
            display: flex; align-items: center; gap: 6px;
        }
    </style>
</head>
<body>
    <div class="bg-pattern"></div>
    <div class="bg-orbs">
        <div class="orb orb-1"></div>
        <div class="orb orb-2"></div>
    </div>
    <canvas id="particles-canvas"></canvas>
    <div class="theme-strip animate-pop" id="theme-strip" role="group" aria-label="Theme Selection">
        <span class="theme-dot active" data-theme="cyber" style="background:#00E5FF;"
              onclick="switchTheme('cyber')"></span>
        <span class="theme-dot" data-theme="midnight" style="background:#6366F1;"
              onclick="switchTheme('midnight')"></span>
        <span class="theme-dot" data-theme="arctic" style="background:#0284C7;"
              onclick="switchTheme('arctic')"></span>
        <span class="theme-dot" data-theme="forest" style="background:#34D399;"
              onclick="switchTheme('forest')"></span>
        <span class="theme-dot" data-theme="dark" style="background:#FAFAFA;"
              onclick="switchTheme('dark')"></span>
    </div>
    <main class="content-layer">
    <nav class="navbar animate-pop">
        <div class="container-fluid d-flex justify-content-between align-items-center">
            <span class="navbar-brand mb-0 d-flex align-items-center gap-2">
                🛡️ <span>Pipeline</span> Sentinel
                <small style="font-size:0.4em; color:var(--text); background:var(--accent-glow);
                border:1px solid var(--accent); padding:4px 10px; border-radius:20px; font-weight:700;">
                COMMAND CENTER</small>
            </span>
            <div class="top-controls position-relative">
                <div class="clock-display" id="clock-display" aria-live="polite">
                    <span class="time-icon" aria-hidden="true">⏳</span>
                    <span id="clock-text">--:--:--</span>
                </div>
                <button class="lang-selector" id="langDropdownBtn" aria-haspopup="true" onclick="toggleLangMenu()">
                    <span id="current-lang-icon">🇬🇧</span> <span id="current-lang-label">EN</span>
                    <span class="chevron" aria-hidden="true">▼</span>
                </button>
                <div class="lang-menu" id="langMenu" role="menu">
                    <div class="lang-item" role="menuitem" tabindex="0" onclick="switchLanguage('en')">
                        🇬🇧 English
                    </div>
                    <div class="lang-item" role="menuitem" tabindex="0" onclick="switchLanguage('ru')">
                        🇷🇺 Русский
                    </div>
                    <div class="lang-item" role="menuitem" tabindex="0" onclick="switchLanguage('zh')">
                        🇨🇳 中文
                    </div>
                    <div class="lang-item" role="menuitem" tabindex="0" onclick="switchLanguage('ar')">
                        🇸🇦 العربية
                    </div>
                </div>
            </div>
        </div>
    </nav>
    <div class="container py-3">
        <div class="row g-3 mb-4 animate-pop delay-1" id="stats-row">
            <div class="col-md-3">
                <div class="card p-3 text-center tilt-card" role="button" tabindex="0"
                     onclick="filterBySeverity('CRITICAL')">
                    <div class="stat-pill text-danger inner-content">
                        <div class="icon" aria-hidden="true">🔥</div><span id="stat-critical">0</span>
                        <small data-i18n="critical" class="fw-bold mt-1 d-block">CRITICAL</small>
                    </div>
                </div>
            </div>
            <div class="col-md-3">
                <div class="card p-3 text-center tilt-card" role="button" tabindex="0"
                     onclick="filterBySeverity('HIGH')">
                    <div class="stat-pill text-warning inner-content">
                        <div class="icon" aria-hidden="true">⚠️</div><span id="stat-high">0</span>
                        <small data-i18n="high" class="fw-bold mt-1 d-block">HIGH</small>
                    </div>
                </div>
            </div>
            <div class="col-md-3">
                <div class="card p-3 text-center tilt-card" role="button" tabindex="0"
                     onclick="filterBySeverity('MEDIUM')">
                    <div class="stat-pill text-info inner-content">
                        <div class="icon" aria-hidden="true">📊</div><span id="stat-medium">0</span>
                        <small data-i18n="medium" class="fw-bold mt-1 d-block">MEDIUM</small>
                    </div>
                </div>
            </div>
            <div class="col-md-3">
                <div class="card p-3 text-center tilt-card" role="button" tabindex="0"
                     onclick="filterBySeverity('LOW')">
                    <div class="stat-pill text-success inner-content">
                        <div class="icon" aria-hidden="true">🛡️</div><span id="stat-low">0</span>
                        <small data-i18n="low" class="fw-bold mt-1 d-block">LOW</small>
                    </div>
                </div>
            </div>
        </div>
        <div class="row g-4 mb-4 animate-pop delay-2">
            <div class="col-md-4">
                <div class="card p-4 h-100 tilt-card">
                    <h5 class="card-title mb-4 inner-content" style="color:var(--accent); font-weight:800;">
                        📊 <span data-i18n="severity_breakdown">Severity Breakdown</span>
                    </h5>
                    <div class="inner-content" style="position:relative; height:100%; min-height:280px; display:flex;">
                        <div id="severityChart" style="width:100%; height:100%; position:absolute;"></div>
                        <div class="chart-center-text">
                            <div class="chart-total-num" id="chart-total-num">0</div>
                            <div class="chart-total-label" data-i18n="total">TOTAL</div>
                        </div>
                    </div>
                </div>
            </div>
            <div class="col-md-8">
                <div class="card p-4 h-100 tilt-card">
                    <h5 class="card-title mb-4 inner-content" style="color:var(--accent); font-weight:800;">
                        📈 <span data-i18n="trend_over_time">Trend Over Time</span>
                    </h5>
                    <div id="trendChart" class="inner-content" style="width:100%; height:300px;"></div>
                </div>
            </div>
        </div>
        <div class="row g-3 mb-4 animate-pop delay-3">
            <div class="col-12">
                <div class="card p-4">
                    <div class="d-flex justify-content-between align-items-center mb-3 flex-wrap gap-3">
                        <h5 class="card-title mb-0" style="color:var(--accent); font-weight:800;">
                            🕸️ <span data-i18n="attack_paths">Attack Paths (AI‑Generated)</span>
                        </h5>
                        <div class="d-flex align-items-center gap-3">
                            <span class="ai-badge fw-bold" id="ai-status"
                                  style="background:var(--bg-secondary); border:1px solid var(--glass-border);
                                  padding:6px 14px; border-radius:20px; font-size:0.85rem;">
                                🤖 <span data-i18n="no_ai">Run with --analyze</span>
                            </span>
                            <button class="btn-accent shadow-sm" id="simulate-selected-btn" disabled>
                                ⚡ <span data-i18n="simulate_selected">Simulate Selected</span>
                            </button>
                        </div>
                    </div>
                    <div id="attack-graph" class="mt-3 shadow-inner"
                         style="width:100%; height:450px; position:relative;"></div>
                    <div id="attack-detail" class="mt-3 p-4 rounded"
                         style="display:none; background:var(--bg-secondary); border:1px solid var(--glass-border);"
                         aria-live="polite"></div>
                    <div id="attack-error" class="text-warning fw-bold mt-2"
                         style="display:none;" aria-live="polite"></div>
                </div>
            </div>
        </div>
        <div class="row g-3 mb-4 animate-pop delay-3">
            <div class="col-12">
                <div class="card p-4 tilt-card">
                    <div class="inner-content">
                        <div class="d-flex justify-content-between align-items-center mb-3 flex-wrap gap-2">
                            <h5 class="card-title mb-0" style="color:var(--accent); font-weight:800;">
                                🧠 <span data-i18n="ai_summary">AI Executive Summary</span>
                            </h5>
                           <div id="ai-meta-info" class="d-flex gap-2" style="display:none !important;">
                                <div class="ai-meta-badge shadow-sm"
                                     style="background:var(--bg-secondary); border:1px solid var(--glass-border);">
                                    ⚙️ <span id="ai-hardware">CPU</span>
                                </div>
                                <div class="ai-meta-badge shadow-sm"
                                     style="background:var(--accent-glow); color:var(--accent);
                                            border:1px solid var(--accent);">
                                    ⏱️ <span id="ai-time">0s</span>
                                </div>
                            </div>
                        </div>
                        <div class="bg-secondary p-4 rounded shadow-inner"
                             style="background:var(--bg-secondary) !important; border:1px solid var(--glass-border);">
                            <div id="exec-summary" class="text-muted typewriter-cursor" data-i18n="no_ai"
                                 style="font-size:1.1rem; line-height:1.8; color:var(--text) !important;">
                                No AI analysis available. Run with --analyze.
                            </div>
                        </div>
                        <div id="risk-score-container" class="mt-4" style="display:none;">
                            <div class="d-flex justify-content-between align-items-end mb-1">
                                <span class="fw-bold" style="color:var(--text-secondary); font-size:0.8rem;"
                                      data-i18n="ai_risk_score">AI Risk Score</span>
                                <span id="risk-score-text" class="fw-bold fs-5">0/100</span>
                            </div>
                            <div class="custom-progress shadow-sm">
                                <div id="risk-score-bar" class="custom-progress-bar"
                                     role="progressbar" style="width:0%;"></div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
        <div class="row g-3 mb-4 animate-pop delay-4">
            <div class="col-12">
                <div class="card p-4">
                    <div class="d-flex justify-content-between align-items-center">
                        <h5 class="card-title mb-0" style="color:var(--accent); font-weight:800;">
                            ⚙️ <span data-i18n="cli_ref_title">CLI Quick Reference</span>
                        </h5>
                        <span class="toggle-pill shadow-sm" id="cli-toggle" onclick="toggleCLI()">
                            <span data-i18n="show_hide">Show</span>
                            <span class="arrow mx-1" aria-hidden="true">▶</span>
                        </span>
                    </div>
                    <div class="collapse mt-4" id="cli-ref-body">
                        <div class="row" id="cli-ref-cards"></div>
                    </div>
                </div>
            </div>
        </div>
        <div class="card p-4 mb-4 animate-pop delay-4" id="findings-section">
            <div class="d-flex justify-content-between align-items-center mb-4 flex-wrap gap-3">
                <div class="d-flex align-items-center gap-3">
                    <button class="btn btn-sm" id="search-toggle-btn"
                            style="font-size:1.3rem; color:var(--text-secondary); background:var(--bg-secondary);
                            border:1px solid var(--glass-border); border-radius:10px; padding:6px 12px;">🔍</button>
                    <h5 class="card-title mb-0" style="color:var(--accent); font-weight:800; font-size:1.4rem;">
                        <span data-i18n="findings">Findings</span>
                    </h5>
                </div>
                <div class="d-flex align-items-center gap-3">
                    <button class="btn-accent shadow-sm" id="report-btn" onclick="openReportModal()">
                        <span>📄</span> <span data-i18n="generate_report">Report</span>
                    </button>
                    <button class="btn-outline-accent shadow-sm" id="clear-filters-btn">
                        ✕ <span data-i18n="clear_filters">Clear Filters</span>
                    </button>
                </div>
            </div>
            <div id="search-input-row" class="mb-4">
                <input type="text" id="searchInput" class="shadow-inner" data-i18n-placeholder="search_placeholder"
                       placeholder="Search findings...">
            </div>
            <div class="findings-table-container shadow-sm">
                <div class="table-responsive">
                    <table class="table table-hover align-middle findings-table">
                        <thead><tr>
                            <th style="width:50px; text-align:center;">
                                <input type="checkbox" id="select-all" class="form-check-input" style="cursor:pointer;">
                            </th>
                            <th data-i18n="tool">Tool</th>
                            <th data-i18n="id_col">ID</th>
                            <th data-i18n="severity">Severity</th>
                            <th data-i18n="target">Target</th>
                            <th data-i18n="description">Description</th>
                        </tr></thead>
                        <tbody id="tableBody" aria-live="polite"></tbody>
                    </table>
                </div>
            </div>
            <div class="pagination-wrap mt-3">
                <div class="pagination-info" id="pagination-info">Showing 0-0 of 0 entries</div>
                <div class="pagination-btns">
                    <button class="btn-page" id="btn-prev-page" data-i18n="prev_page" disabled>◀ Previous</button>
                    <button class="btn-page" id="btn-next-page" data-i18n="next_page" disabled>Next ▶</button>
                </div>
            </div>
        </div>
        <div class="sim-overlay" id="simOverlay" role="dialog" aria-modal="true">
            <div class="sim-panel">
                <button class="sim-close" onclick="closeSimPanel()">&times;</button>
                <div id="sim-panel-content">
                    <div class="text-center py-5">
                        <div class="spinner-border"
                             style="color:var(--accent); width:3.5rem; height:3.5rem; border-width:4px;"></div>
                        <h4 class="mt-4" id="sim-title" data-i18n="simulating"
                            style="color:var(--text); font-weight:700;">Simulating attack chain...</h4>
                        <p class="text-muted mt-2 fw-bold" data-i18n="sim_sub">Executing sandbox PoC environment</p>
                    </div>
                </div>
                <div class="sim-footer">
                    <button class="btn btn-outline-secondary px-4 py-2 fw-bold"
                            style="border-radius:12px; color:var(--text); border-color:var(--glass-border);"
                            onclick="closeSimPanel()" data-i18n="close">Close</button>
                </div>
            </div>
        </div>
        <div class="report-modal-overlay" id="reportModal" role="dialog" aria-modal="true">
            <div class="report-modal-panel">
                <button class="sim-close" onclick="closeReportModal()">&times;</button>
                <h4 class="fw-bold" style="color:var(--accent);" data-i18n="export_title">Export Security Report</h4>
                <p class="text-muted" data-i18n="export_sub">Select file layout criteria for data mapping.</p>
                <div class="report-grid">
                    <div class="report-card-opt" id="opt-pdf" onclick="selectReportFormat('pdf')">
                        <div class="format-icon">📕</div>
                        <div class="format-title" data-i18n="pdf_doc">PDF Document</div>
                        <div class="format-sub" data-i18n="pdf_sub">Executive Presentation</div>
                    </div>
                    <div class="report-card-opt" id="opt-json" onclick="selectReportFormat('json')">
                        <div class="format-icon">📦</div>
                        <div class="format-title" data-i18n="json_data">JSON Dataset</div>
                        <div class="format-sub" data-i18n="json_sub">Automation Merges</div>
                    </div>
                    <div class="report-card-opt" id="opt-html" onclick="selectReportFormat('html')">
                        <div class="format-icon">🌐</div>
                        <div class="format-title" data-i18n="html_view">HTML Engine</div>
                        <div class="format-sub" data-i18n="html_sub">Instant Viewport</div>
                    </div>
                </div>
                <div class="d-flex justify-content-end gap-3 mt-4">
                    <button class="btn btn-outline-secondary px-4 py-2"
                            style="border-radius:12px; color:var(--text);"
                            onclick="closeReportModal()" data-i18n="close">Close</button>
                    <button class="btn-accent px-4 py-2" id="modal-download-btn"
                            onclick="executeModalDownload()" disabled>
                        <span id="modal-download-spinner" class="spinner-border spinner-border-sm d-none"></span>
                        <span data-i18n="download_now">Download Now</span>
                    </button>
                </div>
            </div>
        </div>
        <div class="toast-container position-fixed bottom-0 end-0 p-4" id="toast-container"
             style="z-index: 1060;"></div>
        <footer class="text-center py-4 mt-5 animate-pop delay-4" style="border-top:1px solid var(--glass-border);">
            <small style="color:var(--text-secondary); font-size:0.9rem;">
                🛡️ <strong style="color:var(--text); font-weight:800;">Pipeline Sentinel</strong> · crafted by
                <a href="https://github.com/Mehrdoost" class="text-decoration-none fw-bold"
                   style="color:var(--accent)" target="_blank">ReverseForge</a>
                <span class="version-badge shadow-sm" style="background:var(--accent-2); color:#fff;">v0.4.1</span> ·
                <a href="https://github.com/Mehrdoost/devsecops-radar" class="text-decoration-none fw-bold"
                   style="color:var(--accent)" target="_blank">View on GitHub</a>
            </small>
        </footer>
    </div>
    </main>
    <script src="{{ url_for('static', filename='js/bootstrap.bundle.min.js') }}"></script>
    <script src="{{ url_for('static', filename='js/echarts.min.js') }}"></script>
    <script src="{{ url_for('static', filename='js/d3.v7.min.js') }}"></script>
    <script>
        const T = {
            en: {
                critical: "CRITICAL", high: "HIGH", medium: "MEDIUM", low: "LOW",
                severity_breakdown: "Severity Breakdown", trend_over_time: "Trend Over Time",
                attack_paths: "Attack Paths (AI‑Generated)", simulate_selected: "Simulate Selected",
                findings: "Findings", tool: "Tool", id_col: "ID", severity: "Severity",
                target: "Target", description: "Description", close: "Close",
                attack_simulation: "Attack Simulation", search_placeholder: "Search findings...",
                simulating: "Simulating attack chain...",
                no_ai: "Run with --analyze to enable AI insights", generate_report: "Report",
                clear_filters: "Clear Filters", ai_summary: "AI Executive Summary",
                report_loading: "Generating...", report_success: "Report downloaded!",
                report_failed: "Report generation failed.", cli_ref_title: "CLI Quick Reference",
                show_hide: "Show", hide: "Hide", trivy_desc: "Trivy JSON file or image name",
                semgrep_desc: "Semgrep JSON file or target directory",
                poutine_desc: "Poutine JSON file or repository path",
                zizmor_desc: "Zizmor JSON file or repository path",
                gitleaks_desc: "Gitleaks JSON file or repository path",
                rules_desc: "Directory with custom JSON rule files",
                policy_desc: "Policy JSON file for gating",
                analyze_desc: "Enable LLM analysis (requires Ollama)",
                fix_desc: "Auto‑apply AI‑suggested fixes", review_desc: "Review each fix before applying",
                report_desc: "Generate PDF report", topology_desc: "Path to topology JSON file",
                compliance_desc: "Compliance framework (CIS/PCI‑DSS/ISO27001)",
                output_desc: "Output file for merged findings", wizard_desc: "Interactive setup wizard",
                llm_backend_desc: "LLM backend (ollama or litellm)", llm_model_desc: "LLM model name",
                rego_policy_desc: "OPA Rego policy file", update_rules_desc: "Download/update community rules",
                docker_missing: "Docker not installed. Simulation needs Docker.", total: "TOTAL",
                export_title: "Export Security Report", export_sub: "Select format for data mapping.",
                pdf_sub: "Executive Presentation", json_sub: "Automation Merges",
                html_sub: "Instant Viewport", download_now: "Download Now", prev_page: "◀ Previous",
                next_page: "Next ▶", no_findings: "No findings match your filters.",
                sim_sub: "Executing sandbox PoC environment", sim_results: "Simulation Results",
                sandbox_out: "Sandbox Output:", pdf_doc: "PDF Document", json_data: "JSON Dataset",
                html_view: "HTML Engine", simulate_btn: "⚡ Simulate", line: "Line",
                ai_risk_score: "AI Risk Score", export_sarif_desc: "Export findings as SARIF",
                export_cdx_desc: "Export findings as CycloneDX", notify_jira_desc: "Create Jira issues for findings",
                notify_asana_desc: "Create Asana tasks for critical findings"
            },
            ru: {
                critical: "КРИТИЧЕСКИЙ", high: "ВЫСОКИЙ", medium: "СРЕДНИЙ", low: "НИЗКИЙ",
                severity_breakdown: "Распределение", trend_over_time: "Тренд по времени",
                attack_paths: "Пути атак (ИИ)", simulate_selected: "Симулировать",
                findings: "Находки", tool: "Инструмент", id_col: "ID", severity: "Серьёзность",
                target: "Цель", description: "Описание", close: "Закрыть",
                attack_simulation: "Симуляция атаки", search_placeholder: "Поиск находок...",
                simulating: "Симуляция цепочки атак...",
                no_ai: "Запустите с --analyze для ИИ‑анализа", generate_report: "Отчёт",
                clear_filters: "Сброс", ai_summary: "ИИ Сводка",
                report_loading: "Генерация...", report_success: "Отчёт загружен!",
                report_failed: "Ошибка генерации.", cli_ref_title: "Справка CLI",
                show_hide: "Показать", hide: "Скрыть", trivy_desc: "JSON‑файл Trivy",
                semgrep_desc: "JSON‑файл Semgrep", poutine_desc: "JSON‑файл Poutine",
                zizmor_desc: "JSON‑файл Zizmor", gitleaks_desc: "JSON‑файл Gitleaks",
                rules_desc: "Директория с JSON‑правилами", policy_desc: "JSON‑файл политики",
                analyze_desc: "Включить ИИ‑анализ (Ollama)", fix_desc: "Авто‑применение исправлений",
                review_desc: "Просмотр перед применением", report_desc: "Сгенерировать PDF‑отчёт",
                topology_desc: "Путь к файлу топологии", compliance_desc: "Фреймворк комплаенса",
                output_desc: "Выходной файл", wizard_desc: "Мастер первой настройки",
                llm_backend_desc: "LLM‑бэкенд (ollama/litellm)", llm_model_desc: "Модель LLM",
                rego_policy_desc: "Политика OPA Rego", update_rules_desc: "Обновить правила",
                docker_missing: "Docker не установлен. Требуется Docker.", total: "ВСЕГО",
                export_title: "Экспорт Отчета", export_sub: "Выберите нужный формат.",
                pdf_sub: "Презентация", json_sub: "Интеграция", html_sub: "Просмотр в браузере",
                download_now: "Скачать", prev_page: "◀ Назад", next_page: "Вперед ▶",
                no_findings: "Нет находок.", sim_sub: "Запуск песочницы PoC...",
                sim_results: "Результаты симуляции", sandbox_out: "Вывод песочницы:",
                pdf_doc: "Документ PDF", json_data: "Набор данных JSON", html_view: "Движок HTML",
                simulate_btn: "⚡ Симулировать", line: "Строка", ai_risk_score: "Оценка риска ИИ",
                export_sarif_desc: "Экспорт находок в SARIF", export_cdx_desc: "Экспорт находок в CycloneDX",
                notify_jira_desc: "Создать задачи Jira", notify_asana_desc: "Создать задачи Asana"
            },
            zh: {
                critical: "严重", high: "高", medium: "中", low: "低",
                severity_breakdown: "严重性分布", trend_over_time: "时间趋势",
                attack_paths: "攻击路径 (AI生成)", simulate_selected: "模拟选中",
                findings: "发现", tool: "工具", id_col: "编号", severity: "严重性",
                target: "目标", description: "描述", close: "关闭",
                attack_simulation: "攻击模拟", search_placeholder: "搜索发现...",
                simulating: "正在模拟攻击链...", no_ai: "使用 --analyze 开启 AI 分析",
                generate_report: "报告", clear_filters: "清除", ai_summary: "AI执行摘要",
                report_loading: "生成中...", report_success: "报告下载成功！",
                report_failed: "报告生成失败。", cli_ref_title: "CLI 快速参考",
                show_hide: "显示", hide: "隐藏", trivy_desc: "Trivy 文件或镜像",
                semgrep_desc: "Semgrep 文件或目录", poutine_desc: "Poutine 文件或仓库",
                zizmor_desc: "Zizmor 文件或仓库", gitleaks_desc: "Gitleaks 文件或仓库",
                rules_desc: "自定义 JSON 规则", policy_desc: "用于门控的 Policy 文件",
                analyze_desc: "启用 LLM 分析", fix_desc: "自动应用 AI 修复",
                review_desc: "应用前检查修复", report_desc: "生成 PDF 报告",
                topology_desc: "拓扑 JSON 文件", compliance_desc: "合规框架 (CIS/PCI)",
                output_desc: "合并的输出文件", wizard_desc: "首次设置向导",
                llm_backend_desc: "LLM 后端", llm_model_desc: "LLM 模型",
                rego_policy_desc: "OPA Rego 策略", update_rules_desc: "下载/更新规则",
                docker_missing: "未安装 Docker。", total: "总计",
                export_title: "导出安全报告", export_sub: "选择导出的文件格式。",
                pdf_sub: "高级简报", json_sub: "自动化集成", html_sub: "网页端直接查看",
                download_now: "立即下载", prev_page: "◀ 上一页", next_page: "下一页 ▶",
                no_findings: "没有符合条件的发现。", sim_sub: "正在执行沙盒 PoC 环境",
                sim_results: "模拟结果", sandbox_out: "沙盒输出:", pdf_doc: "PDF 文档",
                json_data: "JSON 数据集", html_view: "HTML 引擎", simulate_btn: "⚡ 模拟",
                line: "行", ai_risk_score: "AI 风险评分", export_sarif_desc: "将发现导出为 SARIF",
                export_cdx_desc: "将发现导出为 CycloneDX", notify_jira_desc: "为发现创建 Jira 任务",
                notify_asana_desc: "为关键发现创建 Asana 任务"
            },
            ar: {
                critical: "حرج", high: "عالي", medium: "متوسط", low: "منخفض",
                severity_breakdown: "توزيع الخطورة", trend_over_time: "مخطط الوقت",
                attack_paths: "مسارات الهجوم (AI)", simulate_selected: "محاكاة المحدد",
                findings: "الثغرات المكتشفة", tool: "الأداة", id_col: "المعرف",
                severity: "الخطورة", target: "الهدف", description: "الوصف", close: "إغلاق",
                attack_simulation: "محاكاة الهجوم", search_placeholder: "البحث...",
                simulating: "جاري المحاكاة...", no_ai: "استخدم --analyze لتفعيل الذكاء الاصطناعي",
                generate_report: "التقرير", clear_filters: "مسح الفلاتر", ai_summary: "الملخص التنفيذي",
                report_loading: "جاري الإنشاء...", report_success: "تم تحميل التقرير بنجاح!",
                report_failed: "فشل إنشاء التقرير.", cli_ref_title: "أوامر CLI",
                show_hide: "عرض", hide: "إخفاء", trivy_desc: "ملف Trivy أو اسم الصورة",
                semgrep_desc: "ملف Semgrep أو المجلد", poutine_desc: "ملف Poutine أو المسار",
                zizmor_desc: "ملف Zizmor أو المسار", gitleaks_desc: "ملف Gitleaks أو المسار",
                rules_desc: "قواعد JSON المخصصة", policy_desc: "قواعد Policy JSON",
                analyze_desc: "تفعيل تحليل LLM", fix_desc: "تطبيق الإصلاحات آلياً",
                review_desc: "مراجعة قبل التطبيق", report_desc: "إنشاء تقرير PDF",
                topology_desc: "مسار ملف Topology", compliance_desc: "إطار الامتثال",
                output_desc: "ملف الدمج النهائي", wizard_desc: "معالج الإعداد",
                llm_backend_desc: "محرك الذكاء الاصطناعي", llm_model_desc: "اسم النموذج",
                rego_policy_desc: "ملف سياسة OPA", update_rules_desc: "تحديث القواعد",
                docker_missing: "Docker غير مثبت.", total: "الإجمالي",
                export_title: "تصدير التقرير", export_sub: "حدد التنسيق المطلوب.",
                pdf_sub: "عرض تقديمي", json_sub: "أتمتة البرمجيات", html_sub: "معاينة بالمتصفح",
                download_now: "تحميل الآن", prev_page: "◀ السابق", next_page: "التالي ▶",
                no_findings: "لا توجد ثغرات.", sim_sub: "تنفيذ بيئة إثبات المفهوم",
                sim_results: "نتائج المحاكاة", sandbox_out: "المخرجات:", pdf_doc: "مستند PDF",
                json_data: "بيانات JSON", html_view: "محرك HTML", simulate_btn: "⚡ محاكاة",
                line: "سطر", ai_risk_score: "مخاطر AI", export_sarif_desc: "تصدير النتائج بتنسيق SARIF",
                export_cdx_desc: "تصدير النتائج بتنسيق CycloneDX", notify_jira_desc: "إنشاء تذاكر Jira",
                notify_asana_desc: "إنشاء مهام Asana للثغرات الحرجة"
            }
        };

        let CL = localStorage.getItem('pipeline-lang') || 'en';

        function switchLanguage(l) {
            CL = l;
            localStorage.setItem('pipeline-lang', l);
            document.documentElement.lang = l;
            if (l === 'ar') {
                document.documentElement.dir = "rtl";
                document.body.style.textAlign = "right";
            } else {
                document.documentElement.dir = "ltr";
                document.body.style.textAlign = "left";
            }
            document.querySelectorAll('[data-i18n]').forEach(el => {
                const k = el.getAttribute('data-i18n');
                if (T[CL] && T[CL][k]) {
                    el.textContent = T[CL][k];
                }
            });
            document.querySelectorAll('[data-i18n-placeholder]').forEach(el => {
                const k = el.getAttribute('data-i18n-placeholder');
                if (T[CL] && T[CL][k]) {
                    el.placeholder = T[CL][k];
                }
            });
            const langIcons = { en: "🇬🇧", ru: "🇷🇺", zh: "🇨🇳", ar: "🇸🇦" };
            const langLabels = { en: "EN", ru: "RU", zh: "ZH", ar: "AR" };
            document.getElementById('current-lang-icon').textContent = langIcons[l];
            document.getElementById('current-lang-label').textContent = langLabels[l];
            document.getElementById('langMenu').classList.remove('open');
            buildCLIRef();
            updatePaginationInfo();
            renderTable();
            updateClock();
            if (typeof lastCounts !== 'undefined' && lastCounts) {
                createSeverityChart(lastCounts);
            }
            if (typeof lastScanData !== 'undefined' && lastScanData) {
                createTrendChart(lastScanLabels, lastScanData);
            }
        }

        function toggleLangMenu() {
            document.getElementById('langMenu').classList.toggle('open');
        }

        document.addEventListener('click', function(e) {
            const btn = document.getElementById('langDropdownBtn');
            const menu = document.getElementById('langMenu');
            if (btn && menu && !btn.contains(e.target) && !menu.contains(e.target)) {
                menu.classList.remove('open');
            }
        });

        function initTiltCards() {
            document.querySelectorAll('.tilt-card').forEach(card => {
                card.addEventListener('mousemove', e => {
                    const rect = card.getBoundingClientRect();
                    const x = e.clientX - rect.left;
                    const y = e.clientY - rect.top;
                    const centerX = rect.width / 2;
                    const centerY = rect.height / 2;
                    const rotateX = ((y - centerY) / centerY) * -5;
                    const rotateY = ((x - centerX) / centerX) * 5;
                    card.style.transform = `perspective(1000px) rotateX(${rotateX}deg) ` +
                                           `rotateY(${rotateY}deg) scale3d(1.02, 1.02, 1.02)`;
                });
                card.addEventListener('mouseleave', () => {
                    card.style.transform = `perspective(1000px) rotateX(0deg) rotateY(0deg) scale3d(1, 1, 1)`;
                });
            });
        }

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
                {flag:'--export-sarif', desc:'export_sarif_desc', icon:'📤'},
                {flag:'--export-cyclonedx', desc:'export_cdx_desc', icon:'📦'},
                {flag:'--topology', desc:'topology_desc', icon:'🗺️'},
                {flag:'--compliance', desc:'compliance_desc', icon:'✅'},
                {flag:'--notify-jira', desc:'notify_jira_desc', icon:'🎫'},
                {flag:'--notify-asana', desc:'notify_asana_desc', icon:'📋'},
                {flag:'--wizard', desc:'wizard_desc', icon:'🧙'},
                {flag:'--update-rules', desc:'update_rules_desc', icon:'🔄'}
            ];
            const container = document.getElementById('cli-ref-cards');
            if (!container) return;
            container.innerHTML = '';
            flags.forEach(f => {
                const col = document.createElement('div');
                col.className = 'col-md-6 col-lg-4';
                const descText = (T[CL] && T[CL][f.desc]) ? T[CL][f.desc] : f.desc;
                col.innerHTML = `
                    <div class="cli-flag-card">
                        <div class="flag-icon" aria-hidden="true">${f.icon}</div>
                        <div>
                            <code>${f.flag}</code>
                            <div class="flag-desc">${descText}</div>
                        </div>
                    </div>`;
                container.appendChild(col);
            });
        }

        function toggleCLI() {
            const body = document.getElementById('cli-ref-body');
            const toggle = document.getElementById('cli-toggle');
            const bsCollapse = bootstrap.Collapse.getInstance(body) ||
                               new bootstrap.Collapse(body, { toggle: false });
            bsCollapse.toggle();
            body.addEventListener('shown.bs.collapse', () => {
                toggle.classList.add('expanded');
                toggle.querySelector('[data-i18n="show_hide"]').textContent = T[CL]?.hide || 'Hide';
            }, {once:true});
            body.addEventListener('hidden.bs.collapse', () => {
                toggle.classList.remove('expanded');
                toggle.querySelector('[data-i18n="show_hide"]').textContent = T[CL]?.show_hide || 'Show';
            }, {once:true});
        }

        let severityChartInstance = null;
        let trendChartInstance = null;
        let lastCounts = null;
        let lastScanData = null;
        let lastScanLabels = null;

        function switchTheme(t) {
            document.documentElement.setAttribute('data-theme', t);
            localStorage.setItem('pipeline-theme', t);
            document.querySelectorAll('.theme-dot').forEach(d => {
                d.classList.remove('active');
            });
            const dot = document.querySelector(`.theme-dot[data-theme="${t}"]`);
            if (dot) dot.classList.add('active');
            initParticles();
            if (severityChartInstance) updateChartColors(severityChartInstance);
            if (trendChartInstance) updateChartColors(trendChartInstance);
        }

        function updateChartColors(chart) {
            const style = getComputedStyle(document.documentElement);
            const textSecondary = style.getPropertyValue('--text-secondary').trim();
            const option = chart.getOption();
            if (option.legend && option.legend[0]) {
                option.legend[0].textStyle = { color: textSecondary };
            }
            if (option.xAxis && option.xAxis.length > 0) {
                option.xAxis[0].axisLabel = { color: textSecondary };
            }
            if (option.yAxis && option.yAxis.length > 0) {
                option.yAxis[0].axisLabel = { color: textSecondary };
                option.yAxis[0].splitLine.lineStyle.color = style.getPropertyValue('--glass-border').trim();
            }
            chart.setOption(option);
        }

        function initParticles() {
            const c = document.getElementById('particles-canvas');
            const ctx = c.getContext('2d');
            c.width = window.innerWidth;
            c.height = window.innerHeight;
            const style = getComputedStyle(document.documentElement);
            const col = style.getPropertyValue('--particle-color').trim();
            const particles = Array.from({length: 80}, () => ({
                x: Math.random() * c.width,
                y: Math.random() * c.height,
                r: Math.random() * 2.5 + 0.5,
                dx: (Math.random() - 0.5) * 0.4,
                dy: (Math.random() - 0.5) * 0.4,
                alpha: Math.random(),
                alphaDir: 0.01
            }));
            function anim() {
                const currentTheme = document.documentElement.getAttribute('data-theme');
                const storedTheme = localStorage.getItem('pipeline-theme') || 'cyber';
                if (currentTheme !== storedTheme) return;
                ctx.clearRect(0, 0, c.width, c.height);
                particles.forEach(p => {
                    p.x += p.dx;
                    p.y += p.dy;
                    if (p.x < 0 || p.x > c.width) p.dx *= -1;
                    if (p.y < 0 || p.y > c.height) p.dy *= -1;
                    p.alpha += p.alphaDir;
                    if (p.alpha <= 0.2 || p.alpha >= 0.8) p.alphaDir *= -1;
                    ctx.beginPath();
                    ctx.arc(p.x, p.y, p.r, 0, Math.PI * 2);
                    ctx.fillStyle = col.replace(/0\.\d+/, (p.alpha).toFixed(2));
                    ctx.fill();
                });
                for (let i = 0; i < particles.length; i++) {
                    for (let j = i + 1; j < particles.length; j++) {
                        const dx = particles[i].x - particles[j].x;
                        const dy = particles[i].y - particles[j].y;
                        const d = Math.hypot(dx, dy);
                        if (d < 120) {
                            ctx.beginPath();
                            ctx.moveTo(particles[i].x, particles[i].y);
                            ctx.lineTo(particles[j].x, particles[j].y);
                            ctx.strokeStyle = col.replace(/0\.\d+/, '0.05');
                            ctx.stroke();
                        }
                    }
                }
                requestAnimationFrame(anim);
            }
            anim();
        }

        function updateClock() {
            const now = new Date();
            const options = {
                weekday: 'short', month: 'short', day: 'numeric',
                hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false
            };
            let loc = CL === 'zh' ? 'zh-CN' : CL === 'ru' ? 'ru-RU' : CL === 'ar' ? 'ar-EG' : 'en-US';
            const timeStr = now.toLocaleDateString(loc, options).replace(',', ' ·');
            document.getElementById('clock-text').textContent = timeStr;
        }
        setInterval(updateClock, 1000);

        function animateCounter(el, target) {
            const dur = 1500;
            const start = performance.now();
            function tick(now) {
                const p = Math.min((now - start) / dur, 1);
                const v = 1 - Math.pow(1 - p, 4);
                el.textContent = Math.round(v * target);
                if (p < 1) requestAnimationFrame(tick);
            }
            requestAnimationFrame(tick);
        }

        function typeWriter(el, text, speed = 15) {
            el.textContent = '';
            el.classList.add('typewriter-cursor');
            let i = 0;
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

        function showToast(message, type = 'info') {
            const container = document.getElementById('toast-container');
            const toastEl = document.createElement('div');
            toastEl.className = `toast align-items-center text-bg-${type} border-0 shadow-lg`;
            toastEl.style.borderRadius = '14px';
            toastEl.setAttribute('role', 'alert');
            toastEl.innerHTML = `
                <div class="d-flex">
                    <div class="toast-body fw-bold px-3 py-3" style="font-size:1.05rem;">
                        ${message}
                    </div>
                    <button type="button" class="btn-close btn-close-white mx-3 m-auto"
                            data-bs-dismiss="toast"></button>
                </div>`;
            container.appendChild(toastEl);
            const toast = new bootstrap.Toast(toastEl, { delay: 4000 });
            toast.show();
            toastEl.addEventListener('hidden.bs.toast', () => toastEl.remove());
        }

        let selectedReportFormat = null;

        function openReportModal() {
            document.getElementById('reportModal').classList.add('open');
        }

        function closeReportModal() {
            document.getElementById('reportModal').classList.remove('open');
            selectedReportFormat = null;
            document.querySelectorAll('.report-card-opt').forEach(c => {
                c.classList.remove('selected');
            });
            document.getElementById('modal-download-btn').disabled = true;
        }

        function selectReportFormat(fmt) {
            selectedReportFormat = fmt;
            document.querySelectorAll('.report-card-opt').forEach(c => {
                c.classList.remove('selected');
            });
            document.getElementById('opt-' + fmt).classList.add('selected');
            document.getElementById('modal-download-btn').disabled = false;
        }

        function executeModalDownload() {
            if (!selectedReportFormat) return;
            const dlBtn = document.getElementById('modal-download-btn');
            const spinner = document.getElementById('modal-download-spinner');
            dlBtn.disabled = true;
            spinner.classList.remove('d-none');
            fetch('/api/report?format=' + selectedReportFormat, { headers: getHeaders() })
                .then(resp => {
                    if (!resp.ok) throw new Error('Failed');
                    return resp.blob();
                })
                .then(blob => {
                    const url = URL.createObjectURL(blob);
                    const a = document.createElement('a');
                    a.href = url;
                    const f = selectedReportFormat;
                    const ext = f === 'json' ? 'json' : f === 'html' ? 'html' : 'pdf';
                    a.download = 'pipeline_sentinel_report.' + ext;
                    document.body.appendChild(a);
                    a.click();
                    a.remove();
                    URL.revokeObjectURL(url);
                    showToast(T[CL]?.report_success || 'Report downloaded', 'success');
                    closeReportModal();
                })
                .catch(() => showToast(T[CL]?.report_failed || 'Report failed', 'danger'))
                .finally(() => {
                    dlBtn.disabled = false;
                    spinner.classList.add('d-none');
                });
        }

        const AK = "{{ api_key }}";
        function getHeaders() {
            return (AK && AK !== 'disabled') ? {'X-API-Key': AK} : {};
        }

        let allFindings = [];
        let filteredFindings = [];
        let selectedFindings = new Set();
        let currentSeverityFilter = null;
        let currentPage = 1;
        const itemsPerPage = 5;

        function truncate(t, m) {
            return (!t) ? t : (t.length > m ? t.substring(0, m) + '...' : t);
        }

        function severityColor(s) {
            switch(s.toUpperCase()) {
                case 'CRITICAL': return 'danger';
                case 'HIGH': return 'warning text-dark';
                case 'MEDIUM': return 'info text-dark';
                case 'LOW': return 'success';
                default: return 'secondary';
            }
        }

        function renderTable() {
            const tb = document.getElementById('tableBody');
            tb.innerHTML = '';
            if (filteredFindings.length === 0) {
                const msg = T[CL]?.no_findings || 'No findings match your filters.';
                tb.innerHTML = `<tr><td colspan="6" class="text-center py-5 text-muted">${msg}</td></tr>`;
                updatePaginationInfo();
                return;
            }

            const startIndex = (currentPage - 1) * itemsPerPage;
            const endIndex = Math.min(startIndex + itemsPerPage, filteredFindings.length);
            const pageItems = filteredFindings.slice(startIndex, endIndex);

            const fragment = document.createDocumentFragment();
            pageItems.forEach(f => {
                const row = document.createElement('tr');
                row.setAttribute('data-finding-id', f.id);
                const isChecked = selectedFindings.has(f.id) ? 'checked' : '';
                const sColor = severityColor(f.severity);
                row.innerHTML = `
                    <td style="text-align:center;">
                      <input type="checkbox" class="finding-checkbox form-check-input"
                             data-id="${f.id}" ${isChecked}>
                    </td>
                    <td class="fw-bold">${f.tool}</td>
                    <td>
                        <code style="color:var(--accent); background:transparent; font-weight:700;">
                            ${f.id}
                        </code>
                    </td>
                    <td>
                        <span class="badge bg-${sColor} px-3 py-2 rounded-pill">
                            ${f.severity}
                        </span>
                    </td>
                    <td class="fw-medium">${f.target}</td>
                    <td style="color:var(--text-secondary);">${truncate(f.description, 70)}</td>`;

                const detailRow = document.createElement('tr');
                detailRow.className = 'finding-detail-row';
                detailRow.style.display = 'none';
                const idLbl = T[CL]?.id_col || 'ID';
                const sevLbl = T[CL]?.severity || 'Severity';
                const toolLbl = T[CL]?.tool || 'Tool';
                const targLbl = T[CL]?.target || 'Target';
                const lineLbl = T[CL]?.line || 'Line';
                const descLbl = T[CL]?.description || 'Description';
                const noAiMsg = T[CL]?.no_ai || 'Run with --analyze';
                const lineInfo = f.line ? `<strong style="color:var(--accent);">${lineLbl}:</strong> ${f.line}` : '';
                detailRow.innerHTML = `
                    <td colspan="6" style="padding:0; border:none; background:transparent;">
                    <div class="finding-detail mx-3 my-2">
                        <div class="row">
                          <div class="col-md-6">
                            <strong style="color:var(--accent);">${idLbl}:</strong> ${f.id}<br>
                            <strong style="color:var(--accent);">${sevLbl}:</strong> ${f.severity}<br>
                            <strong style="color:var(--accent);">${toolLbl}:</strong> ${f.tool}
                          </div>
                          <div class="col-md-6">
                            <strong style="color:var(--accent);">${targLbl}:</strong> ${f.target}<br>
                            ${lineInfo}
                          </div>
                        </div>
                        <div class="mt-3">
                          <strong style="color:var(--accent);">${descLbl}:</strong><br>
                          <span style="line-height:1.6;">${f.description || 'N/A'}</span>
                        </div>
                        <hr style="border-color:var(--glass-border); margin:15px 0;">
                        <small class="text-muted">💡 ${noAiMsg}</small>
                    </div>
                    </td>`;

                row.addEventListener('click', function(e) {
                    if (e.target.tagName === 'INPUT') return;
                    const isHidden = detailRow.style.display === 'none';
                    detailRow.style.display = isHidden ? '' : 'none';
                    if (isHidden) {
                        detailRow.querySelector('.finding-detail').classList.add('show');
                    }
                });
                fragment.appendChild(row);
                fragment.appendChild(detailRow);
            });

            requestAnimationFrame(() => {
                tb.appendChild(fragment);
                document.querySelectorAll('.finding-checkbox').forEach(cb => {
                    cb.addEventListener('change', function() {
                        if (this.checked) {
                            selectedFindings.add(this.dataset.id);
                        } else {
                            selectedFindings.delete(this.dataset.id);
                        }
                        const ssb = document.getElementById('simulate-selected-btn');
                        if (ssb) ssb.disabled = selectedFindings.size === 0;
                    });
                });
                updatePaginationInfo();
            });
        }

        function updatePaginationInfo() {
            const total = filteredFindings.length;
            const startIndex = total === 0 ? 0 : (currentPage - 1) * itemsPerPage + 1;
            const endIndex = Math.min(currentPage * itemsPerPage, total);

            const infoEl = document.getElementById('pagination-info');
            if (infoEl) {
                if (CL === 'ar') {
                    infoEl.textContent = `عرض ${startIndex}-${endIndex} من أصل ${total} إدخالات`;
                } else if (CL === 'ru') {
                    infoEl.textContent = `Показано ${startIndex}-${endIndex} из ${total} записей`;
                } else if (CL === 'zh') {
                    infoEl.textContent = `显示第 ${startIndex}-${endIndex} 条，共 ${total} 条记录`;
                } else {
                    infoEl.textContent = `Showing ${startIndex}-${endIndex} of ${total} entries`;
                }
            }
            document.getElementById('btn-prev-page').disabled = (currentPage === 1 || total === 0);
            document.getElementById('btn-next-page').disabled = (endIndex >= total);
        }

        document.getElementById('btn-prev-page').addEventListener('click', () => {
            if (currentPage > 1) {
                currentPage--;
                renderTable();
            }
        });

        document.getElementById('btn-next-page').addEventListener('click', () => {
            if (currentPage * itemsPerPage < filteredFindings.length) {
                currentPage++;
                renderTable();
            }
        });

        function applyFilters() {
            const s = document.getElementById('searchInput').value.toLowerCase();
            filteredFindings = allFindings;
            if (currentSeverityFilter) {
                filteredFindings = filteredFindings.filter(f => {
                    return f.severity.toUpperCase() === currentSeverityFilter;
                });
            }
            if (s) {
                filteredFindings = filteredFindings.filter(f =>
                    String(f.id).toLowerCase().includes(s) ||
                    (f.description && f.description.toLowerCase().includes(s))
                );
            }
            currentPage = 1;
            renderTable();
        }

        function filterBySeverity(sev) {
            currentSeverityFilter = (currentSeverityFilter === sev) ? null : sev;
            document.querySelectorAll('#stats-row .card').forEach(c => {
                c.style.borderColor = 'var(--glass-border)';
            });
            if (currentSeverityFilter) {
                let cls = 'text-secondary';
                if (sev === 'LOW') cls = 'text-success';
                if (sev === 'CRITICAL') cls = 'text-danger';
                if (sev === 'HIGH') cls = 'text-warning';
                if (sev === 'MEDIUM') cls = 'text-info';
                const activeCard = document.querySelector(`#stats-row .card:has(.stat-pill.${cls})`);
                if (activeCard) {
                    activeCard.style.borderColor = 'var(--accent)';
                }
            }
            applyFilters();
            document.getElementById('findings-section').scrollIntoView({ behavior: 'smooth', block: 'start' });
        }

        const clearBtn = document.getElementById('clear-filters-btn');
        if (clearBtn) {
            clearBtn.addEventListener('click', () => {
                currentSeverityFilter = null;
                document.getElementById('searchInput').value = '';
                document.querySelectorAll('#stats-row .card').forEach(c => {
                    c.style.borderColor = 'var(--glass-border)';
                });
                applyFilters();
            });
        }

        const searchToggle = document.getElementById('search-toggle-btn');
        const searchInputRow = document.getElementById('search-input-row');
        const searchInput = document.getElementById('searchInput');
        if (searchToggle && searchInputRow && searchInput) {
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
        }

        function createSeverityChart(counts) {
            lastCounts = counts;
            const dom = document.getElementById('severityChart');
            if (!dom) return;
            if (severityChartInstance) severityChartInstance.dispose();
            severityChartInstance = echarts.init(dom);
            const style = getComputedStyle(document.documentElement);
            const textColor = style.getPropertyValue('--text').trim();
            const bgTertiary = style.getPropertyValue('--bg-tertiary').trim();
            const total = counts.CRITICAL + counts.HIGH + counts.MEDIUM + counts.LOW;
            const tNames = [
                T[CL]?.critical || 'CRITICAL',
                T[CL]?.high || 'HIGH',
                T[CL]?.medium || 'MEDIUM',
                T[CL]?.low || 'LOW'
            ];

            const numEl = document.getElementById('chart-total-num');
            if (numEl) numEl.textContent = total;

            const option = {
                tooltip: {
                    trigger: 'item',
                    backgroundColor: bgTertiary,
                    borderColor: 'var(--glass-border)',
                    textStyle: { color: textColor },
                    padding: 12,
                    formatter: p => {
                        return `<div style="font-weight:800; border-bottom:1px solid var(--glass-border);
                                         margin-bottom:8px; padding-bottom:6px;">${p.name}</div>
                                <span style="color:${p.color}; font-size:1.5rem; vertical-align:middle;">●</span>
                                <b style="font-size:1.2rem;">${p.value}</b>
                                <span style="color:var(--text-secondary)">(${p.percent}%)</span>`;
                    }
                },
                series: [{
                    type: 'pie',
                    radius: ['55%', '85%'],
                    center: ['50%', '50%'],
                    avoidLabelOverlap: false,
                    itemStyle: {
                        borderRadius: 12,
                        borderColor: 'var(--glass)',
                        borderWidth: 3,
                        shadowBlur: 20,
                        shadowColor: 'rgba(0,0,0,0.4)'
                    },
                    label: { show: false },
                    emphasis: {
                        scaleSize: 15,
                        itemStyle: { shadowBlur: 30, shadowColor: 'rgba(0,0,0,0.6)', borderWidth: 0 }
                    },
                    data: [
                        { value: counts.CRITICAL, name: tNames[0], itemStyle: { color: '#FF4D6D' } },
                        { value: counts.HIGH, name: tNames[1], itemStyle: { color: '#FFB100' } },
                        { value: counts.MEDIUM, name: tNames[2], itemStyle: { color: '#00B4D8' } },
                        { value: counts.LOW, name: tNames[3], itemStyle: { color: '#06D6A0' } }
                    ]
                }]
            };
            severityChartInstance.setOption(option);
        }

        function createTrendChart(labels, scans) {
            lastScanLabels = labels;
            lastScanData = scans;
            const dom = document.getElementById('trendChart');
            if (!dom) return;
            if (trendChartInstance) trendChartInstance.dispose();
            trendChartInstance = echarts.init(dom);

            const style = getComputedStyle(document.documentElement);
            const textColor = style.getPropertyValue('--text').trim();
            const textSecondary = style.getPropertyValue('--text-secondary').trim();
            const glassBorder = style.getPropertyValue('--glass-border').trim();
            const bgTertiary = style.getPropertyValue('--bg-tertiary').trim();

            const tCritical = T[CL]?.critical || 'CRITICAL';
            const tHigh = T[CL]?.high || 'HIGH';
            const tMedium = T[CL]?.medium || 'MEDIUM';
            const tLow = T[CL]?.low || 'LOW';

            const option = {
                tooltip: {
                    trigger: 'axis',
                    backgroundColor: bgTertiary,
                    borderColor: glassBorder,
                    textStyle: { color: textColor },
                    padding: 12,
                    axisPointer: {
                        type: 'line',
                        lineStyle: { color: 'var(--accent)', type: 'dashed', width: 2 }
                    }
                },
                legend: {
                    data: [tCritical, tHigh, tMedium, tLow],
                    textStyle: { color: textSecondary, fontWeight: 700 },
                    top: 0,
                    icon: 'roundRect',
                    itemGap: 20
                },
                grid: { left: '2%', right: '3%', bottom: '2%', containLabel: true },
                xAxis: {
                    type: 'category',
                    boundaryGap: false,
                    data: labels,
                    axisLabel: { color: textSecondary, margin: 15, fontWeight: 600 },
                    axisLine: { lineStyle: { color: glassBorder } }
                },
                yAxis: {
                    type: 'value',
                    axisLabel: { color: textSecondary, fontWeight: 600 },
                    splitLine: { lineStyle: { color: glassBorder, type: 'dashed' } }
                },
                series: [
                    {
                        name: tCritical,
                        type: 'line',
                        data: scans.map(s => s.critical),
                        smooth: 0.5,
                        symbol: 'circle',
                        symbolSize: 8,
                        showSymbol: false,
                        lineStyle: { width: 4, shadowBlur: 15, shadowColor: 'rgba(255,77,109,0.5)' },
                        areaStyle: { color: new echarts.graphic.LinearGradient(0,0,0,1,[
                            {offset:0, color:'rgba(255,77,109,0.8)'},
                            {offset:1, color:'rgba(255,77,109,0.01)'}
                        ])},
                        itemStyle: { color: '#FF4D6D', borderColor: '#fff', borderWidth: 2 },
                        emphasis: { focus: 'series' }
                    },
                    {
                        name: tHigh,
                        type: 'line',
                        data: scans.map(s => s.high),
                        smooth: 0.5,
                        symbol: 'circle',
                        symbolSize: 8,
                        showSymbol: false,
                        lineStyle: { width: 4, shadowBlur: 15, shadowColor: 'rgba(255,177,0,0.5)' },
                        areaStyle: { color: new echarts.graphic.LinearGradient(0,0,0,1,[
                            {offset:0, color:'rgba(255,177,0,0.8)'},
                            {offset:1, color:'rgba(255,177,0,0.01)'}
                        ])},
                        itemStyle: { color: '#FFB100', borderColor: '#fff', borderWidth: 2 },
                        emphasis: { focus: 'series' }
                    },
                    {
                        name: tMedium,
                        type: 'line',
                        data: scans.map(s => s.medium),
                        smooth: 0.5,
                        symbol: 'circle',
                        symbolSize: 8,
                        showSymbol: false,
                        lineStyle: { width: 4, shadowBlur: 15, shadowColor: 'rgba(0,180,216,0.5)' },
                        areaStyle: { color: new echarts.graphic.LinearGradient(0,0,0,1,[
                            {offset:0, color:'rgba(0,180,216,0.8)'},
                            {offset:1, color:'rgba(0,180,216,0.01)'}
                        ])},
                        itemStyle: { color: '#00B4D8', borderColor: '#fff', borderWidth: 2 },
                        emphasis: { focus: 'series' }
                    },
                    {
                        name: tLow,
                        type: 'line',
                        data: scans.map(s => s.low),
                        smooth: 0.5,
                        symbol: 'circle',
                        symbolSize: 8,
                        showSymbol: false,
                        lineStyle: { width: 4, shadowBlur: 15, shadowColor: 'rgba(6,214,160,0.5)' },
                        areaStyle: { color: new echarts.graphic.LinearGradient(0,0,0,1,[
                            {offset:0, color:'rgba(6,214,160,0.8)'},
                            {offset:1, color:'rgba(6,214,160,0.01)'}
                        ])},
                        itemStyle: { color: '#06D6A0', borderColor: '#fff', borderWidth: 2 },
                        emphasis: { focus: 'series' }
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
                if (el) {
                    const val = counts[k.toUpperCase()];
                    el.setAttribute('data-target', val);
                    animateCounter(el, val);
                }
            });
            createSeverityChart(counts);
        }

        let attackSim = null;
        function drawAttackGraph(data) {
            const co = document.getElementById('attack-graph');
            if (!co) return;
            co.innerHTML = '';
            if (attackSim) attackSim.stop();
            const W = co.clientWidth;
            const H = co.clientHeight;
            const svg = d3.select('#attack-graph').append('svg').attr('width', W).attr('height', H);

            const simulation = d3.forceSimulation(data.nodes)
                .force('link', d3.forceLink(data.links).id(d => d.id).distance(120))
                .force('charge', d3.forceManyBody().strength(-400))
                .force('center', d3.forceCenter(W / 2, H / 2))
                .force('collision', d3.forceCollide().radius(20));
            attackSim = simulation;

            const link = svg.append('g').selectAll('line')
                .data(data.links).enter().append('line')
                .attr('stroke', 'var(--text-secondary)')
                .attr('stroke-opacity', 0.4)
                .attr('stroke-width', 2);

            const node = svg.append('g').selectAll('circle')
                .data(data.nodes).enter().append('circle')
                .attr('r', 12)
                .attr('fill', d => {
                    const colors = {
                        CRITICAL: '#FF4D6D',
                        HIGH: '#FFB100',
                        MEDIUM: '#00B4D8',
                        LOW: '#06D6A0'
                    };
                    return colors[d.severity] || '#6c757d';
                })
                .style('cursor', 'pointer')
                .style('filter', 'drop-shadow(0 0 8px currentColor)')
                .attr('aria-label', d => d.title)
                .on('click', (e, d) => {
                    const dt = document.getElementById('attack-detail');
                    const sColor = severityColor(d.severity);
                    const btnTxt = T[CL]?.simulate_btn || '⚡ Simulate';
                    dt.innerHTML = `
                        <div class="d-flex justify-content-between align-items-center">
                            <div>
                                <strong style="font-size:1.2rem; color:var(--accent);">${d.id}</strong><br>
                                <span class="badge bg-${sColor} mt-2 mb-2">${d.severity}</span><br>
                                <span style="color:var(--text); font-weight:600;">${d.title}</span>
                            </div>
                            <button class="btn-accent shadow-lg" onclick="simulateAttack(['${d.id}'])">
                                ${btnTxt}
                            </button>
                        </div>`;
                    dt.style.display = 'block';
                    dt.classList.add('animate-pop');
                })
                .call(d3.drag()
                    .on('start', (event, d) => {
                        if (!event.active) simulation.alphaTarget(0.3).restart();
                        d.fx = d.x; d.fy = d.y;
                    })
                    .on('drag', (event, d) => { d.fx = event.x; d.fy = event.y; })
                    .on('end', (event, d) => {
                        if (!event.active) simulation.alphaTarget(0);
                        d.fx = null; d.fy = null;
                    })
                );

            const label = svg.append('g').selectAll('text')
                .data(data.nodes).enter().append('text')
                .text(d => d.id).attr('font-size', '10px').attr('dx', 16).attr('dy', 4)
                .attr('fill', 'var(--text)').style('font-family', 'var(--mono-font)')
                .style('font-weight', '700');

            simulation.on('tick', () => {
                node.attr('cx', d => Math.max(12, Math.min(W - 12, d.x)))
                    .attr('cy', d => Math.max(12, Math.min(H - 12, d.y)));
                link.attr('x1', d => d.source.x).attr('y1', d => d.source.y)
                    .attr('x2', d => d.target.x).attr('y2', d => d.target.y);
                label.attr('x', d => Math.max(15, Math.min(W - 50, d.x)))
                     .attr('y', d => Math.max(15, Math.min(H - 20, d.y)));
            });
            window.addEventListener('resize', () => {
                if (!co.clientWidth) return;
                const newW = co.clientWidth;
                const newH = co.clientHeight;
                simulation.force('center', d3.forceCenter(newW / 2, newH / 2));
                simulation.alpha(0.3).restart();
            });
        }

        function openSimPanel() {
            document.getElementById('simOverlay').classList.add('open');
            const simTxt = T[CL]?.simulating || 'Simulating...';
            const subTxt = T[CL]?.sim_sub || 'Executing sandbox PoC environment';
            document.getElementById('sim-panel-content').innerHTML = `
                <div class="text-center py-5">
                    <div class="spinner-border"
                         style="color:var(--accent); width:3.5rem; height:3.5rem; border-width:4px;"></div>
                    <h4 class="mt-4" aria-live="polite" style="color:var(--text); font-weight:800;">
                        ${simTxt}
                    </h4>
                    <p class="text-muted mt-2 fw-bold">${subTxt}</p>
                </div>`;
        }

        function closeSimPanel() {
            document.getElementById('simOverlay').classList.remove('open');
        }

        document.getElementById('simOverlay').addEventListener('click', function(e) {
            if (e.target === this) closeSimPanel();
        });

        fetch('/api/findings', { headers: getHeaders() })
            .then(r => r.json())
            .then(data => {
                allFindings = data.data || [];
                filteredFindings = allFindings;
                currentPage = 1;
                renderTable();
                updateStats(allFindings);

                const sInput = document.getElementById('searchInput');
                if (sInput) sInput.addEventListener('input', applyFilters);

                const sa = document.getElementById('select-all');
                if (sa) sa.addEventListener('change', function() {
                    document.querySelectorAll('.finding-checkbox').forEach(cb => {
                        cb.checked = this.checked;
                        if (this.checked) {
                            selectedFindings.add(cb.dataset.id);
                        } else {
                            selectedFindings.delete(cb.dataset.id);
                        }
                    });
                    const ssb = document.getElementById('simulate-selected-btn');
                    if (ssb) ssb.disabled = selectedFindings.size === 0;
                });

                const ssb = document.getElementById('simulate-selected-btn');
                if (ssb) ssb.addEventListener('click', () => {
                    const ids = Array.from(selectedFindings);
                    if (ids.length > 0) simulateAttack(ids);
                });
            });

        fetch('/api/history', { headers: getHeaders() })
            .then(r => r.json())
            .then(sc => {
                if (sc.length) {
                    const labels = sc.map(s => s.timestamp.substring(0, 10));
                    createTrendChart(labels, sc);
                }
            });

        function renderRiskScore(score) {
            document.getElementById('risk-score-container').style.display = 'block';
            document.getElementById('risk-score-text').textContent = score + '/100';

            const bar = document.getElementById('risk-score-bar');
            setTimeout(() => { bar.style.width = score + '%'; }, 500);

            if (score > 70) {
                bar.style.background = 'var(--danger)';
                bar.style.boxShadow = '0 0 15px var(--danger)';
                document.getElementById('risk-score-text').style.color = 'var(--danger)';
            } else if (score > 40) {
                bar.style.background = 'var(--warning)';
                bar.style.boxShadow = '0 0 15px var(--warning)';
                document.getElementById('risk-score-text').style.color = 'var(--warning)';
            } else {
                bar.style.background = 'var(--success)';
                bar.style.boxShadow = '0 0 15px var(--success)';
                document.getElementById('risk-score-text').style.color = 'var(--success)';
            }
        }

        fetch('/api/summary', { headers: getHeaders() })
            .then(r => r.json())
            .then(d => {
                if (d.executive_summary) {
                    const el = document.getElementById('exec-summary');
                    if (el) typeWriter(el, d.executive_summary, 15);
                    const aiStat = document.getElementById('ai-status');
                    if (aiStat) {
                        aiStat.innerHTML = '🤖 AI Analysis Active';
                        aiStat.style.background = 'rgba(0, 229, 255, 0.15)';
                        aiStat.style.borderColor = 'var(--accent)';
                        aiStat.style.color = 'var(--accent)';
                    }
                    if (d.execution_time) {
                        document.getElementById('ai-meta-info').style.setProperty('display', 'flex', 'important');
                        document.getElementById('ai-time').textContent = d.execution_time;
                    }
                    if (d.hardware_profile) {
                        document.getElementById('ai-meta-info').style.setProperty('display', 'flex', 'important');
                        document.getElementById('ai-hardware').textContent = d.hardware_profile;
                    }
                    if (d.risk_score) renderRiskScore(d.risk_score);
                } else {
                    const aiStat = document.getElementById('ai-status');
                    const noAiMsg = T[CL]?.no_ai || 'Run with --analyze';
                    if (aiStat) aiStat.innerHTML = `🤖 <span data-i18n="no_ai">${noAiMsg}</span>`;
                }
            });

        fetch('/api/attack-paths', { headers: getHeaders() })
            .then(r => r.json())
            .then(d => {
                if (d.error) {
                    const errEl = document.getElementById('attack-error');
                    if (errEl) {
                        errEl.style.display = 'block';
                        errEl.textContent = '⚠️ ' + (T[CL]?.no_ai || 'Run with --analyze');
                    }
                } else if (d.nodes && d.nodes.length) {
                    drawAttackGraph(d);
                }
            });

        async function simulateAttack(fids) {
            openSimPanel();
            const content = document.getElementById('sim-panel-content');
            await new Promise(r => setTimeout(r, 50));
            try {
                const reqBody = JSON.stringify({ finding_ids: fids });
                const r = await fetch('/api/simulate', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json', ...getHeaders() },
                    body: reqBody
                });
                const d = await r.json();
                if (d.error) {
                    content.innerHTML = `
                        <div class="alert alert-warning border-0 shadow-sm fw-bold">
                            ${escapeHtml(d.error)}
                        </div>`;
                    return;
                }
                const soTitle = T[CL]?.sandbox_out || 'Sandbox Output:';
                const soStr = escapeHtml(d.sandbox_output);
                const so = d.sandbox_output ? `
                    <div class="mt-4">
                        <strong style="color:var(--accent); font-size:1.1rem;">${soTitle}</strong>
                        <pre class="bg-dark text-light p-3 mt-2 rounded shadow-inner"
                             style="max-height:250px; overflow-y:auto; border:1px solid #333;
                                    font-family:'SF Mono', 'Fira Code', monospace;">${soStr}</pre>
                    </div>` : '';

                const simRes = T[CL]?.sim_results || 'Simulation Results';
                const descTitle = T[CL]?.description || 'Description';

                content.innerHTML = `
                    <h4 style="color:var(--accent); font-weight:800; margin-bottom:20px;">
                        <span aria-hidden="true">⚡</span> ${simRes}
                    </h4>
                    <pre class="bg-dark text-light p-4 rounded shadow-inner"
                         style="max-height:300px; overflow-y:auto; border:1px solid #333;
                                font-family:'SF Mono', 'Fira Code', monospace; font-size:0.95rem;">
                         ${escapeHtml(d.script)}
                    </pre>
                    <p class="mt-4 p-3 rounded"
                       style="color:var(--text); font-size:1.05rem; background:var(--bg-tertiary);
                              border:1px solid var(--glass-border);">
                        <strong style="color:var(--accent);">${descTitle}:</strong> <br>
                        <span class="mt-2 d-block line-height-lg">${escapeHtml(d.description)}</span>
                    </p>
                    ${so}`;
            } catch (err) {
                const msg = T[CL]?.docker_missing || 'Docker is required for sandboxed PoC.';
                content.innerHTML = `<div class="alert alert-danger border-0 shadow-sm fw-bold">${msg}</div>`;
            }
        }

        function escapeHtml(text) {
            if (!text) return '';
            return text.replace(/&/g, '&amp;')
                       .replace(/</g, '&lt;')
                       .replace(/>/g, '&gt;')
                       .replace(/"/g, '&quot;');
        }

        document.addEventListener('keydown', function(e) {
            const sInput = document.getElementById('searchInput');
            if (e.key === '/' && document.activeElement !== sInput) {
                e.preventDefault();
                if (!searchInputRow.classList.contains('expanded')) {
                    searchInputRow.classList.add('expanded');
                }
                if (sInput) sInput.focus();
            }
            if (e.key === 'Escape') {
                if (sInput) {
                    sInput.value = '';
                    sInput.blur();
                }
                if (searchInputRow) searchInputRow.classList.remove('expanded');
                currentSeverityFilter = null;
                document.querySelectorAll('#stats-row .card').forEach(c => {
                    c.style.borderColor = 'var(--glass-border)';
                });
                applyFilters();
                closeSimPanel();
                closeReportModal();
            }
        });

        (function() {
            const savedTheme = localStorage.getItem('pipeline-theme') || 'cyber';
            switchTheme(savedTheme);
            switchLanguage(CL);
            buildCLIRef();
            initParticles();
            initTiltCards();
            updateClock();
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
    api_key_val = os.environ.get("PIPELINE_API_KEY", "disabled")
    return render_template_string(
        DASHBOARD_HTML,
        findings=findings,
        api_key=api_key_val
    )

@dashboard_bp.route('/api/findings')
@require_api_key
def api_findings():
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 50, type=int)
    return jsonify(get_findings_paginated(page, per_page))

@dashboard_bp.route('/api/history')
@require_api_key
def api_history():
    return jsonify(get_all_scans())

@dashboard_bp.route('/api/rag')
@require_api_key
def api_rag():
    q = request.args.get('q', '')
    if not q:
        return jsonify([])
    return jsonify(rag_search(q))

@dashboard_bp.route('/api/simulate', methods=['POST'])
@require_api_key
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
    return jsonify({
        "script": fs,
        "description": desc,
        "sandbox_output": so
    })

@dashboard_bp.route('/api/report')
@require_api_key
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
        data = json.dumps({
            "findings": findings,
            "ai_summary": ai_summary
        }, indent=2)
        return send_file(
            io.BytesIO(data.encode()),
            mimetype='application/json',
            as_attachment=True,
            download_name='report.json'
        )
    if fmt == 'html':
        html = '<html><head><title>Pipeline Sentinel Report</title></head><body>'
        html += '<h1>Pipeline Sentinel Security Report</h1>'
        if ai_summary.get("executive_summary"):
            html += '<h2>Executive Summary</h2>'
            html += '<p>' + ai_summary["executive_summary"] + '</p>'
        html += ('<h2>Findings</h2><table border="1"><tr>'
                 '<th>Tool</th><th>ID</th><th>Severity</th>'
                 '<th>Target</th><th>Title</th></tr>')
        for f in findings:
            html += (f'<tr><td>{f["tool"]}</td><td>{f["id"]}</td>'
                     f'<td>{f["severity"]}</td><td>{f["target"]}</td>'
                     f'<td>{f["title"]}</td></tr>')
        html += '</table></body></html>'
        import io
        return send_file(
            io.BytesIO(html.encode()),
            mimetype='text/html',
            as_attachment=True,
            download_name='report.html'
        )
    report_path = os.path.join(os.getcwd(), 'report.pdf')
    generate_pdf_report(findings, ai_summary, report_path)
    return send_file(
        report_path,
        as_attachment=True,
        download_name='pipeline_sentinel_report.pdf'
    )
