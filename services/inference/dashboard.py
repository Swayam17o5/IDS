"""
services/inference/dashboard.py
-------------------------------
Professional Real-Time SOC Intrusion Detection Dashboard HTML for AegisNIDS.
"""

DASHBOARD_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>AegisNIDS // Security Operations Center</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;600;700&family=Plus+Jakarta+Sans:wght@400;500;600;700;800&display=swap" rel="stylesheet">
  <style>
    :root {
      --bg: #07090e;
      --card-bg: rgba(15, 23, 42, 0.75);
      --card-border: rgba(51, 65, 85, 0.55);
      --accent-cyan: #00f0ff;
      --accent-blue: #3b82f6;
      --accent-purple: #a855f7;
      --accent-emerald: #10b981;
      --critical: #ef4444;
      --high: #f97316;
      --medium: #f59e0b;
      --low: #3b82f6;
      --text: #f8fafc;
      --text-muted: #94a3b8;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      background: radial-gradient(circle at 10% 10%, #0d1527 0%, #07090e 90%);
      color: var(--text);
      font-family: 'Plus Jakarta Sans', sans-serif;
      min-height: 100vh;
      display: flex;
      flex-direction: column;
    }
    header {
      padding: 14px 28px;
      display: flex;
      justify-content: space-between;
      align-items: center;
      border-bottom: 1px solid var(--card-border);
      backdrop-filter: blur(16px);
      background: rgba(7, 9, 14, 0.88);
      position: sticky;
      top: 0;
      z-index: 100;
    }
    .brand { display: flex; align-items: center; gap: 12px; }
    .brand-icon {
      width: 38px; height: 38px; border-radius: 9px;
      background: linear-gradient(135deg, var(--accent-cyan), var(--accent-blue));
      display: flex; align-items: center; justify-content: center;
      font-weight: 800; color: #000; font-size: 19px;
      box-shadow: 0 0 16px rgba(0, 240, 255, 0.35);
    }
    .brand h1 { font-size: 18px; font-weight: 800; letter-spacing: 0.5px; }
    .brand span { color: var(--accent-cyan); font-weight: 600; font-size: 12px; margin-left: 6px; }

    .header-actions { display: flex; align-items: center; gap: 12px; flex-wrap: wrap; }
    .ws-badge {
      display: inline-flex; align-items: center; gap: 6px;
      padding: 4px 10px; border-radius: 14px; font-size: 11px;
      font-family: 'JetBrains Mono', monospace; font-weight: 600;
      background: rgba(16, 185, 129, 0.1); border: 1px solid rgba(16, 185, 129, 0.3); color: #34d399;
    }
    .ws-badge.disconnected {
      background: rgba(245, 158, 11, 0.1); border-color: rgba(245, 158, 11, 0.3); color: #fbbf24;
    }
    .ws-dot { width: 6px; height: 6px; border-radius: 50%; background: #10b981; box-shadow: 0 0 6px #10b981; }
    .ws-badge.disconnected .ws-dot { background: #f59e0b; box-shadow: 0 0 6px #f59e0b; }

    .mode-indicator {
      display: flex; align-items: center; gap: 8px;
      padding: 5px 12px; border-radius: 16px; font-size: 11px; font-weight: 700;
      text-transform: uppercase; font-family: 'JetBrains Mono', monospace;
    }
    .mode-indicator.replay {
      background: rgba(168, 85, 247, 0.15); border: 1px solid rgba(168, 85, 247, 0.4); color: #c084fc;
    }
    .mode-indicator.live {
      background: rgba(239, 68, 68, 0.15); border: 1px solid rgba(239, 68, 68, 0.4); color: #f87171;
    }
    .mode-indicator.idle {
      background: rgba(148, 163, 184, 0.12); border: 1px solid rgba(148, 163, 184, 0.25); color: #cbd5e1;
    }
    .mode-dot { width: 7px; height: 7px; border-radius: 50%; }
    .mode-dot.red { background: #ef4444; box-shadow: 0 0 8px #ef4444; animation: pulse 1.5s infinite; }
    .mode-dot.purple { background: #a855f7; box-shadow: 0 0 8px #a855f7; }
    .mode-dot.gray { background: #94a3b8; }
    @keyframes pulse { 0%, 100% { opacity: 1; } 50% { opacity: 0.3; } }

    .capture-status-indicator {
      display: inline-flex; align-items: center; gap: 7px;
      padding: 5px 12px; border-radius: 20px; font-size: 11px;
      font-family: 'JetBrains Mono', monospace; font-weight: 600;
      border: 1px solid rgba(255,255,255,0.07); background: rgba(255,255,255,0.03); color: var(--text-muted);
      white-space: nowrap;
    }
    .capture-status-indicator.active {
      background: rgba(16, 185, 129, 0.08); border-color: rgba(16, 185, 129, 0.35); color: #34d399;
    }
    .capture-status-indicator.active .cap-dot {
      background: #10b981; box-shadow: 0 0 7px #10b981; animation: pulse 1.5s infinite;
    }
    .capture-status-indicator.inactive .cap-dot { background: var(--text-muted); }
    .cap-dot { width: 7px; height: 7px; border-radius: 50%; flex-shrink: 0; }

    .btn-change-network {
      background: rgba(0, 240, 255, 0.08); border: 1px solid rgba(0, 240, 255, 0.28);
      color: var(--accent-cyan); padding: 6px 14px; border-radius: 20px; font-size: 12px;
      font-weight: 700; display: inline-flex; align-items: center; gap: 7px; cursor: pointer;
      font-family: 'JetBrains Mono', monospace;
    }
    .btn-change-network:hover { background: rgba(0, 240, 255, 0.18); }

    .btn-reset {
      background: rgba(239, 68, 68, 0.12); border: 1px solid rgba(239, 68, 68, 0.35);
      color: #f87171; padding: 6px 14px; border-radius: 20px; font-size: 12px;
      font-weight: 700; display: inline-flex; align-items: center; gap: 7px; cursor: pointer;
      font-family: 'JetBrains Mono', monospace;
    }
    .btn-reset:hover { background: rgba(239, 68, 68, 0.25); color: #fff; }

    /* Navigation Bar */
    .nav-tabs {
      display: flex; gap: 6px; padding: 10px 28px;
      background: rgba(10, 16, 28, 0.95); border-bottom: 1px solid var(--card-border);
      overflow-x: auto;
    }
    .tab-btn {
      padding: 8px 16px; border-radius: 8px; font-size: 13px; font-weight: 700;
      cursor: pointer; border: 1px solid transparent; background: transparent; color: var(--text-muted);
      display: inline-flex; align-items: center; gap: 8px; transition: all 0.2s ease;
      white-space: nowrap; font-family: 'Plus Jakarta Sans', sans-serif;
    }
    .tab-btn:hover { color: #fff; background: rgba(255,255,255,0.04); }
    .tab-btn.active {
      color: var(--accent-cyan); background: rgba(0, 240, 255, 0.08);
      border-color: rgba(0, 240, 255, 0.3); box-shadow: 0 0 12px rgba(0, 240, 255, 0.15);
    }
    .tab-badge {
      font-size: 10px; padding: 1px 6px; border-radius: 10px;
      background: rgba(255,255,255,0.1); color: #fff; font-family: 'JetBrains Mono', monospace;
    }

    main { padding: 22px 28px; flex: 1; display: flex; flex-direction: column; gap: 20px; max-width: 1700px; margin: 0 auto; width: 100%; }

    .tab-content { display: none; flex-direction: column; gap: 20px; }
    .tab-content.active { display: flex; }

    /* Control Bar */
    .capture-panel, .control-panel {
      background: rgba(13, 20, 36, 0.85); border: 1px solid var(--card-border);
      border-radius: 12px; padding: 14px 18px; display: flex; flex-direction: column; gap: 10px;
      backdrop-filter: blur(16px);
    }
    .capture-top-row, .control-row { display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 10px; }
    .capture-controls, .btn-group { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; }
    .select-input, .text-input {
      background: rgba(7, 9, 14, 0.9); border: 1px solid var(--card-border);
      color: #fff; padding: 7px 12px; border-radius: 6px; font-size: 13px; outline: none;
      font-family: 'Plus Jakarta Sans', sans-serif;
    }
    .select-input:focus, .text-input:focus { border-color: var(--accent-cyan); }
    .btn {
      padding: 7px 15px; border-radius: 6px; font-weight: 700; font-size: 12px; cursor: pointer;
      border: none; display: inline-flex; align-items: center; gap: 6px; transition: all 0.2s ease;
      font-family: 'Plus Jakarta Sans', sans-serif;
    }
    .btn-live-start, .btn-emerald { background: linear-gradient(135deg, #10b981, #059669); color: #fff; }
    .btn-live-start:hover, .btn-emerald:hover { opacity: 0.9; box-shadow: 0 0 12px rgba(16, 185, 129, 0.4); }
    .btn-live-stop, .btn-rose { background: linear-gradient(135deg, #ef4444, #dc2626); color: #fff; }
    .btn-live-stop:hover, .btn-rose:hover { opacity: 0.9; box-shadow: 0 0 12px rgba(239, 68, 68, 0.4); }
    .btn-cyan { background: linear-gradient(135deg, #00f0ff, #0284c7); color: #000; font-weight: 800; }
    .btn-cyan:hover { opacity: 0.9; box-shadow: 0 0 12px rgba(0, 240, 255, 0.4); }
    .btn-purple { background: linear-gradient(135deg, #a855f7, #7c3aed); color: #fff; }
    .btn-purple:hover { opacity: 0.9; box-shadow: 0 0 12px rgba(168, 85, 247, 0.4); }
    .btn-secondary { background: rgba(255,255,255,0.06); border: 1px solid var(--card-border); color: #cbd5e1; }
    .btn-secondary:hover { background: rgba(255,255,255,0.12); color: #fff; }
    .btn:disabled { opacity: 0.4; cursor: not-allowed; }

    .driver-banner {
      background: rgba(234, 179, 8, 0.1); border: 1px solid rgba(234, 179, 8, 0.3);
      padding: 10px 14px; border-radius: 6px; font-size: 12px; color: #facc15;
      display: flex; align-items: center; justify-content: space-between; gap: 10px;
    }
    .driver-banner a { color: #00f0ff; text-decoration: underline; font-weight: 700; }

    /* Metrics Grid */
    .metrics-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(190px, 1fr)); gap: 14px; }
    .card {
      background: var(--card-bg); border: 1px solid var(--card-border);
      border-radius: 12px; padding: 16px 18px; backdrop-filter: blur(16px);
      box-shadow: 0 8px 32px rgba(0,0,0,0.3); position: relative; overflow: hidden;
    }
    .card::before {
      content: ''; position: absolute; top: 0; left: 0; width: 100%; height: 2px;
      background: linear-gradient(90deg, transparent, var(--accent-cyan), transparent);
    }
    .card-title { font-size: 11px; text-transform: uppercase; color: var(--text-muted); font-weight: 700; letter-spacing: 0.5px; }
    .card-val { font-size: 26px; font-weight: 800; margin-top: 6px; font-family: 'JetBrains Mono', monospace; }
    .card-val.crit { color: var(--critical); text-shadow: 0 0 16px rgba(239, 68, 68, 0.4); }
    .card-val.high { color: var(--high); }
    .card-val.cyan { color: var(--accent-cyan); text-shadow: 0 0 16px rgba(0, 240, 255, 0.4); }
    .card-val.emerald { color: var(--accent-emerald); }
    .card-val.purple { color: var(--accent-purple); }
    .card-sub { font-size: 11px; color: var(--text-muted); margin-top: 4px; font-family: 'JetBrains Mono', monospace; }

    /* Content Layout */
    .content-grid { display: grid; grid-template-columns: 2fr 1fr; gap: 18px; }
    @media (max-width: 1150px) { .content-grid { grid-template-columns: 1fr; } }

    /* Table Styles */
    .table-container { overflow-x: auto; max-height: 440px; }
    table { width: 100%; border-collapse: collapse; text-align: left; font-size: 13px; }
    th { padding: 11px 12px; color: var(--text-muted); font-weight: 600; border-bottom: 1px solid var(--card-border); background: rgba(0,0,0,0.25); font-size: 12px; position: sticky; top: 0; z-index: 10; backdrop-filter: blur(8px); }
    td { padding: 9px 12px; border-bottom: 1px solid rgba(255,255,255,0.04); font-family: 'JetBrains Mono', monospace; font-size: 12px; }
    tr:hover { background: rgba(255,255,255,0.025); }

    .badge {
      display: inline-block; padding: 2px 7px; border-radius: 5px; font-size: 10px; font-weight: 700; text-transform: uppercase;
    }
    .badge.CRITICAL { background: rgba(239, 68, 68, 0.15); color: #f87171; border: 1px solid rgba(239, 68, 68, 0.4); }
    .badge.HIGH { background: rgba(249, 115, 22, 0.15); color: #fb923c; border: 1px solid rgba(249, 115, 22, 0.4); }
    .badge.MEDIUM { background: rgba(245, 158, 11, 0.15); color: #facc15; border: 1px solid rgba(245, 158, 11, 0.4); }
    .badge.LOW { background: rgba(59, 130, 246, 0.15); color: #60a5fa; border: 1px solid rgba(59, 130, 246, 0.4); }
    .badge.BENIGN, .badge.Benign { background: rgba(16, 185, 129, 0.15); color: #34d399; border: 1px solid rgba(16, 185, 129, 0.4); }
    .badge.ATTACK, .badge.Attack { background: rgba(239, 68, 68, 0.15); color: #f87171; border: 1px solid rgba(239, 68, 68, 0.4); }
    .badge.proto { background: rgba(99, 102, 241, 0.15); color: #818cf8; border: 1px solid rgba(99, 102, 241, 0.3); font-size: 10px; }

    /* Triage buttons */
    .triage-actions { display: flex; gap: 4px; align-items: center; }
    .triage-btn {
      padding: 3px 6px; border-radius: 4px; font-size: 10px; font-weight: 700; cursor: pointer;
      border: 1px solid; transition: all 0.15s ease; font-family: 'JetBrains Mono', monospace; text-transform: uppercase;
    }
    .triage-btn.ack { background: rgba(59, 130, 246, 0.12); border-color: rgba(59, 130, 246, 0.4); color: #60a5fa; }
    .triage-btn.ack:hover { background: rgba(59, 130, 246, 0.25); }
    .triage-btn.fp { background: rgba(245, 158, 11, 0.12); border-color: rgba(245, 158, 11, 0.4); color: #facc15; }
    .triage-btn.fp:hover { background: rgba(245, 158, 11, 0.25); }
    .triage-btn.esc { background: rgba(168, 85, 247, 0.12); border-color: rgba(168, 85, 247, 0.4); color: #c084fc; }
    .triage-btn.esc:hover { background: rgba(168, 85, 247, 0.25); }
    .triage-btn.res { background: rgba(16, 185, 129, 0.12); border-color: rgba(16, 185, 129, 0.4); color: #34d399; }
    .triage-btn.res:hover { background: rgba(16, 185, 129, 0.25); }
    .triage-btn.inspect { background: rgba(0, 240, 255, 0.12); border-color: rgba(0, 240, 255, 0.4); color: var(--accent-cyan); }
    .triage-btn.inspect:hover { background: rgba(0, 240, 255, 0.25); }

    /* Status Badges */
    .badge.NEW { background: rgba(59, 130, 246, 0.15); color: #60a5fa; border: 1px solid rgba(59, 130, 246, 0.4); }
    .badge.ACKNOWLEDGED { background: rgba(99, 102, 241, 0.15); color: #818cf8; border: 1px solid rgba(99, 102, 241, 0.4); }
    .badge.INVESTIGATING { background: rgba(168, 85, 247, 0.15); color: #c084fc; border: 1px solid rgba(168, 85, 247, 0.4); }
    .badge.FALSE_POSITIVE { background: rgba(245, 158, 11, 0.15); color: #facc15; border: 1px solid rgba(245, 158, 11, 0.4); }
    .badge.ESCALATED { background: rgba(239, 68, 68, 0.15); color: #f87171; border: 1px solid rgba(239, 68, 68, 0.4); }
    .badge.RESOLVED { background: rgba(16, 185, 129, 0.15); color: #34d399; border: 1px solid rgba(16, 185, 129, 0.4); }

    /* Timeline Cards */
    .timeline-container { display: flex; flex-direction: column; gap: 12px; max-height: 600px; overflow-y: auto; padding-right: 4px; }
    .timeline-card {
      background: rgba(255,255,255,0.025); border: 1px solid var(--card-border);
      border-left: 4px solid var(--accent-cyan); border-radius: 8px; padding: 14px 16px;
      display: flex; justify-content: space-between; align-items: center; gap: 12px;
      transition: all 0.2s ease;
    }
    .timeline-card.CRITICAL { border-left-color: var(--critical); }
    .timeline-card.HIGH { border-left-color: var(--high); }
    .timeline-card.MEDIUM { border-left-color: var(--medium); }
    .timeline-card:hover { background: rgba(255,255,255,0.05); transform: translateX(2px); }
    .timeline-info { display: flex; flex-direction: column; gap: 4px; }
    .timeline-meta { font-size: 11px; color: var(--text-muted); font-family: 'JetBrains Mono', monospace; display: flex; gap: 12px; }

    /* Explanation Box */
    .explanation-box {
      background: rgba(0, 240, 255, 0.04); border: 1px solid rgba(0, 240, 255, 0.15);
      border-radius: 8px; padding: 12px 16px; margin-bottom: 14px;
      font-size: 13px; color: #e2e8f0; line-height: 1.6;
    }
    .explanation-box .label { font-size: 10px; text-transform: uppercase; font-weight: 700; color: var(--accent-cyan); letter-spacing: 0.5px; margin-bottom: 6px; }

    /* SHAP Waterfall / Bars */
    .shap-bar-item { margin-bottom: 10px; }
    .shap-bar-label { display: flex; justify-content: space-between; font-size: 12px; margin-bottom: 3px; font-family: 'JetBrains Mono', monospace; }
    .shap-bar-track { width: 100%; height: 7px; background: rgba(255,255,255,0.06); border-radius: 4px; overflow: hidden; }
    .shap-bar-fill { height: 100%; background: linear-gradient(90deg, var(--accent-cyan), var(--accent-blue)); border-radius: 4px; }
    .shap-bar-fill.pos { background: linear-gradient(90deg, #f59e0b, #ef4444); }
    .shap-bar-fill.neg { background: linear-gradient(90deg, #10b981, #06b6d4); }

    /* Terminal Window for Demo */
    .terminal-box {
      background: #04070e; border: 1px solid rgba(0, 240, 255, 0.2);
      border-radius: 8px; padding: 14px; font-family: 'JetBrains Mono', monospace;
      font-size: 12px; color: #38bdf8; max-height: 280px; overflow-y: auto;
      line-height: 1.5;
    }

    /* Modal Backdrop & Dialog */
    .modal-backdrop {
      position: fixed; top: 0; left: 0; width: 100vw; height: 100vh;
      background: rgba(4, 7, 14, 0.85); backdrop-filter: blur(10px);
      z-index: 1000; display: none; align-items: center; justify-content: center;
      animation: fadeIn 0.15s ease-out;
    }
    .modal-dialog {
      background: #0d1424; border: 1px solid var(--card-border);
      box-shadow: 0 25px 60px rgba(0,0,0,0.8), 0 0 30px rgba(0, 240, 255, 0.1);
      border-radius: 12px; width: 90%; max-width: 580px; padding: 22px;
      animation: scaleIn 0.18s ease-out; max-height: 90vh; overflow-y: auto;
    }
    .modal-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 14px; }
    .modal-close-btn { background: none; border: none; color: var(--text-muted); font-size: 18px; cursor: pointer; }
    .modal-close-btn:hover { color: #fff; }
    .modal-footer { display: flex; justify-content: flex-end; gap: 10px; margin-top: 18px; }
    .btn-modal-cancel { background: rgba(255,255,255,0.06); border: 1px solid var(--card-border); color: #cbd5e1; }
    .btn-modal-cancel:hover { background: rgba(255,255,255,0.12); color: #fff; }
    .btn-modal-confirm { background: linear-gradient(135deg, #ef4444, #dc2626); color: #fff; }
    .btn-modal-confirm:hover { opacity: 0.95; box-shadow: 0 0 16px rgba(239, 68, 68, 0.5); }
    @keyframes fadeIn { from { opacity: 0; } to { opacity: 1; } }
    @keyframes scaleIn { from { opacity: 0; transform: scale(0.96); } to { opacity: 1; transform: scale(1); } }

    /* Form Styles */
    .form-group, .fp-form-group { margin-bottom: 12px; }
    .form-group label, .fp-form-group label { display: block; font-size: 11px; font-weight: 700; color: var(--text-muted); margin-bottom: 5px; text-transform: uppercase; letter-spacing: 0.5px; }
    .form-group select, .form-group textarea, .form-group input,
    .fp-form-group select, .fp-form-group textarea, .fp-form-group input {
      width: 100%; background: rgba(7, 9, 14, 0.9); border: 1px solid var(--card-border);
      color: #fff; padding: 8px 12px; border-radius: 6px; font-size: 13px; outline: none;
      font-family: 'Plus Jakarta Sans', sans-serif;
    }
    .form-group textarea, .fp-form-group textarea { resize: vertical; min-height: 60px; }
    .btn-fp-submit { background: linear-gradient(135deg, #f59e0b, #d97706); color: #000; font-weight: 700; }

    /* Toast */
    .toast {
      position: fixed; bottom: 20px; right: 20px;
      background: #0f172a; border: 1px solid var(--accent-cyan);
      box-shadow: 0 10px 30px rgba(0,0,0,0.5), 0 0 20px rgba(0, 240, 255, 0.25);
      color: #fff; padding: 10px 18px; border-radius: 8px; font-size: 13px; font-weight: 600;
      z-index: 2000; display: flex; align-items: center; gap: 8px;
    }

    .lab-badge {
      background: rgba(245, 158, 11, 0.12); border: 1px solid rgba(245, 158, 11, 0.4);
      color: #fbbf24; padding: 8px 14px; border-radius: 6px; font-size: 12px; font-weight: 700;
      display: flex; align-items: center; gap: 8px;
    }
  </style>
</head>
<body>
  <header>
    <div class="brand">
      <div class="brand-icon">🛡️</div>
      <h1>AegisNIDS <span>// Real-Time SOC Intelligence</span></h1>
    </div>
    <div class="header-actions">
      <div id="ws-status-badge" class="ws-badge">
        <span class="ws-dot"></span>
        <span id="ws-status-text">WS CONNECTED</span>
      </div>
      <div id="mode-indicator" class="mode-indicator idle">
        <span class="mode-dot gray" id="mode-dot"></span>
        <span id="mode-label">IDLE</span>
      </div>
      <div class="capture-status-indicator inactive" id="header-cap-indicator">
        <span class="cap-dot"></span>
        <span id="header-cap-label">Capture: IDLE</span>
      </div>
      <button class="btn-change-network" onclick="openNetworkModal()">
        <span>⇄</span> Change Network
      </button>
      <button class="btn-reset" onclick="openResetModal()">
        <span>↺</span> Reset Data
      </button>
    </div>
  </header>

  <nav class="nav-tabs">
    <button class="tab-btn active" onclick="switchTab('tab-live', this)">🛡️ Live Feed & Telemetry</button>
    <button class="tab-btn" onclick="switchTab('tab-timeline', this)">⏱️ Attack Timeline <span class="tab-badge" id="badge-timeline-count">0</span></button>
    <button class="tab-btn" onclick="switchTab('tab-attackers', this)">🎯 Top Attacking IPs</button>
    <button class="tab-btn" onclick="switchTab('tab-incidents', this)">📋 Incident Management <span class="tab-badge" id="badge-incident-count">0</span></button>
    <button class="tab-btn" onclick="switchTab('tab-explain', this)">🧠 Explainability (SHAP)</button>
    <button class="tab-btn" onclick="switchTab('tab-replay', this)">📼 Offline PCAP Replay</button>
    <button class="tab-btn" onclick="switchTab('tab-demo', this)">⚡ Authorized Nmap Lab Demo</button>
  </nav>

  <main>
    <!-- TAB 1: LIVE FEED & TELEMETRY -->
    <div id="tab-live" class="tab-content active">
      <div class="capture-panel">
        <div class="capture-top-row">
          <div class="capture-controls">
            <span style="font-size: 12px; color: var(--text-muted); font-weight: 700;">INTERFACE:</span>
            <select id="iface-select" class="select-input"></select>
            <button id="btn-start-cap" class="btn btn-live-start" onclick="startCapture()">▶ Start Capture</button>
            <button id="btn-stop-cap" class="btn btn-live-stop" onclick="stopCapture()" disabled>⏹ Stop</button>
          </div>
          <div style="font-size: 12px; color: var(--text-muted); font-family: 'JetBrains Mono', monospace;">
            Active IP: <span id="cap-active-ip" style="color: var(--accent-cyan); font-weight: 700;">127.0.0.1</span> | Packets: <span id="cap-packet-count" style="color: #fff;">0</span>
          </div>
        </div>
        <div id="driver-warning" class="driver-banner" style="display: none;">
          <span id="driver-warning-msg">Npcap packet driver is not installed.</span>
          <a href="https://npcap.com/#download" target="_blank">Download Npcap</a>
        </div>
      </div>

      <div class="metrics-grid">
        <div class="card">
          <div class="card-title">Total Flows</div>
          <div class="card-val cyan" id="stat-total-flows">0</div>
          <div class="card-sub"><span id="rate-flows">0</span> flows/min</div>
        </div>
        <div class="card">
          <div class="card-title">Total Predictions</div>
          <div class="card-val" id="stat-total-preds">0</div>
          <div class="card-sub"><span id="rate-preds">0</span> preds/min</div>
        </div>
        <div class="card">
          <div class="card-title">Triggered Alerts</div>
          <div class="card-val crit" id="stat-total-alerts">0</div>
          <div class="card-sub"><span id="rate-alerts">0</span> alerts/min</div>
        </div>
        <div class="card">
          <div class="card-title">PortScan Detections</div>
          <div class="card-val" style="color: #facc15;" id="count-portscan">0</div>
          <div class="card-sub">SYN Heuristic & ML</div>
        </div>
        <div class="card">
          <div class="card-title">Live Detection Rate</div>
          <div class="card-val emerald" id="stat-detection-rate">0.0%</div>
          <div class="card-sub">Attack vs Benign</div>
        </div>
        <div class="card">
          <div class="card-title" id="stat-precision-label">Analyst-Verified Precision</div>
          <div class="card-val purple" id="stat-precision">—</div>
          <div class="card-sub"><span id="stat-total-triaged">0</span> triaged alerts</div>
        </div>
      </div>

      <!-- 1. LIVE NETWORK FLOW STREAM (Top of Security Alerts) -->
      <div class="card" style="margin-bottom: 4px;">
        <div class="card-title" style="margin-bottom: 12px; display: flex; justify-content: space-between; align-items: center;">
          <div style="display: flex; align-items: center; gap: 8px;">
            <span style="font-size: 14px;">🌐</span>
            <span style="font-size: 13px; font-weight: 800; color: #fff; letter-spacing: 0.5px;">Live Network Flow Stream</span>
            <span class="badge proto" style="font-size: 10px;">77 CICIDS2017 Features Extracted</span>
          </div>
          <span style="font-size: 11px; font-weight: 400; color: var(--text-muted); font-family: 'JetBrains Mono', monospace;">Auto-Refreshing Wire Ingestion</span>
        </div>
        <div class="table-container" style="max-height: 280px;">
          <table>
            <thead>
              <tr>
                <th>Flow #</th>
                <th>Time</th>
                <th>Proto</th>
                <th>Source</th>
                <th>Destination</th>
                <th>Classification</th>
                <th>Confidence</th>
                <th>Model</th>
              </tr>
            </thead>
            <tbody id="flows-body">
              <tr><td colspan="8" style="text-align: center; color: var(--text-muted);">No network flows captured yet.</td></tr>
            </tbody>
          </table>
        </div>
      </div>

      <!-- 2. REAL-TIME SECURITY ALERTS & AI EXPLANATION GRID -->
      <div class="content-grid">
        <div class="card">
          <div class="card-title" style="margin-bottom: 12px; display: flex; justify-content: space-between; align-items: center;">
            <div style="display: flex; align-items: center; gap: 8px;">
              <span style="font-size: 14px;">🚨</span>
              <span style="font-size: 13px; font-weight: 800; color: #fff; letter-spacing: 0.5px;">Real-Time Security Alert Feed</span>
            </div>
            <span style="font-size: 11px; font-weight: 400; color: var(--text-muted);">Auto-Deduplicated (120s Window)</span>
          </div>
          <div class="table-container">
            <table>
              <thead>
                <tr>
                  <th>Alert ID</th>
                  <th>Severity</th>
                  <th>Attack Type</th>
                  <th>Confidence</th>
                  <th>Source</th>
                  <th>Destination</th>
                  <th>Status</th>
                  <th>Triage</th>
                  <th>Explainability</th>
                </tr>
              </thead>
              <tbody id="alerts-body">
                <tr><td colspan="9" style="text-align: center; color: var(--text-muted);">No alerts recorded. Network clean.</td></tr>
              </tbody>
            </table>
          </div>
        </div>

        <div style="display: flex; flex-direction: column; gap: 16px;">
          <div class="card" id="explanation-container">
            <div class="card-title" style="margin-bottom: 10px;">🧠 AI Explanation & Feature Salience</div>
            <div id="latest-explanation-box" class="explanation-box" style="display: none;">
              <div class="label">AI Alert Analysis</div>
              <div id="latest-explanation-text"></div>
            </div>
            <div id="shap-container">
              <div style="font-size: 12px; color: var(--text-muted); font-style: italic; text-align: center; padding: 16px;">
                Feature importance will render here upon attack detection.
              </div>
            </div>
          </div>

          <div class="card">
            <div class="card-title" style="margin-bottom: 10px;">⚙️ Active Detection Model</div>
            <div id="models-container" class="models-grid" style="grid-template-columns: 1fr;"></div>
            <div style="margin-top: 10px; font-size: 10px; color: var(--text-muted); display: flex; gap: 8px;">
              <span>• NSL-KDD (Not yet implemented)</span>
              <span>• UNSW-NB15 (Not yet implemented)</span>
            </div>
          </div>
        </div>
      </div>
    </div>

    <!-- TAB 2: ATTACK TIMELINE -->
    <div id="tab-timeline" class="tab-content">
      <div class="control-panel">
        <div class="control-row">
          <div class="btn-group">
            <span style="font-size: 12px; color: var(--text-muted); font-weight: 700;">RANGE:</span>
            <select id="timeline-range" class="select-input" onchange="fetchTimeline()">
              <option value="all">All Recorded History</option>
              <option value="last_5m">Last 5 Minutes</option>
              <option value="last_15m">Last 15 Minutes</option>
              <option value="last_1h">Last 1 Hour</option>
              <option value="last_24h">Last 24 Hours</option>
            </select>
            <select id="timeline-sev" class="select-input" onchange="fetchTimeline()">
              <option value="">All Severities</option>
              <option value="CRITICAL">Critical</option>
              <option value="HIGH">High</option>
              <option value="MEDIUM">Medium</option>
            </select>
            <input type="text" id="timeline-search-ip" class="text-input" placeholder="Filter IP..." oninput="fetchTimeline()">
          </div>
          <button class="btn btn-secondary" onclick="fetchTimeline()">🔄 Refresh Timeline</button>
        </div>
      </div>

      <div class="card">
        <div class="card-title" style="margin-bottom: 14px;">⏱️ Chronological Security Events</div>
        <div id="timeline-list" class="timeline-container">
          <div style="text-align: center; color: var(--text-muted); padding: 30px;">Loading attack timeline...</div>
        </div>
      </div>
    </div>

    <!-- TAB 3: TOP ATTACKING IPS -->
    <div id="tab-attackers" class="tab-content">
      <div class="control-panel">
        <div class="control-row">
          <div class="btn-group">
            <span style="font-size: 12px; color: var(--text-muted); font-weight: 700;">RANGE:</span>
            <select id="attackers-range" class="select-input" onchange="fetchTopAttackers()">
              <option value="all">All Database Records</option>
              <option value="last_1h">Last 1 Hour</option>
              <option value="last_24h">Last 24 Hours</option>
            </select>
          </div>
          <button class="btn btn-secondary" onclick="fetchTopAttackers()">🔄 Refresh Rankings</button>
        </div>
      </div>

      <div class="card">
        <div class="card-title" style="margin-bottom: 14px;">🎯 Threat Intelligence & Attacker Rankings</div>
        <div class="table-container">
          <table>
            <thead>
              <tr>
                <th>Attacker Source IP</th>
                <th>Alerts Count</th>
                <th>Affected Targets</th>
                <th>Attack Types</th>
                <th>Primary Attack</th>
                <th>Peak Severity</th>
                <th>Max Confidence</th>
                <th>First Seen</th>
                <th>Last Seen</th>
              </tr>
            </thead>
            <tbody id="attackers-body">
              <tr><td colspan="9" style="text-align: center; color: var(--text-muted);">No attacker data recorded.</td></tr>
            </tbody>
          </table>
        </div>
      </div>
    </div>

    <!-- TAB 4: INCIDENT MANAGEMENT -->
    <div id="tab-incidents" class="tab-content">
      <div class="control-panel">
        <div class="control-row">
          <div class="btn-group">
            <span style="font-size: 12px; color: var(--text-muted); font-weight: 700;">FILTER STATUS:</span>
            <select id="inc-filter-status" class="select-input" onchange="fetchIncidents()">
              <option value="">All Statuses</option>
              <option value="NEW">New</option>
              <option value="ACKNOWLEDGED">Acknowledged</option>
              <option value="INVESTIGATING">Investigating</option>
              <option value="RESOLVED">Resolved</option>
              <option value="FALSE_POSITIVE">False Positive</option>
            </select>
          </div>
          <div class="btn-group">
            <button class="btn btn-cyan" onclick="openNewIncidentModal()">+ Create Incident</button>
            <button class="btn btn-secondary" onclick="fetchIncidents()">🔄 Refresh</button>
          </div>
        </div>
      </div>

      <div class="card">
        <div class="card-title" style="margin-bottom: 14px;">📋 Incident Tickets</div>
        <div class="table-container">
          <table>
            <thead>
              <tr>
                <th>Incident ID</th>
                <th>Title</th>
                <th>Severity</th>
                <th>Attack Type</th>
                <th>Source IP</th>
                <th>Linked Alerts</th>
                <th>Status</th>
                <th>Created</th>
                <th>Action</th>
              </tr>
            </thead>
            <tbody id="incidents-body">
              <tr><td colspan="9" style="text-align: center; color: var(--text-muted);">No incidents recorded.</td></tr>
            </tbody>
          </table>
        </div>
      </div>
    </div>

    <!-- TAB 5: SHAP EXPLAINABILITY EXPLORER -->
    <div id="tab-explain" class="tab-content">
      <div class="card">
        <div class="card-title" style="margin-bottom: 12px;">🧠 Model Decision Transparency (TreeExplainer)</div>
        <div id="explain-detail-target" style="padding: 16px; background: rgba(0,0,0,0.3); border-radius: 8px; border: 1px solid var(--card-border);">
          Select an alert from the Live Alert Feed or Attack Timeline to inspect its feature contributions.
        </div>
      </div>
    </div>

    <!-- TAB 6: OFFLINE PCAP REPLAY -->
    <div id="tab-replay" class="tab-content">
      <div class="control-panel">
        <div class="control-row">
          <div class="btn-group" style="flex: 1; flex-wrap: wrap;">
            <input type="text" id="replay-file-path" class="text-input" style="flex: 1; min-width: 260px;" placeholder="Path to PCAP file...">
            <button id="btn-replay-start" class="btn btn-purple" onclick="startReplay()">▶ Start Offline Replay</button>
            <button id="btn-replay-stop" class="btn btn-rose" onclick="stopReplay()" disabled>⏹ Stop</button>
          </div>
          <button class="btn btn-cyan" onclick="generateSyntheticPCAP()">✨ Generate Synthetic Attack PCAP</button>
        </div>
      </div>

      <div class="metrics-grid">
        <div class="card">
          <div class="card-title">Replay Pipeline</div>
          <div class="card-val purple" id="replay-status-text">OFFLINE</div>
          <div class="card-sub">Zero raw network injection</div>
        </div>
        <div class="card">
          <div class="card-title">Packets Processed</div>
          <div class="card-val" id="replay-packets">0</div>
          <div class="card-sub">Scapy PcapReader</div>
        </div>
        <div class="card">
          <div class="card-title">Flows Extracted</div>
          <div class="card-val" id="replay-flows">0</div>
          <div class="card-sub">77 CICIDS2017 features</div>
        </div>
        <div class="card">
          <div class="card-title">Alerts Generated</div>
          <div class="card-val crit" id="replay-alerts">0</div>
          <div class="card-sub">Persisted to nids.db</div>
        </div>
      </div>

      <div class="card">
        <div class="card-title" style="margin-bottom: 12px;">📼 PCAP Replay Execution History</div>
        <div class="table-container">
          <table>
            <thead>
              <tr>
                <th>Replay ID</th>
                <th>Filename</th>
                <th>Status</th>
                <th>Packets</th>
                <th>Flows</th>
                <th>Alerts</th>
                <th>Duration</th>
                <th>Started</th>
              </tr>
            </thead>
            <tbody id="replay-history-body">
              <tr><td colspan="8" style="text-align: center; color: var(--text-muted);">No replay history recorded.</td></tr>
            </tbody>
          </table>
        </div>
      </div>
    </div>

    <!-- TAB 7: AUTHORIZED NMAP DEMO -->
    <div id="tab-demo" class="tab-content">
      <div class="lab-badge">
        ⚠️ AUTHORIZED DEMONSTRATION / LAB MODE ONLY — Restricted strictly to loopback (127.0.0.1) and RFC1918 private subnets.
      </div>

      <div class="control-panel">
        <div class="control-row">
          <div class="btn-group" style="flex: 1; flex-wrap: wrap;">
            <div style="display: flex; flex-direction: column; gap: 4px;">
              <span style="font-size: 11px; color: var(--text-muted); font-weight: 700;">TARGET IP:</span>
              <input type="text" id="demo-target-ip" class="text-input" value="127.0.0.1" style="width: 150px;" oninput="validateDemoTargetUI()">
            </div>
            <div style="display: flex; flex-direction: column; gap: 4px;">
              <span style="font-size: 11px; color: var(--text-muted); font-weight: 700;">PORTS:</span>
              <input type="text" id="demo-ports" class="text-input" value="21,22,80,443,3306,8080" style="width: 210px;">
            </div>
            <div style="display: flex; flex-direction: column; gap: 4px;">
              <span style="font-size: 11px; color: var(--text-muted); font-weight: 700;">SCAN TYPE:</span>
              <select id="demo-scan-type" class="select-input">
                <option value="syn">TCP SYN Scan (-sS)</option>
                <option value="connect">TCP Connect Scan (-sT)</option>
              </select>
            </div>
            <div style="display: flex; align-items: flex-end;">
              <button id="btn-start-demo" class="btn btn-emerald" onclick="startNmapDemo()">⚡ Run Controlled PortScan</button>
            </div>
          </div>
          <div id="demo-validation-msg" style="font-size: 12px; color: #34d399; font-weight: 600;">Authorized Localhost Target</div>
        </div>
      </div>

      <div class="content-grid">
        <div class="card">
          <div class="card-title" style="margin-bottom: 10px;">💻 Live Execution Terminal</div>
          <div id="demo-terminal" class="terminal-box">Ready to execute authorized PortScan test.</div>
        </div>
        <div class="card">
          <div class="card-title" style="margin-bottom: 12px;">📊 Real Pipeline Verification Results</div>
          <div style="display: flex; flex-direction: column; gap: 10px; font-size: 13px;">
            <div style="display: flex; justify-content: space-between; padding: 8px 10px; background: rgba(255,255,255,0.03); border-radius: 6px;">
              <span style="color: var(--text-muted);">Flows Generated:</span>
              <span id="demo-res-flows" style="font-weight: 700; color: #fff;">0</span>
            </div>
            <div style="display: flex; justify-content: space-between; padding: 8px 10px; background: rgba(255,255,255,0.03); border-radius: 6px;">
              <span style="color: var(--text-muted);">Predictions:</span>
              <span id="demo-res-preds" style="font-weight: 700; color: #fff;">0</span>
            </div>
            <div style="display: flex; justify-content: space-between; padding: 8px 10px; background: rgba(255,255,255,0.03); border-radius: 6px;">
              <span style="color: var(--text-muted);">PortScan Detections:</span>
              <span id="demo-res-portscan" style="font-weight: 700; color: #facc15;">0</span>
            </div>
            <div style="display: flex; justify-content: space-between; padding: 8px 10px; background: rgba(255,255,255,0.03); border-radius: 6px;">
              <span style="color: var(--text-muted);">Alerts Persisted:</span>
              <span id="demo-res-alerts" style="font-weight: 700; color: var(--critical);">0</span>
            </div>
          </div>
        </div>
      </div>
    </div>
  </main>

  <!-- MODALS -->

  <!-- False Positive Modal -->
  <div id="fp-modal" class="modal-backdrop">
    <div class="modal-dialog fp-modal-dialog">
      <div class="modal-header">
        <h3 style="font-size: 16px; color: #facc15;">⚠️ False Positive Correction</h3>
        <button class="modal-close-btn" onclick="closeFPModal()">✕</button>
      </div>
      <div style="font-size: 12px; color: var(--text-muted); margin-bottom: 14px;">
        Alert ID: <span id="fp-alert-id-display" style="color: #fff; font-family: 'JetBrains Mono', monospace; font-weight: 700;"></span>
      </div>
      <div class="fp-form-group">
        <label>Original Detected Label</label>
        <input type="text" id="fp-original-label" readonly style="opacity: 0.7; width: 100%; background: rgba(7,9,14,0.9); border: 1px solid var(--card-border); color: #fff; padding: 8px 12px; border-radius: 6px;">
      </div>
      <div class="fp-form-group">
        <label>Corrected True Label</label>
        <select id="fp-corrected-label">
          <option value="Benign" selected>Benign</option>
          <option value="PortScan">PortScan</option>
          <option value="DDoS">DDoS</option>
          <option value="DoS Hulk">DoS Hulk</option>
          <option value="Web Attack - XSS">Web Attack - XSS</option>
        </select>
      </div>
      <div class="fp-form-group">
        <label>Analyst Notes</label>
        <textarea id="fp-notes" placeholder="Explain why this flow was benign..."></textarea>
      </div>
      <div class="modal-footer">
        <button class="btn btn-secondary" onclick="closeFPModal()">Cancel</button>
        <button id="btn-fp-submit" class="btn btn-fp-submit" onclick="submitFalsePositive()">Confirm False Positive & Log Feedback</button>
      </div>
    </div>
  </div>

  <!-- New Incident Modal -->
  <div id="new-incident-modal" class="modal-backdrop">
    <div class="modal-dialog">
      <div class="modal-header">
        <h3 style="font-size: 16px; color: var(--accent-cyan);">📋 Create Incident Ticket</h3>
        <button class="modal-close-btn" onclick="closeNewIncidentModal()">✕</button>
      </div>
      <div class="form-group">
        <label>Incident Title</label>
        <input type="text" id="inc-new-title" placeholder="e.g. Sequential PortScan on Gateway">
      </div>
      <div class="form-group">
        <label>Attack Type</label>
        <input type="text" id="inc-new-attack" value="PortScan">
      </div>
      <div class="form-group">
        <label>Severity</label>
        <select id="inc-new-sev">
          <option value="CRITICAL">Critical</option>
          <option value="HIGH">High</option>
          <option value="MEDIUM" selected>Medium</option>
          <option value="LOW">Low</option>
        </select>
      </div>
      <div class="form-group">
        <label>Attacker IP</label>
        <input type="text" id="inc-new-src-ip" placeholder="e.g. 192.168.1.40">
      </div>
      <div class="form-group">
        <label>Assigned Analyst</label>
        <input type="text" id="inc-new-analyst" value="SOC Lead">
      </div>
      <div class="form-group">
        <label>Analyst Notes</label>
        <textarea id="inc-new-notes" placeholder="Initial incident findings..."></textarea>
      </div>
      <div class="modal-footer">
        <button class="btn btn-secondary" onclick="closeNewIncidentModal()">Cancel</button>
        <button class="btn btn-cyan" onclick="submitNewIncident()">Create Ticket</button>
      </div>
    </div>
  </div>

  <!-- Incident Detail Modal -->
  <div id="incident-detail-modal" class="modal-backdrop">
    <div class="modal-dialog" style="max-width: 660px;">
      <div class="modal-header">
        <h3 style="font-size: 16px; color: var(--accent-cyan);" id="inc-view-title">Incident Details</h3>
        <button class="modal-close-btn" onclick="closeIncidentDetailModal()">✕</button>
      </div>
      <div style="display: flex; gap: 8px; margin-bottom: 12px; align-items: center;">
        <span class="badge" id="inc-view-status"></span>
        <span class="badge" id="inc-view-sev"></span>
        <span style="font-size: 11px; color: var(--text-muted); font-family: 'JetBrains Mono', monospace;" id="inc-view-id"></span>
      </div>
      <div class="form-group">
        <label>Update Status</label>
        <select id="inc-update-status" onchange="updateIncidentStatus()">
          <option value="NEW">NEW</option>
          <option value="ACKNOWLEDGED">ACKNOWLEDGED</option>
          <option value="INVESTIGATING">INVESTIGATING</option>
          <option value="RESOLVED">RESOLVED</option>
          <option value="FALSE_POSITIVE">FALSE_POSITIVE</option>
        </select>
      </div>
      <div class="form-group">
        <label>Add Investigation Note</label>
        <div style="display: flex; gap: 8px;">
          <input type="text" id="inc-add-note-text" placeholder="Add notes..." style="flex: 1;">
          <button class="btn btn-cyan" onclick="submitIncidentNote()">Post</button>
        </div>
      </div>
      <div style="margin-top: 12px;">
        <label style="font-size: 11px; font-weight: 700; color: var(--text-muted); text-transform: uppercase;">Analyst Notes</label>
        <div id="inc-notes-timeline" style="margin-top: 6px; display: flex; flex-direction: column; gap: 6px; max-height: 160px; overflow-y: auto;"></div>
      </div>
      <div style="margin-top: 12px;">
        <label style="font-size: 11px; font-weight: 700; color: var(--text-muted); text-transform: uppercase;">Linked Alerts</label>
        <div id="inc-linked-alerts" style="margin-top: 6px; display: flex; flex-direction: column; gap: 6px; max-height: 120px; overflow-y: auto;"></div>
      </div>
      <div class="modal-footer">
        <button class="btn btn-secondary" onclick="closeIncidentDetailModal()">Close</button>
      </div>
    </div>
  </div>

  <!-- Alert Detail Modal -->
  <div id="alert-detail-modal" class="modal-backdrop">
    <div class="modal-dialog" style="max-width: 620px;">
      <div class="modal-header">
        <h3 style="font-size: 16px; color: var(--accent-cyan);">🔍 Alert Detail & AI Explanation</h3>
        <button class="modal-close-btn" onclick="closeAlertDetailModal()">✕</button>
      </div>
      <div id="modal-alert-details" style="font-size: 13px; margin-bottom: 12px;"></div>
      <div id="modal-shap-container"></div>
      <div class="modal-footer">
        <button class="btn btn-secondary" onclick="closeAlertDetailModal()">Close</button>
        <button class="btn btn-cyan" onclick="convertAlertToIncident()">+ Create Incident Ticket</button>
      </div>
    </div>
  </div>

  <!-- Network Switch Modal -->
  <div id="network-modal" class="modal-backdrop">
    <div class="modal-dialog">
      <div class="modal-header">
        <h3 style="font-size: 16px; color: var(--accent-cyan);">⚙️ Select Capture Network Interface</h3>
        <button class="modal-close-btn" onclick="closeNetworkModal()">✕</button>
      </div>
      <div class="form-group">
        <label>Available Network Adapters</label>
        <select id="modal-iface-select" size="6" style="min-height: 140px;"></select>
      </div>
      <div class="modal-footer">
        <button class="btn btn-secondary" onclick="closeNetworkModal()">Cancel</button>
        <button class="btn btn-cyan" onclick="submitNetworkSwitch()">Bind Interface</button>
      </div>
    </div>
  </div>

  <!-- Reset Confirmation Modal -->
  <div id="reset-modal" class="modal-backdrop">
    <div class="modal-dialog">
      <div class="modal-header">
        <h3 style="font-size: 16px; color: #f87171;">⚠️ Confirm Database Reset</h3>
        <button class="modal-close-btn" onclick="closeResetModal()">✕</button>
      </div>
      <div class="modal-body">
        This will clear flows, predictions, alerts, and incidents from the SOC database. Model configurations will remain intact.
      </div>
      <div class="modal-footer">
        <button class="btn btn-modal-cancel" onclick="closeResetModal()">Cancel</button>
        <button class="btn btn-modal-confirm" onclick="submitResetSOC()">Confirm Reset</button>
      </div>
    </div>
  </div>

  <script>
    let ws = null;
    let currentFPAlertId = null;
    let currentInspectAlert = null;
    let currentInspectIncidentId = null;
    let activeTabId = 'tab-live';

    function switchTab(tabId, btn) {
      activeTabId = tabId;
      document.querySelectorAll('.tab-content').forEach(el => el.classList.remove('active'));
      document.querySelectorAll('.tab-btn').forEach(el => el.classList.remove('active'));
      const target = document.getElementById(tabId);
      if (target) target.classList.add('active');
      if (btn) btn.classList.add('active');

      if (tabId === 'tab-timeline') fetchTimeline();
      if (tabId === 'tab-attackers') fetchTopAttackers();
      if (tabId === 'tab-incidents') fetchIncidents();
      if (tabId === 'tab-replay') fetchReplayHistory();
    }

    function initWebSocket() {
      const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
      const wsUrl = `${protocol}//${window.location.host}/ws/live`;
      try {
        ws = new WebSocket(wsUrl);
        ws.onopen = () => {
          document.getElementById('ws-status-badge').classList.remove('disconnected');
          document.getElementById('ws-status-text').innerText = 'WS CONNECTED';
        };
        ws.onmessage = (event) => {
          try {
            const msg = JSON.parse(event.data);
            if (msg.type === 'alert') {
              showToast(`🚨 ${msg.data.severity} Alert: ${msg.data.attack_type}`);
              fetchAlerts();
              fetchStats();
              if (activeTabId === 'tab-timeline') fetchTimeline();
              if (activeTabId === 'tab-attackers') fetchTopAttackers();
            } else if (msg.type === 'flow') {
              fetchFlows();
            }
          } catch (e) {}
        };
        ws.onclose = () => {
          document.getElementById('ws-status-badge').classList.add('disconnected');
          document.getElementById('ws-status-text').innerText = 'POLLING FALLBACK';
          setTimeout(initWebSocket, 4000);
        };
        ws.onerror = () => {
          document.getElementById('ws-status-badge').classList.add('disconnected');
          document.getElementById('ws-status-text').innerText = 'POLLING FALLBACK';
        };
      } catch (err) {
        document.getElementById('ws-status-badge').classList.add('disconnected');
        document.getElementById('ws-status-text').innerText = 'POLLING FALLBACK';
      }
    }

    function showToast(text) {
      const toast = document.createElement('div');
      toast.className = 'toast';
      toast.innerHTML = `<span>⚡</span><span>${text}</span>`;
      document.body.appendChild(toast);
      setTimeout(() => { toast.remove(); }, 3500);
    }

    async function fetchStats() {
      try {
        const res = await fetch('/api/stats');
        if (!res.ok) return;
        const data = await res.json();

        document.getElementById('stat-total-flows').innerText = (data.total_flows || 0).toLocaleString();
        document.getElementById('stat-total-preds').innerText = (data.total_predictions || 0).toLocaleString();
        document.getElementById('stat-total-alerts').innerText = (data.total_alerts || 0).toLocaleString();
        document.getElementById('count-portscan').innerText = (data.portscan_count || 0).toLocaleString();
        document.getElementById('stat-detection-rate').innerText = `${data.detection_rate || 0}%`;

        document.getElementById('rate-flows').innerText = data.flows_per_minute || 0;
        document.getElementById('rate-preds').innerText = data.predictions_per_minute || 0;
        document.getElementById('rate-alerts').innerText = data.alerts_per_minute || 0;

        const prec = data.analyst_precision;
        document.getElementById('stat-precision').innerText = (prec !== null && prec !== undefined) ? `${prec}%` : '—';
        document.getElementById('stat-total-triaged').innerText = data.total_triaged || 0;

        document.getElementById('badge-incident-count').innerText = data.active_incidents || 0;

        const modeLabel = document.getElementById('mode-label');
        const modeDot = document.getElementById('mode-dot');
        const modeInd = document.getElementById('mode-indicator');
        if (data.mode === 'LIVE_CAPTURE') {
          modeLabel.innerText = 'LIVE CAPTURE';
          modeDot.className = 'mode-dot red';
          modeInd.className = 'mode-indicator live';
        } else if (data.mode === 'PCAP_REPLAY') {
          modeLabel.innerText = 'PCAP REPLAY';
          modeDot.className = 'mode-dot purple';
          modeInd.className = 'mode-indicator replay';
        } else {
          modeLabel.innerText = 'IDLE';
          modeDot.className = 'mode-dot gray';
          modeInd.className = 'mode-indicator idle';
        }

        const isCap = data.capture_status && data.capture_status.is_capturing;
        document.getElementById('btn-start-cap').disabled = isCap;
        document.getElementById('btn-stop-cap').disabled = !isCap;
        const capInd = document.getElementById('header-cap-indicator');
        const capLbl = document.getElementById('header-cap-label');
        if (isCap) {
          capInd.className = 'capture-status-indicator active';
          capLbl.innerText = `Capture: ACTIVE (${data.capture_status.active_interface || 'Live'})`;
        } else {
          capInd.className = 'capture-status-indicator inactive';
          capLbl.innerText = 'Capture: IDLE';
        }

        if (data.capture_status) {
          document.getElementById('cap-active-ip').innerText = data.capture_status.active_ip || '127.0.0.1';
          document.getElementById('cap-packet-count').innerText = data.capture_status.packet_count || 0;
        }

        if (data.latest_explanation) {
          document.getElementById('latest-explanation-box').style.display = 'block';
          document.getElementById('latest-explanation-text').innerText = data.latest_explanation;
        }

        if (data.latest_shap && data.latest_shap.length > 0) {
          renderShapBars(data.latest_shap, 'shap-container');
        }
      } catch (e) {}
    }

    function renderShapBars(features, containerId) {
      const container = document.getElementById(containerId);
      if (!container || !features || features.length === 0) return;
      const maxImp = Math.max(...features.map(s => s.importance || Math.abs(s.shap_value || 0)), 0.0001);
      let html = '';
      features.forEach(s => {
        const imp = s.importance !== undefined ? s.importance : Math.abs(s.shap_value || 0);
        const pct = Math.min(100, Math.round((imp / maxImp) * 100));
        const isPos = (s.contribution === 'positive' || (s.shap_value && s.shap_value >= 0));
        const fillClass = isPos ? 'pos' : 'neg';
        const sign = isPos ? '+' : '-';
        html += `
          <div class="shap-bar-item">
            <div class="shap-bar-label">
              <span>${s.feature} <span style="font-size: 10px; color: var(--text-muted);">(${s.value !== undefined ? s.value : ''})</span></span>
              <span style="color: ${isPos ? '#f87171' : '#34d399'};">${sign}${imp.toFixed(4)}</span>
            </div>
            <div class="shap-bar-track">
              <div class="shap-bar-fill ${fillClass}" style="width: ${pct}%;"></div>
            </div>
          </div>
        `;
      });
      container.innerHTML = html;
    }

    async function fetchFlows() {
      try {
        const res = await fetch('/api/flows?limit=30');
        if (!res.ok) return;
        const flows = await res.json();
        const tbody = document.getElementById('flows-body');
        if (!flows || flows.length === 0) {
          tbody.innerHTML = '<tr><td colspan="8" style="text-align: center; color: var(--text-muted);">No network flows captured yet.</td></tr>';
          return;
        }
        let html = '';
        const protoMap = { 6: 'TCP', 17: 'UDP', 1: 'ICMP', 2: 'IGMP' };
        flows.forEach(f => {
          const isBenign = (!f.predicted_label || f.predicted_label.toLowerCase() === 'benign');
          const badgeClass = isBenign ? 'BENIGN' : 'ATTACK';
          const protoName = protoMap[f.protocol] || `Proto ${f.protocol}`;
          const timeStr = f.timestamp ? f.timestamp.split('T')[1].split('.')[0] : '--:--:--';
          html += `
            <tr>
              <td>#${f.id}</td>
              <td style="color: var(--text-muted);">${timeStr}</td>
              <td><span class="badge proto">${protoName}</span></td>
              <td>${f.src_ip}:${f.src_port || 0}</td>
              <td>${f.dst_ip}:${f.dst_port || 0}</td>
              <td><span class="badge ${badgeClass}">${f.predicted_label}</span></td>
              <td>${(f.confidence * 100).toFixed(1)}%</td>
              <td style="color: var(--text-muted); font-size: 11px;">${f.model_name || 'weighted_voting_ensemble'}</td>
            </tr>
          `;
        });
        tbody.innerHTML = html;
      } catch (e) {}
    }

    async function fetchAlerts() {
      try {
        const res = await fetch('/api/alerts?limit=25');
        if (!res.ok) return;
        const alerts = await res.json();
        const tbody = document.getElementById('alerts-body');
        if (!alerts || alerts.length === 0) {
          tbody.innerHTML = '<tr><td colspan="8" style="text-align: center; color: var(--text-muted);">No alerts recorded. Network clean.</td></tr>';
          return;
        }
        let html = '';
        alerts.forEach(a => {
          const st = a.status || 'NEW';
          const isTerminal = (st === 'RESOLVED' || st === 'FALSE_POSITIVE');
          let triageHtml = '';
          if (isTerminal) {
            triageHtml = `<span style="font-size: 11px; color: var(--text-muted);">—</span>`;
          } else {
            triageHtml = `<div class="triage-actions">`;
            if (st !== 'ACKNOWLEDGED') triageHtml += `<button class="triage-btn ack" onclick="triageAlert('${a.alert_id}','ACKNOWLEDGED')">ACK</button>`;
            triageHtml += `<button class="triage-btn fp" onclick="openFPModal('${a.alert_id}','${a.attack_type}')">FP</button>`;
            if (st !== 'ESCALATED') triageHtml += `<button class="triage-btn esc" onclick="triageAlert('${a.alert_id}','ESCALATED')">ESC</button>`;
            triageHtml += `<button class="triage-btn res" onclick="triageAlert('${a.alert_id}','RESOLVED')">RES</button>`;
            triageHtml += `</div>`;
          }
          let methodTag = '';
          if (a.detection_method === 'SYN_BURST_HEURISTIC') {
            methodTag = `<span style="font-size: 10px; padding: 2px 5px; border-radius: 4px; background: rgba(0, 240, 255, 0.15); color: var(--accent-cyan); margin-left: 4px;">SYN Heuristic</span>`;
          }
          html += `
            <tr>
              <td><span style="font-weight: 700; color: #fff;">${a.alert_id}</span></td>
              <td><span class="badge ${a.severity}">${a.severity}</span></td>
              <td>
                <div style="display: flex; align-items: center; gap: 4px;">
                  <span style="font-weight: 700; color: #fff;">${a.attack_type}</span>
                  ${methodTag}
                </div>
              </td>
              <td><div style="font-weight: 700; color: var(--accent-cyan);">${(a.confidence * 100).toFixed(1)}%</div></td>
              <td>${a.src_ip}</td>
              <td>${a.dst_ip}:${a.dst_port || 0}</td>
              <td><span class="badge ${st}">${st}</span></td>
              <td>${triageHtml}</td>
              <td>
                <a href="/explainability/${a.alert_id}" class="btn btn-secondary" style="font-size: 11px; padding: 4px 8px; text-decoration: none; display: inline-flex; align-items: center; gap: 4px; border-color: rgba(0,240,255,0.4); color: var(--accent-cyan); white-space: nowrap;">
                  🔍 Deep Explain
                </a>
              </td>
            </tr>
          `;
        });
        tbody.innerHTML = html;
      } catch (e) {}
    }

    async function triageAlert(alertId, newStatus) {
      try {
        const res = await fetch(`/api/alerts/${alertId}/status`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ status: newStatus })
        });
        if (res.ok) {
          showToast(`Alert ${alertId} → ${newStatus}`);
          fetchAlerts();
          fetchStats();
        }
      } catch (e) {}
    }

    async function fetchTimeline() {
      try {
        const range = document.getElementById('timeline-range').value;
        const sev = document.getElementById('timeline-sev').value;
        const ip = document.getElementById('timeline-search-ip').value.trim();
        let url = `/api/timeline?time_range=${range}`;
        if (sev) url += `&severity=${sev}`;
        if (ip) url += `&src_ip=${encodeURIComponent(ip)}`;

        const res = await fetch(url);
        if (!res.ok) return;
        const data = await res.json();
        document.getElementById('badge-timeline-count').innerText = data.total_events || 0;

        const container = document.getElementById('timeline-list');
        if (!data.events || data.events.length === 0) {
          container.innerHTML = '<div style="text-align: center; color: var(--text-muted); padding: 30px;">No attack events recorded for this filter.</div>';
          return;
        }

        let html = '';
        data.events.forEach(ev => {
          const timeStr = ev.timestamp ? ev.timestamp.replace('T', ' ').split('.')[0] : '--';
          html += `
            <div class="timeline-card ${ev.severity}">
              <div class="timeline-info">
                <div style="display: flex; align-items: center; gap: 8px;">
                  <span class="badge ${ev.severity}">${ev.severity}</span>
                  <span style="font-weight: 800; font-size: 14px; color: #fff;">${ev.attack_type}</span>
                  <span style="color: var(--accent-cyan); font-weight: 700; font-family: 'JetBrains Mono', monospace;">${(ev.confidence * 100).toFixed(1)}%</span>
                  <span style="font-size: 11px; padding: 2px 6px; border-radius: 4px; background: rgba(255,255,255,0.06);">${ev.detection_method}</span>
                </div>
                <div class="timeline-meta">
                  <span>🕒 ${timeStr}</span>
                  <span>📍 ${ev.src_ip} → ${ev.dst_ip}:${ev.dst_port || 0}</span>
                  <span>🔢 Flows: ${ev.flow_count || 1}</span>
                  <span>🆔 ${ev.alert_id}</span>
                </div>
                ${ev.explanation ? `<div style="font-size: 11px; color: #cbd5e1; margin-top: 4px;">${ev.explanation}</div>` : ''}
              </div>
              <div style="display: flex; flex-direction: column; gap: 6px;">
                <button class="btn btn-secondary" style="font-size: 11px;" onclick="inspectAlert('${ev.alert_id}')">Inspect</button>
                <a href="/explainability/${ev.alert_id}" class="btn btn-secondary" style="font-size: 11px; text-decoration: none; color: var(--accent-cyan); border-color: rgba(0,240,255,0.4); text-align: center;">🔍 Deep Explain</a>
              </div>
            </div>
          `;
        });
        container.innerHTML = html;
      } catch (e) {}
    }

    async function fetchTopAttackers() {
      try {
        const range = document.getElementById('attackers-range').value;
        const res = await fetch(`/api/analytics/top-attackers?time_range=${range}`);
        if (!res.ok) return;
        const data = await res.json();
        const tbody = document.getElementById('attackers-body');
        if (!data.attackers || data.attackers.length === 0) {
          tbody.innerHTML = '<tr><td colspan="9" style="text-align: center; color: var(--text-muted);">No attacker data recorded.</td></tr>';
          return;
        }
        let html = '';
        data.attackers.forEach(atk => {
          const firstSeen = atk.first_seen ? atk.first_seen.replace('T', ' ').split('.')[0] : '--';
          const lastSeen = atk.last_seen ? atk.last_seen.replace('T', ' ').split('.')[0] : '--';
          html += `
            <tr>
              <td><span style="font-weight: 700; color: var(--accent-cyan);">${atk.src_ip}</span></td>
              <td><span style="font-weight: 800; color: #fff;">${atk.alerts}</span></td>
              <td>${atk.affected_destinations}</td>
              <td>${atk.attack_types.join(', ')}</td>
              <td><span class="badge" style="background: rgba(255,255,255,0.08); color: #fff;">${atk.most_common_attack}</span></td>
              <td><span class="badge ${atk.highest_severity}">${atk.highest_severity}</span></td>
              <td>${(atk.max_confidence * 100).toFixed(1)}%</td>
              <td style="font-size: 11px; color: var(--text-muted);">${firstSeen}</td>
              <td style="font-size: 11px; color: var(--text-muted);">${lastSeen}</td>
            </tr>
          `;
        });
        tbody.innerHTML = html;
      } catch (e) {}
    }

    async function fetchIncidents() {
      try {
        const st = document.getElementById('inc-filter-status').value;
        let url = `/api/incidents`;
        if (st) url += `?status=${st}`;
        const res = await fetch(url);
        if (!res.ok) return;
        const incs = await res.json();
        const tbody = document.getElementById('incidents-body');
        if (!incs || incs.length === 0) {
          tbody.innerHTML = '<tr><td colspan="9" style="text-align: center; color: var(--text-muted);">No incident tickets recorded.</td></tr>';
          return;
        }
        let html = '';
        incs.forEach(inc => {
          const createdStr = inc.created_at ? inc.created_at.replace('T', ' ').split('.')[0] : '--';
          html += `
            <tr>
              <td><span style="font-weight: 700; color: #fff;">${inc.incident_id}</span></td>
              <td>${inc.title}</td>
              <td><span class="badge ${inc.severity}">${inc.severity}</span></td>
              <td>${inc.attack_type}</td>
              <td>${inc.src_ip || '—'}</td>
              <td><span class="badge" style="background: rgba(0, 240, 255, 0.1); color: var(--accent-cyan);">${inc.alert_count}</span></td>
              <td><span class="badge ${inc.status}">${inc.status}</span></td>
              <td style="font-size: 11px; color: var(--text-muted);">${createdStr}</td>
              <td><button class="btn btn-secondary" style="font-size: 11px;" onclick="viewIncidentDetail('${inc.incident_id}')">Manage</button></td>
            </tr>
          `;
        });
        tbody.innerHTML = html;
      } catch (e) {}
    }

    function openNewIncidentModal(defaultSrcIp, defaultAttack) {
      if (defaultSrcIp) document.getElementById('inc-new-src-ip').value = defaultSrcIp;
      if (defaultAttack) document.getElementById('inc-new-attack').value = defaultAttack;
      document.getElementById('new-incident-modal').style.display = 'flex';
    }

    function closeNewIncidentModal() {
      document.getElementById('new-incident-modal').style.display = 'none';
    }

    async function submitNewIncident() {
      const payload = {
        title: document.getElementById('inc-new-title').value.trim(),
        attack_type: document.getElementById('inc-new-attack').value.trim(),
        severity: document.getElementById('inc-new-sev').value,
        src_ip: document.getElementById('inc-new-src-ip').value.trim(),
        assigned_analyst: document.getElementById('inc-new-analyst').value.trim(),
        notes: document.getElementById('inc-new-notes').value.trim()
      };
      const res = await fetch('/api/incidents', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      });
      if (res.ok) {
        closeNewIncidentModal();
        showToast("Incident ticket created successfully");
        fetchIncidents();
        fetchStats();
      }
    }

    async function viewIncidentDetail(incidentId) {
      currentInspectIncidentId = incidentId;
      const res = await fetch(`/api/incidents/${incidentId}`);
      if (!res.ok) return;
      const inc = await res.json();

      document.getElementById('inc-view-title').innerText = inc.title;
      document.getElementById('inc-view-id').innerText = inc.incident_id;
      const stEl = document.getElementById('inc-view-status');
      stEl.innerText = inc.status;
      stEl.className = `badge ${inc.status}`;
      const sevEl = document.getElementById('inc-view-sev');
      sevEl.innerText = inc.severity;
      sevEl.className = `badge ${inc.severity}`;

      document.getElementById('inc-update-status').value = inc.status;

      const notesContainer = document.getElementById('inc-notes-timeline');
      if (!inc.notes || inc.notes.length === 0) {
        notesContainer.innerHTML = '<div style="font-size: 11px; color: var(--text-muted);">No notes recorded.</div>';
      } else {
        let nHtml = '';
        inc.notes.forEach(n => {
          const t = n.created_at ? n.created_at.replace('T', ' ').split('.')[0] : '--';
          nHtml += `<div style="padding: 6px 10px; background: rgba(255,255,255,0.03); border-radius: 6px; font-size: 12px;"><span style="color: var(--accent-cyan); font-weight: 700;">${n.author}</span> <span style="font-size: 10px; color: var(--text-muted);">(${t}):</span> ${n.note}</div>`;
        });
        notesContainer.innerHTML = nHtml;
      }

      const alertsContainer = document.getElementById('inc-linked-alerts');
      if (!inc.alerts || inc.alerts.length === 0) {
        alertsContainer.innerHTML = '<div style="font-size: 11px; color: var(--text-muted);">No alerts linked directly.</div>';
      } else {
        let aHtml = '';
        inc.alerts.forEach(a => {
          aHtml += `<div style="padding: 6px 10px; background: rgba(255,255,255,0.03); border-radius: 6px; font-size: 12px; display: flex; justify-content: space-between;"><span>${a.alert_id} - ${a.attack_type} (${a.src_ip})</span><span class="badge ${a.severity}">${a.severity}</span></div>`;
        });
        alertsContainer.innerHTML = aHtml;
      }

      document.getElementById('incident-detail-modal').style.display = 'flex';
    }

    function closeIncidentDetailModal() {
      document.getElementById('incident-detail-modal').style.display = 'none';
      currentInspectIncidentId = null;
    }

    async function updateIncidentStatus() {
      if (!currentInspectIncidentId) return;
      const newStatus = document.getElementById('inc-update-status').value;
      const res = await fetch(`/api/incidents/${currentInspectIncidentId}`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ status: newStatus })
      });
      if (res.ok) {
        showToast(`Incident status updated to ${newStatus}`);
        viewIncidentDetail(currentInspectIncidentId);
        fetchIncidents();
        fetchStats();
      }
    }

    async function submitIncidentNote() {
      if (!currentInspectIncidentId) return;
      const noteInput = document.getElementById('inc-add-note-text');
      const noteText = noteInput.value.trim();
      if (!noteText) return;
      const res = await fetch(`/api/incidents/${currentInspectIncidentId}/notes`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ note: noteText, author: "SOC Analyst" })
      });
      if (res.ok) {
        noteInput.value = '';
        showToast("Note added to incident");
        viewIncidentDetail(currentInspectIncidentId);
      }
    }

    async function inspectAlert(alertId) {
      try {
        const res = await fetch(`/api/alerts/${alertId}/explanation`);
        if (!res.ok) return;
        const data = await res.json();
        currentInspectAlert = data;

        let detHtml = `
          <div style="display: flex; gap: 8px; align-items: center; margin-bottom: 8px;">
            <span class="badge ${data.severity}">${data.severity}</span>
            <span style="font-weight: 800; font-size: 15px; color: #fff;">${data.attack_type}</span>
            <span style="color: var(--accent-cyan); font-weight: 700;">${(data.confidence * 100).toFixed(1)}%</span>
            <span style="font-size: 11px; color: var(--text-muted);">Model: ${data.model_used || 'Active'}</span>
          </div>
          ${data.explanation ? `<div class="explanation-box"><div class="label">🧠 AI Detection Rationale</div><div>${data.explanation}</div></div>` : ''}
          <div style="margin-top: 10px; margin-bottom: 12px;">
            <a href="/explainability/${data.alert_id}" class="btn btn-cyan" style="text-decoration: none; display: inline-flex; align-items: center; gap: 6px; font-size: 12px; padding: 6px 12px;">
              🔍 Open Deep AI Explainability Page
            </a>
          </div>
        `;
        document.getElementById('modal-alert-details').innerHTML = detHtml;
        renderShapBars(data.features, 'modal-shap-container');
        document.getElementById('alert-detail-modal').style.display = 'flex';

        document.getElementById('explain-detail-target').innerHTML = `
          <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px;">
            <div style="font-weight: 700; color: #fff; font-size: 15px;">Inspecting Alert: ${data.alert_id} (${data.attack_type})</div>
            <a href="/explainability/${data.alert_id}" class="btn btn-cyan" style="text-decoration: none; font-size: 12px;">🔍 Open Dedicated Explainability Page</a>
          </div>
          ${data.explanation ? `<div class="explanation-box" style="margin-bottom: 12px;"><div class="label">AI Rationale</div><div>${data.explanation}</div></div>` : ''}
          <div id="tab-shap-bars"></div>
        `;
        renderShapBars(data.features, 'tab-shap-bars');
      } catch (e) {}
    }

    function closeAlertDetailModal() {
      document.getElementById('alert-detail-modal').style.display = 'none';
    }

    function convertAlertToIncident() {
      if (!currentInspectAlert) return;
      closeAlertDetailModal();
      openNewIncidentModal(currentInspectAlert.src_ip || '', currentInspectAlert.attack_type || '');
    }

    async function generateSyntheticPCAP() {
      showToast("Generating synthetic security incident PCAP...");
      try {
        const res = await fetch('/api/replay/generate_synthetic', { method: 'POST' });
        if (res.ok) {
          const data = await res.json();
          document.getElementById('replay-file-path').value = data.pcap_path;
          showToast("Generated demo_attack_scenario.pcap in scratch/");
        }
      } catch (e) {}
    }

    async function startReplay() {
      const pcapPath = document.getElementById('replay-file-path').value.trim();
      if (!pcapPath) {
        showToast("Please specify a valid PCAP file path");
        return;
      }
      const res = await fetch('/api/replay/start', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ pcap_path: pcapPath })
      });
      if (res.ok) {
        showToast("Offline PCAP replay started");
        pollReplayStatus();
      } else {
        const err = await res.json();
        showToast(`Replay error: ${err.detail || 'Failed'}`);
      }
    }

    async function stopReplay() {
      const res = await fetch('/api/replay/stop', { method: 'POST' });
      if (res.ok) {
        showToast("PCAP replay stopped");
        fetchStats();
        fetchReplayHistory();
      }
    }

    async function pollReplayStatus() {
      try {
        const res = await fetch('/api/replay/status');
        if (!res.ok) return;
        const data = await res.json();
        document.getElementById('replay-status-text').innerText = data.status;
        document.getElementById('replay-packets').innerText = data.packets_processed || 0;
        document.getElementById('replay-flows').innerText = data.flows_generated || 0;
        document.getElementById('replay-alerts').innerText = data.alerts_generated || 0;

        document.getElementById('btn-replay-start').disabled = data.is_replaying;
        document.getElementById('btn-replay-stop').disabled = !data.is_replaying;

        if (data.is_replaying) {
          setTimeout(pollReplayStatus, 1000);
        } else {
          fetchReplayHistory();
        }
      } catch (e) {}
    }

    async function fetchReplayHistory() {
      try {
        const res = await fetch('/api/replay/history');
        if (!res.ok) return;
        const history = await res.json();
        const tbody = document.getElementById('replay-history-body');
        if (!history || history.length === 0) {
          tbody.innerHTML = '<tr><td colspan="8" style="text-align: center; color: var(--text-muted);">No replay history recorded.</td></tr>';
          return;
        }
        let html = '';
        history.forEach(h => {
          const t = h.started_at ? h.started_at.replace('T', ' ').split('.')[0] : '--';
          html += `
            <tr>
              <td><span style="font-weight: 700; color: #fff;">${h.replay_id}</span></td>
              <td>${h.filename}</td>
              <td><span class="badge ${h.status === 'COMPLETED' ? 'RESOLVED' : 'HIGH'}">${h.status}</span></td>
              <td>${h.packets_processed}</td>
              <td>${h.flows_generated}</td>
              <td>${h.alerts_generated}</td>
              <td>${h.duration_seconds}s</td>
              <td style="font-size: 11px; color: var(--text-muted);">${t}</td>
            </tr>
          `;
        });
        tbody.innerHTML = html;
      } catch (e) {}
    }

    function validateDemoTargetUI() {
      const target = document.getElementById('demo-target-ip').value.trim().toLowerCase();
      const msgEl = document.getElementById('demo-validation-msg');
      if (target === '127.0.0.1' || target === 'localhost') {
        msgEl.innerText = '✓ Authorized Localhost Target';
        msgEl.style.color = '#34d399';
      } else if (target.startsWith('192.168.') || target.startsWith('10.') || target.startsWith('172.16.')) {
        msgEl.innerText = '✓ Authorized RFC1918 Lab Subnet';
        msgEl.style.color = '#34d399';
      } else {
        msgEl.innerText = '✗ Target must be 127.0.0.1 or Private RFC1918 Lab IP';
        msgEl.style.color = '#ef4444';
      }
    }

    async function startNmapDemo() {
      const target = document.getElementById('demo-target-ip').value.trim();
      const ports = document.getElementById('demo-ports').value.trim();
      const scanType = document.getElementById('demo-scan-type').value;

      const terminal = document.getElementById('demo-terminal');
      terminal.innerText = `>>> Launching Authorized Nmap Lab Demo on ${target} (${scanType.toUpperCase()} scan)...\\n`;

      const btn = document.getElementById('btn-start-demo');
      btn.disabled = true;
      btn.innerText = 'Scanning...';

      try {
        const res = await fetch('/api/demo/nmap/start', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ target: target, ports: ports, scan_type: scanType })
        });
        if (res.ok) {
          showToast("Authorized PortScan demo started");
          pollDemoStatus();
        } else {
          const err = await res.json();
          terminal.innerText += `\\n[ERROR] ${err.detail || 'Scan request rejected.'}\\n`;
          btn.disabled = false;
          btn.innerText = '⚡ Run Controlled PortScan';
        }
      } catch (e) {
        btn.disabled = false;
        btn.innerText = '⚡ Run Controlled PortScan';
      }
    }

    async function pollDemoStatus() {
      try {
        const res = await fetch('/api/demo/nmap/status');
        if (!res.ok) return;
        const data = await res.json();
        const terminal = document.getElementById('demo-terminal');

        if (data.logs && data.logs.length > 0) {
          terminal.innerText = data.logs.join('\\n');
          terminal.scrollTop = terminal.scrollHeight;
        }

        if (data.verification) {
          document.getElementById('demo-res-flows').innerText = data.verification.flows_generated || 0;
          document.getElementById('demo-res-preds').innerText = data.verification.predictions_generated || 0;
          document.getElementById('demo-res-portscan').innerText = data.verification.portscan_predictions || 0;
          document.getElementById('demo-res-alerts').innerText = data.verification.alerts_persisted || 0;
        }

        if (data.is_running) {
          setTimeout(pollDemoStatus, 1000);
        } else {
          const btn = document.getElementById('btn-start-demo');
          btn.disabled = false;
          btn.innerText = '⚡ Run Controlled PortScan';
          fetchStats();
          fetchAlerts();
          fetchFlows();
        }
      } catch (e) {}
    }

    async function checkCapabilities() {
      try {
        const res = await fetch('/api/capture/capabilities');
        if (!res.ok) return;
        const data = await res.json();
        if (!data.can_capture_live) {
          document.getElementById('driver-warning').style.display = 'flex';
          document.getElementById('driver-warning-msg').innerText = data.status_message;
        }
      } catch (e) {}
    }

    async function fetchInterfaces() {
      try {
        const res = await fetch('/api/capture/interfaces');
        if (!res.ok) return;
        const ifaces = await res.json();
        const sel1 = document.getElementById('iface-select');
        const sel2 = document.getElementById('modal-iface-select');
        let html = '';
        ifaces.forEach(iface => {
          html += `<option value="${iface.id}">${iface.name} (${iface.ip})</option>`;
        });
        sel1.innerHTML = html;
        sel2.innerHTML = html;
      } catch (e) {}
    }

    async function startCapture() {
      const iface = document.getElementById('iface-select').value;
      const res = await fetch('/api/capture/start', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ interface: iface })
      });
      if (res.ok) {
        showToast("Live packet sniffing started");
        fetchStats();
      } else {
        const err = await res.json();
        showToast(`Capture error: ${err.detail ? (err.detail.message || JSON.stringify(err.detail)) : 'Failed'}`);
      }
    }

    async function stopCapture() {
      const res = await fetch('/api/capture/stop', { method: 'POST' });
      if (res.ok) {
        showToast("Live packet sniffing stopped");
        fetchStats();
      }
    }

    function openNetworkModal() { document.getElementById('network-modal').style.display = 'flex'; }
    function closeNetworkModal() { document.getElementById('network-modal').style.display = 'none'; }
    async function submitNetworkSwitch() {
      const iface = document.getElementById('modal-iface-select').value;
      const res = await fetch('/api/capture/switch', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ interface: iface })
      });
      if (res.ok) {
        closeNetworkModal();
        showToast(`Switched interface to ${iface}`);
        fetchStats();
      }
    }

    function openFPModal(alertId, attackType) {
      currentFPAlertId = alertId;
      document.getElementById('fp-alert-id-display').innerText = alertId;
      document.getElementById('fp-original-label').value = attackType;
      document.getElementById('fp-corrected-label').value = 'Benign';
      document.getElementById('fp-notes').value = '';
      document.getElementById('fp-modal').style.display = 'flex';
    }

    function closeFPModal() {
      document.getElementById('fp-modal').style.display = 'none';
      currentFPAlertId = null;
    }

    async function submitFalsePositive() {
      if (!currentFPAlertId) return;
      const btn = document.getElementById('btn-fp-submit');
      btn.disabled = true;
      try {
        const res = await fetch(`/api/alerts/${currentFPAlertId}/status`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            status: 'FALSE_POSITIVE',
            corrected_label: document.getElementById('fp-corrected-label').value,
            notes: document.getElementById('fp-notes').value
          })
        });
        if (res.ok) {
          closeFPModal();
          showToast(`Alert ${currentFPAlertId} marked as FALSE POSITIVE`);
          fetchAlerts();
          fetchStats();
        }
      } catch (e) {} finally {
        btn.disabled = false;
      }
    }

    function openResetModal() { document.getElementById('reset-modal').style.display = 'flex'; }
    function closeResetModal() { document.getElementById('reset-modal').style.display = 'none'; }
    async function submitResetSOC() {
      const res = await fetch('/api/reset', { method: 'POST' });
      if (res.ok) {
        closeResetModal();
        showToast("Database & capture counters reset");
        fetchStats();
        fetchFlows();
        fetchAlerts();
        if (activeTabId === 'tab-timeline') fetchTimeline();
        if (activeTabId === 'tab-attackers') fetchTopAttackers();
        if (activeTabId === 'tab-incidents') fetchIncidents();
      }
    }

    async function fetchModels() {
      try {
        const res = await fetch('/api/models');
        if (!res.ok) return;
        const data = await res.json();
        const container = document.getElementById('models-container');
        let html = '';
        data.models.forEach(m => {
          const mClean = m.model_id.replace('_cicids2017', '');
          const isActive = (mClean === data.active_model || m.model_id === data.active_model || (data.active_model === 'weighted_voting_ensemble' && (m.model_id === 'weighted_voting_ensemble_cicids2017' || mClean === 'weighted_voting_ensemble')));
          html += `
            <div class="model-card ${isActive ? 'active' : ''}" style="background: rgba(255,255,255,0.02); border: 1px solid var(--card-border); border-radius: 8px; padding: 12px; margin-bottom: 8px;">
              <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px;">
                <span style="font-weight: 700; font-size: 13px;">${m.name}</span>
                <span style="font-size: 10px; padding: 2px 6px; border-radius: 4px; background: rgba(255,255,255,0.1);">${m.framework}</span>
              </div>
              <div style="display: flex; justify-content: space-between; align-items: center;">
                <span style="font-size: 11px; color: var(--text-muted); font-family: 'JetBrains Mono', monospace;">Acc: ${(m.metrics.accuracy * 100).toFixed(1)}% | F1: ${(m.metrics.f1_score * 100).toFixed(1)}%</span>
                <button class="btn btn-secondary" style="font-size: 10px; padding: 4px 8px; ${isActive ? 'border-color: var(--accent-cyan); color: var(--accent-cyan);' : ''}" onclick="switchModel('${m.model_id}')">${isActive ? 'ACTIVE' : 'ACTIVATE'}</button>
              </div>
            </div>
          `;
        });
        container.innerHTML = html;
      } catch (e) {}
    }

    async function switchModel(modelId) {
      await fetch('/api/models/switch_active', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ model_id: modelId })
      });
      fetchStats();
      fetchModels();
    }

    initWebSocket();
    checkCapabilities();
    fetchInterfaces();
    fetchStats();
    fetchFlows();
    fetchAlerts();
    fetchModels();

    setInterval(fetchStats, 1500);
    setInterval(fetchFlows, 1500);
    setInterval(fetchAlerts, 2000);
  </script>
</body>
</html>
"""
