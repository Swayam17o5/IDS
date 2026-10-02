"""
services/inference/explainability_page.py
-----------------------------------------
Dedicated AI Explainability & Forensic Alert Analysis Page for AegisNIDS.
Provides deep mathematical SHAP breakdowns, dual-signal separation (ML vs Behavioral Heuristic),
full 77-feature inspection, and plain-English rationale.
"""

EXPLAINABILITY_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>AegisNIDS // AI Explainability & Alert Analysis</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;600;700;800&family=Plus+Jakarta+Sans:wght@400;500;600;700;800&display=swap" rel="stylesheet">
  <style>
    :root {
      --bg: #07090e;
      --card-bg: rgba(15, 23, 42, 0.78);
      --card-border: rgba(51, 65, 85, 0.6);
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
      --supporting: #10b981;
      --opposing: #ef4444;
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
      background: rgba(7, 9, 14, 0.92);
      position: sticky;
      top: 0;
      z-index: 100;
    }
    .header-left {
      display: flex;
      align-items: center;
      gap: 16px;
    }
    .btn-back {
      background: rgba(255, 255, 255, 0.06);
      border: 1px solid var(--card-border);
      color: var(--text);
      padding: 7px 14px;
      border-radius: 6px;
      font-size: 13px;
      font-weight: 600;
      cursor: pointer;
      display: flex;
      align-items: center;
      gap: 8px;
      text-decoration: none;
      transition: all 0.2s;
    }
    .btn-back:hover {
      background: rgba(0, 240, 255, 0.12);
      border-color: var(--accent-cyan);
      color: var(--accent-cyan);
    }
    .logo-title {
      font-size: 17px;
      font-weight: 800;
      letter-spacing: 0.5px;
    }
    .logo-subtitle {
      font-size: 11px;
      color: var(--text-muted);
      font-family: 'JetBrains Mono', monospace;
    }
    .header-actions {
      display: flex;
      align-items: center;
      gap: 10px;
    }
    .btn-action {
      background: rgba(255, 255, 255, 0.05);
      border: 1px solid var(--card-border);
      color: var(--text);
      padding: 6px 12px;
      border-radius: 6px;
      font-size: 12px;
      font-weight: 600;
      cursor: pointer;
      display: flex;
      align-items: center;
      gap: 6px;
      transition: all 0.2s;
    }
    .btn-action:hover {
      background: rgba(255, 255, 255, 0.12);
      border-color: var(--text-muted);
    }

    main {
      padding: 24px 28px;
      max-width: 1600px;
      margin: 0 auto;
      width: 100%;
      display: flex;
      flex-direction: column;
      gap: 22px;
      flex: 1;
    }

    /* Cards */
    .card {
      background: var(--card-bg);
      border: 1px solid var(--card-border);
      border-radius: 12px;
      padding: 20px;
      display: flex;
      flex-direction: column;
      gap: 14px;
      position: relative;
    }
    .card-title {
      font-size: 14px;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 0.8px;
      color: var(--text);
      display: flex;
      align-items: center;
      gap: 8px;
    }

    /* Badges */
    .badge {
      display: inline-block;
      padding: 3px 8px;
      border-radius: 4px;
      font-size: 11px;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 0.5px;
      font-family: 'JetBrains Mono', monospace;
    }
    .badge.CRITICAL { background: rgba(239, 68, 68, 0.2); color: var(--critical); border: 1px solid var(--critical); }
    .badge.HIGH { background: rgba(249, 115, 22, 0.2); color: var(--high); border: 1px solid var(--high); }
    .badge.MEDIUM { background: rgba(245, 158, 11, 0.2); color: var(--medium); border: 1px solid var(--medium); }
    .badge.LOW { background: rgba(59, 130, 246, 0.2); color: var(--low); border: 1px solid var(--low); }
    .badge.BENIGN { background: rgba(16, 185, 129, 0.2); color: var(--accent-emerald); border: 1px solid var(--accent-emerald); }

    /* Comparative Dual-Signal Grid */
    .dual-signal-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(320px, 1fr));
      gap: 16px;
    }
    .signal-card {
      background: rgba(255, 255, 255, 0.02);
      border: 1px solid var(--card-border);
      border-radius: 10px;
      padding: 16px 18px;
      display: flex;
      flex-direction: column;
      gap: 8px;
      position: relative;
    }
    .signal-card.highlight-aegis {
      border-color: rgba(0, 240, 255, 0.5);
      background: rgba(0, 240, 255, 0.03);
    }
    .signal-card.highlight-ml {
      border-color: rgba(59, 130, 246, 0.5);
      background: rgba(59, 130, 246, 0.03);
    }
    .signal-card.highlight-heuristic {
      border-color: rgba(245, 158, 11, 0.5);
      background: rgba(245, 158, 11, 0.03);
    }
    .signal-header {
      font-size: 11px;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 0.8px;
      color: var(--text-muted);
    }
    .signal-verdict {
      font-size: 22px;
      font-weight: 800;
      font-family: 'JetBrains Mono', monospace;
      color: #fff;
    }
    .signal-meta {
      font-size: 12px;
      color: var(--text-muted);
      line-height: 1.4;
    }

    /* Notice Callout Box */
    .notice-box {
      background: rgba(0, 240, 255, 0.05);
      border: 1px solid rgba(0, 240, 255, 0.25);
      border-radius: 8px;
      padding: 12px 18px;
      display: flex;
      align-items: center;
      gap: 12px;
      font-size: 13px;
      color: #e0f2fe;
    }

    /* Decision Flow Visual */
    .flow-diagram {
      background: rgba(0, 0, 0, 0.4);
      border: 1px solid var(--card-border);
      border-radius: 8px;
      padding: 16px;
      font-family: 'JetBrains Mono', monospace;
      font-size: 12px;
      color: var(--accent-cyan);
      overflow-x: auto;
      line-height: 1.6;
    }

    /* SHAP Bars */
    .shap-section-grid {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 18px;
    }
    @media (max-width: 1000px) {
      .shap-section-grid { grid-template-columns: 1fr; }
    }
    .shap-subpanel {
      background: rgba(255, 255, 255, 0.02);
      border: 1px solid var(--card-border);
      border-radius: 8px;
      padding: 14px;
      display: flex;
      flex-direction: column;
      gap: 10px;
    }
    .shap-subpanel-title {
      font-size: 12px;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 0.6px;
      display: flex;
      align-items: center;
      gap: 6px;
    }
    .shap-feature-row {
      display: flex;
      flex-direction: column;
      gap: 4px;
      padding: 8px 10px;
      background: rgba(255, 255, 255, 0.02);
      border-radius: 6px;
      border: 1px solid rgba(255, 255, 255, 0.04);
    }
    .shap-feat-header {
      display: flex;
      justify-content: space-between;
      font-size: 12px;
    }
    .shap-feat-name {
      font-weight: 600;
      color: var(--text);
    }
    .shap-feat-val {
      font-family: 'JetBrains Mono', monospace;
      color: var(--text-muted);
      font-size: 11px;
    }
    .shap-bar-track {
      background: rgba(255, 255, 255, 0.06);
      height: 6px;
      border-radius: 3px;
      overflow: hidden;
      display: flex;
    }
    .shap-bar-fill.supporting {
      background: linear-gradient(90deg, #10b981, #00f0ff);
    }
    .shap-bar-fill.opposing {
      background: linear-gradient(90deg, #f97316, #ef4444);
    }
    .shap-feat-footer {
      display: flex;
      justify-content: space-between;
      font-size: 11px;
      font-family: 'JetBrains Mono', monospace;
    }

    /* Class Probabilities Bar */
    .prob-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
      gap: 8px;
    }
    .prob-card {
      background: rgba(255, 255, 255, 0.02);
      border: 1px solid var(--card-border);
      border-radius: 6px;
      padding: 8px 10px;
      display: flex;
      flex-direction: column;
      gap: 4px;
    }
    .prob-header {
      display: flex;
      justify-content: space-between;
      font-size: 11px;
      font-weight: 600;
    }

    /* Feature Table */
    .table-container {
      overflow-x: auto;
      max-height: 480px;
      overflow-y: auto;
    }
    table {
      width: 100%;
      border-collapse: collapse;
      font-size: 12px;
      text-align: left;
    }
    th {
      position: sticky;
      top: 0;
      background: #0f172a;
      color: var(--text-muted);
      font-weight: 600;
      padding: 10px 12px;
      border-bottom: 1px solid var(--card-border);
      text-transform: uppercase;
      font-size: 10px;
      letter-spacing: 0.6px;
      z-index: 10;
    }
    td {
      padding: 8px 12px;
      border-bottom: 1px solid rgba(255, 255, 255, 0.04);
      font-family: 'JetBrains Mono', monospace;
      font-size: 11px;
    }
    tr:hover {
      background: rgba(255, 255, 255, 0.025);
    }
    .search-bar {
      display: flex;
      gap: 10px;
      align-items: center;
      margin-bottom: 8px;
    }
    .search-input {
      background: rgba(0, 0, 0, 0.4);
      border: 1px solid var(--card-border);
      color: var(--text);
      padding: 6px 12px;
      border-radius: 6px;
      font-size: 12px;
      flex: 1;
      max-width: 320px;
    }

    /* Loading overlay */
    #loading-state {
      padding: 60px 20px;
      text-align: center;
      color: var(--text-muted);
      font-size: 14px;
    }
  </style>
</head>
<body>

  <header>
    <div class="header-left">
      <a href="/" class="btn-back">
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="19" y1="12" x2="5" y2="12"></line><polyline points="12 19 5 12 12 5"></polyline></svg>
        Back to SOC Dashboard
      </a>
      <div>
        <div class="logo-title">AegisNIDS // AI Explainability & Forensic Analysis</div>
        <div class="logo-subtitle">MATHEMATICAL SHAP FEATURE ATTRIBUTION & DUAL-SIGNAL VERDICT FORENSICS</div>
      </div>
    </div>
    <div class="header-actions">
      <button class="btn-action" onclick="exportExplanationJSON()">
        <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"></path><polyline points="7 10 12 15 17 10"></polyline><line x1="12" y1="15" x2="12" y2="3"></line></svg>
        Download JSON
      </button>
      <button class="btn-action" onclick="window.print()">
        <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="6 9 6 2 18 2 18 9"></polyline><path d="M6 18H4a2 2 0 0 1-2-2v-5a2 2 0 0 1 2-2h16a2 2 0 0 1 2 2v5a2 2 0 0 1-2 2h-2"></path><rect x="6" y="14" width="12" height="8"></rect></svg>
        Print Report
      </button>
    </div>
  </header>

  <main>
    <div id="loading-state">
      <div style="font-size: 18px; margin-bottom: 8px;">🧠 Computing Deep SHAP Attributions...</div>
      <div>Loading stored flow feature vectors and evaluating TreeSHAP feature importance...</div>
    </div>

    <div id="content-state" style="display: none; display: flex; flex-direction: column; gap: 20px;">

      <!-- SECTION 1: ALERT SUMMARY & DUAL-SIGNAL COMPARATIVE GRID -->
      <div class="card">
        <div class="card-title" style="justify-content: space-between;">
          <span>🎯 Alert Telemetry & Identification</span>
          <span id="alert-id-badge" class="badge" style="background: rgba(255,255,255,0.08); color: #fff;">ALT-...</span>
        </div>
        <div class="dual-signal-grid">
          <!-- Final Aegis Verdict -->
          <div class="signal-card highlight-aegis">
            <div class="signal-header">Final AegisNIDS Decision</div>
            <div id="val-final-decision" class="signal-verdict" style="color: var(--accent-cyan);">PORTSCAN</div>
            <div class="signal-meta">
              <div>Severity: <span id="val-severity" class="badge MEDIUM">MEDIUM</span></div>
              <div>Confidence: <strong id="val-detection-conf">85.4%</strong></div>
              <div>Detection Method: <strong id="val-detection-method" style="color: var(--accent-cyan);">SYN_BURST_HEURISTIC</strong></div>
            </div>
          </div>

          <!-- ML Model Verdict -->
          <div class="signal-card highlight-ml">
            <div class="signal-header">Machine Learning Model Prediction</div>
            <div id="val-ml-prediction" class="signal-verdict" style="color: #60a5fa;">BENIGN</div>
            <div class="signal-meta">
              <div>ML Confidence: <strong id="val-ml-conf">99.6%</strong></div>
              <div>Active Model: <span id="val-model-used">Weighted Voting Ensemble</span></div>
              <div>Explainer: <span id="val-explainer-model">TreeSHAP (XGBoost Component)</span></div>
            </div>
          </div>

          <!-- Behavioral Detection -->
          <div class="signal-card highlight-heuristic">
            <div class="signal-header">Behavioral Network Heuristic</div>
            <div id="val-heuristic-verdict" class="signal-verdict" style="color: var(--medium);">PORTSCAN</div>
            <div class="signal-meta">
              <div>Distinct Ports Probed: <strong id="val-distinct-ports">8</strong></div>
              <div>Sequential Probing: <strong id="val-seq-probing">Detected</strong></div>
              <div>Heuristic Confidence: <strong id="val-heuristic-conf">85.4%</strong></div>
            </div>
          </div>
        </div>

        <!-- 5-Tuple Network Metadata -->
        <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 10px; font-size: 12px; background: rgba(0,0,0,0.25); padding: 12px 16px; border-radius: 6px; border: 1px solid var(--card-border);">
          <div>Source IP: <strong id="val-src-ip" style="color: var(--accent-cyan);">--</strong></div>
          <div>Destination IP: <strong id="val-dst-ip">--</strong></div>
          <div>Target Port: <strong id="val-dst-port">--</strong></div>
          <div>Timestamp: <span id="val-timestamp" style="color: var(--text-muted);">--</span></div>
          <div>Flows Correlated: <strong id="val-flow-count">1</strong></div>
        </div>
      </div>

      <!-- SECTION 2: ARCHITECTURAL SEPARATION NOTICE & FLOW DIAGRAM -->
      <div class="notice-box">
        <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="var(--accent-cyan)" stroke-width="2"><circle cx="12" cy="12" r="10"></circle><line x1="12" y1="16" x2="12" y2="12"></line><line x1="12" y1="8" x2="12.01" y2="8"></line></svg>
        <div>
          <strong>Dual-Signal Separation Architecture:</strong> SHAP mathematically explains the <strong>Machine Learning Model</strong> prediction for this flow instance. The final AegisNIDS alert was additionally evaluated by the <strong>Behavioral SYN-Burst Detector</strong> to capture high-speed multi-port sweeps.
        </div>
      </div>

      <div class="card">
        <div class="card-title">🔀 Detection Decision Flow Pipeline</div>
        <div class="flow-diagram">
NETWORK WIRE FRAME ──► 77-FEATURE VECTOR EXTRACTION ──► FEATURE VALIDATOR (Schema & Ranges)
                               │
            ┌──────────────────┴──────────────────┐
            ▼                                     ▼
   [ ML ENSEMBLE BRANCH ]              [ BEHAVIORAL HEURISTIC BRANCH ]
   • XGBoost / LightGBM / CatBoost     • TCP SYN Burst Analyzer
   • Prediction: <span id="flow-diag-ml-pred" style="color: #60a5fa;">BENIGN (99.6%)</span>          • Probed Ports: <span id="flow-diag-ports" style="color: var(--medium);">8 Ports</span>
   • Explained via TreeSHAP            • Verdict: <span id="flow-diag-heur-verdict" style="color: var(--medium);">PORTSCAN (85.4%)</span>
            │                                     │
            └──────────────────┬──────────────────┘
                               ▼
                [ DUAL-SIGNAL ALERT ENGINE ]
                • Resolution: Behavioral Heuristic overrides ML for multi-port sweeps
                • Final AegisNIDS Verdict: <strong id="flow-diag-final" style="color: var(--accent-cyan);">PORTSCAN (85.4%)</strong>
                • Action: Deduplicated Alert Persisted to SQLite
        </div>
      </div>

      <!-- SECTION 3: ML CLASS PROBABILITY DISTRIBUTION -->
      <div class="card">
        <div class="card-title">📊 ML Model Class Probabilities Distribution</div>
        <div id="prob-container" class="prob-grid">
          <!-- Rendered dynamically -->
        </div>
      </div>

      <!-- SECTION 4: MAIN SHAP FEATURE EXPLANATION -->
      <div class="card">
        <div class="card-title">🧠 Why Did the ML Model Predict <span id="title-ml-pred" style="color: #60a5fa;">BENIGN</span>?</div>
        <p style="font-size: 13px; color: var(--text-muted);">
          Shapley Additive exPlanations (SHAP) allocate credit to each individual feature based on how much it shifted the model's output from the dataset base rate towards the predicted class.
        </p>

        <div id="base-val-info" style="display: none; font-size: 12px; background: rgba(255,255,255,0.03); padding: 8px 14px; border-radius: 6px; border: 1px solid var(--card-border);">
          Expected Base Value (E[X]): <strong id="val-base-value">--</strong> | Final Model Score: <strong id="val-output-score">--</strong>
        </div>

        <div class="shap-section-grid">
          <!-- Supporting Panel -->
          <div class="shap-subpanel">
            <div class="shap-subpanel-title" style="color: var(--supporting);">
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="18 15 12 9 6 15"></polyline></svg>
              Features Supporting ML Prediction (<span id="supporting-count">0</span>)
            </div>
            <div id="supporting-shap-list" style="display: flex; flex-direction: column; gap: 8px;">
              <!-- Dynamic items -->
            </div>
          </div>

          <!-- Opposing Panel -->
          <div class="shap-subpanel">
            <div class="shap-subpanel-title" style="color: var(--opposing);">
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="6 9 12 15 18 9"></polyline></svg>
              Features Opposing ML Prediction (<span id="opposing-count">0</span>)
            </div>
            <div id="opposing-shap-list" style="display: flex; flex-direction: column; gap: 8px;">
              <!-- Dynamic items -->
            </div>
          </div>
        </div>
      </div>

      <!-- SECTION 5: BEHAVIORAL DETECTION ANALYSIS -->
      <div class="card" id="behavioral-card">
        <div class="card-title" style="color: var(--medium);">⚡ Behavioral Heuristic Evidence Analysis</div>
        <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 12px; font-size: 12px;">
          <div style="background: rgba(255,255,255,0.02); padding: 12px; border-radius: 6px; border: 1px solid var(--card-border);">
            <div style="color: var(--text-muted);">Distinct Ports Probed</div>
            <div id="heur-distinct-ports" style="font-size: 20px; font-weight: 800; color: #fff; margin-top: 4px;">--</div>
          </div>
          <div style="background: rgba(255,255,255,0.02); padding: 12px; border-radius: 6px; border: 1px solid var(--card-border);">
            <div style="color: var(--text-muted);">Probing Pattern</div>
            <div id="heur-pattern" style="font-size: 16px; font-weight: 700; color: var(--accent-cyan); margin-top: 4px;">Sequential TCP SYN Sweep</div>
          </div>
          <div style="background: rgba(255,255,255,0.02); padding: 12px; border-radius: 6px; border: 1px solid var(--card-border);">
            <div style="color: var(--text-muted);">Payload Activity</div>
            <div id="heur-payload" style="font-size: 16px; font-weight: 700; color: var(--accent-emerald); margin-top: 4px;">Header-Only Probing (0 B)</div>
          </div>
          <div style="background: rgba(255,255,255,0.02); padding: 12px; border-radius: 6px; border: 1px solid var(--card-border);">
            <div style="color: var(--text-muted);">Heuristic Confidence</div>
            <div id="heur-conf-score" style="font-size: 20px; font-weight: 800; color: var(--medium); margin-top: 4px;">85.4%</div>
          </div>
        </div>
      </div>

      <!-- SECTION 6: WHY WAS THIS ALERT GENERATED? SYNTHESIS -->
      <div class="card">
        <div class="card-title">📝 Forensic Verdict Synthesis & Plain-English Rationale</div>
        <div id="verdict-synthesis-text" style="font-size: 13px; line-height: 1.6; background: rgba(255,255,255,0.02); padding: 16px; border-radius: 8px; border: 1px solid var(--card-border);">
          Loading rationale synthesis...
        </div>
      </div>

      <!-- SECTION 7: FULL 77-FEATURE INSPECTOR -->
      <div class="card">
        <div class="card-title" style="justify-content: space-between;">
          <span>📋 Canonical 77-Feature Inference Vector & SHAP Rankings</span>
          <button id="btn-toggle-features" class="btn-action" onclick="toggleAllFeatures()">Show All 77 Features</button>
        </div>

        <div class="search-bar">
          <input type="text" id="feature-search" class="search-input" placeholder="🔍 Search 77 features (e.g. Duration, SYN, Port)..." oninput="filterFeatureTable()">
          <button class="btn-action" onclick="sortFeatureTable('shap')">Sort by SHAP Impact</button>
          <button class="btn-action" onclick="sortFeatureTable('name')">Sort by Name</button>
          <button class="btn-action" onclick="sortFeatureTable('val')">Sort by Value</button>
        </div>

        <div class="table-container" id="features-table-wrapper" style="max-height: 320px;">
          <table>
            <thead>
              <tr>
                <th>#</th>
                <th>Canonical Feature Name</th>
                <th>Actual Value</th>
                <th>SHAP Contribution</th>
                <th>Influence Direction</th>
              </tr>
            </thead>
            <tbody id="features-tbody">
              <!-- Dynamically populated -->
            </tbody>
          </table>
        </div>
      </div>

      <!-- SECTION 8: GLOBAL MODEL EXPLAINABILITY -->
      <div class="card">
        <div class="card-title">🌐 Global Model Explainability (Dataset Level)</div>
        <p style="font-size: 13px; color: var(--text-muted);">
          Key discriminating features across the entire CICIDS2017 training benchmark for the active architecture:
        </p>
        <div id="global-importance-grid" style="display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 8px; margin-top: 4px;">
          <!-- Dynamically populated -->
        </div>
      </div>

    </div>
  </main>

  <script>
    const alertId = window.location.pathname.split('/').pop();
    let deepData = null;
    let allFeaturesList = [];
    let isFeaturesExpanded = false;
    let currentSortMode = 'shap';

    async function loadDeepExplanation() {
      try {
        const res = await fetch(`/api/alerts/${alertId}/deep-explanation`);
        if (!res.ok) {
          document.getElementById('loading-state').innerHTML = `
            <div style="color: var(--critical); font-size: 18px; margin-bottom: 8px;">❌ Alert Explanation Not Found</div>
            <div>Alert ID <strong>${alertId}</strong> was not found in the SQLite database.</div>
          `;
          return;
        }
        deepData = await res.json();
        renderPage(deepData);
      } catch (e) {
        document.getElementById('loading-state').innerHTML = `
          <div style="color: var(--critical); font-size: 18px; margin-bottom: 8px;">⚠️ Failed to compute SHAP attributions</div>
          <div>${e.message}</div>
        `;
      }
    }

    function renderPage(data) {
      document.getElementById('loading-state').style.display = 'none';
      document.getElementById('content-state').style.display = 'flex';

      const alert = data.alert || {};
      const ml = data.ml_verdict || {};
      const heur = data.heuristic_verdict || {};
      const shap = data.shap || {};

      // Badges & IDs
      document.getElementById('alert-id-badge').innerText = alert.alert_id || alertId;
      document.getElementById('val-final-decision').innerText = (alert.attack_type || 'UNKNOWN').toUpperCase();
      document.getElementById('val-severity').innerText = (alert.severity || 'MEDIUM').toUpperCase();
      document.getElementById('val-severity').className = `badge ${(alert.severity || 'MEDIUM').toUpperCase()}`;
      document.getElementById('val-detection-conf').innerText = `${((alert.confidence || 0) * 100).toFixed(1)}%`;
      document.getElementById('val-detection-method').innerText = alert.detection_method || 'MACHINE_LEARNING';

      // ML Verdict
      document.getElementById('val-ml-prediction').innerText = (ml.predicted_label || 'BENIGN').toUpperCase();
      document.getElementById('val-ml-conf').innerText = `${((ml.confidence || 0) * 100).toFixed(1)}%`;
      document.getElementById('val-model-used').innerText = ml.model_name || alert.model_used || 'Weighted Voting Ensemble';
      document.getElementById('val-explainer-model').innerText = shap.explainer_model || 'TreeSHAP';
      document.getElementById('title-ml-pred').innerText = (ml.predicted_label || 'BENIGN').toUpperCase();

      // Heuristic Verdict
      document.getElementById('val-heuristic-verdict').innerText = heur.attack_type || alert.attack_type || 'PORTSCAN';
      document.getElementById('val-distinct-ports').innerText = heur.distinct_ports_scanned || 8;
      document.getElementById('val-seq-probing').innerText = heur.sequential_probing ? 'Detected' : 'Observed';
      document.getElementById('val-heuristic-conf').innerText = `${((heur.heuristic_confidence || alert.confidence || 0.85) * 100).toFixed(1)}%`;

      // 5-Tuple
      document.getElementById('val-src-ip').innerText = alert.src_ip || '0.0.0.0';
      document.getElementById('val-dst-ip').innerText = alert.dst_ip || '0.0.0.0';
      document.getElementById('val-dst-port').innerText = alert.dst_port || '0';
      document.getElementById('val-timestamp').innerText = alert.timestamp ? alert.timestamp.replace('T', ' ').split('.')[0] : '--';
      document.getElementById('val-flow-count').innerText = alert.flow_count || 1;

      // Decision Flow
      document.getElementById('flow-diag-ml-pred').innerText = `${ml.predicted_label || 'BENIGN'} (${((ml.confidence||0)*100).toFixed(1)}%)`;
      document.getElementById('flow-diag-ports').innerText = `${heur.distinct_ports_scanned || 8} Ports`;
      document.getElementById('flow-diag-heur-verdict').innerText = `${alert.attack_type} (${((alert.confidence||0)*100).toFixed(1)}%)`;
      document.getElementById('flow-diag-final').innerText = `${alert.attack_type} (${((alert.confidence||0)*100).toFixed(1)}%)`;

      // Probabilities
      renderProbabilities(ml.class_probabilities || {});

      // SHAP Lists
      renderShapLists(shap.supporting_features || [], shap.opposing_features || []);

      // Base value
      if (shap.base_value !== null && shap.base_value !== undefined) {
        document.getElementById('base-val-info').style.display = 'block';
        document.getElementById('val-base-value').innerText = shap.base_value.toFixed(4);
        document.getElementById('val-output-score').innerText = ((ml.confidence || 0) * 100).toFixed(2) + '%';
      }

      // Behavioral Card
      if (alert.detection_method === 'SYN_BURST_HEURISTIC' || alert.detection_method === 'ML_HYBRID') {
        document.getElementById('heur-distinct-ports').innerText = heur.distinct_ports_scanned || 8;
        document.getElementById('heur-conf-score').innerText = `${((alert.confidence || 0.85) * 100).toFixed(1)}%`;
      }

      // Synthesis Rationale
      document.getElementById('verdict-synthesis-text').innerHTML = data.comparison?.why_alert_generated || alert.explanation || 'Detection rationale processed.';

      // 77 Features Table
      allFeaturesList = shap.all_77_features || [];
      renderFeaturesTable(allFeaturesList);

      // Global Importance
      renderGlobalImportance(data.global_shap || []);
    }

    function renderProbabilities(probs) {
      const container = document.getElementById('prob-container');
      const entries = Object.entries(probs);
      if (entries.length === 0) {
        container.innerHTML = '<div style="color: var(--text-muted); font-size: 12px;">Class probabilities not available for this model architecture.</div>';
        return;
      }
      // Sort descending
      entries.sort((a, b) => b[1] - a[1]);
      let html = '';
      entries.forEach(([cls, p]) => {
        const pct = (p * 100).toFixed(1);
        const isTop = (p > 0.1);
        html += `
          <div class="prob-card" style="${isTop ? 'border-color: rgba(0, 240, 255, 0.4);' : ''}">
            <div class="prob-header">
              <span>${cls}</span>
              <span style="color: ${isTop ? 'var(--accent-cyan)' : 'var(--text-muted)'};">${pct}%</span>
            </div>
            <div class="shap-bar-track">
              <div class="shap-bar-fill supporting" style="width: ${Math.max(2, p * 100)}%;"></div>
            </div>
          </div>
        `;
      });
      container.innerHTML = html;
    }

    function renderShapLists(supporting, opposing) {
      document.getElementById('supporting-count').innerText = supporting.length;
      document.getElementById('opposing-count').innerText = opposing.length;

      const supContainer = document.getElementById('supporting-shap-list');
      const oppContainer = document.getElementById('opposing-shap-list');

      let supHtml = '';
      if (supporting.length === 0) {
        supHtml = '<div style="color: var(--text-muted); font-size: 12px; padding: 8px;">No positive supporting features.</div>';
      } else {
        supporting.forEach(f => {
          const barWidth = Math.min(100, Math.max(5, Math.abs(f.shap_value) * 100));
          supHtml += `
            <div class="shap-feature-row">
              <div class="shap-feat-header">
                <span class="shap-feat-name">${f.feature}</span>
                <span class="shap-feat-val">Val: ${Number(f.value).toLocaleString()}</span>
              </div>
              <div class="shap-bar-track">
                <div class="shap-bar-fill supporting" style="width: ${barWidth}%;"></div>
              </div>
              <div class="shap-feat-footer">
                <span style="color: var(--supporting);">+${Number(f.shap_value).toFixed(4)}</span>
                <span style="color: var(--text-muted);">${f.direction_label || '→ Supports Prediction'}</span>
              </div>
            </div>
          `;
        });
      }
      supContainer.innerHTML = supHtml;

      let oppHtml = '';
      if (opposing.length === 0) {
        oppHtml = '<div style="color: var(--text-muted); font-size: 12px; padding: 8px;">No negative opposing features.</div>';
      } else {
        opposing.forEach(f => {
          const barWidth = Math.min(100, Math.max(5, Math.abs(f.shap_value) * 100));
          oppHtml += `
            <div class="shap-feature-row">
              <div class="shap-feat-header">
                <span class="shap-feat-name">${f.feature}</span>
                <span class="shap-feat-val">Val: ${Number(f.value).toLocaleString()}</span>
              </div>
              <div class="shap-bar-track">
                <div class="shap-bar-fill opposing" style="width: ${barWidth}%;"></div>
              </div>
              <div class="shap-feat-footer">
                <span style="color: var(--opposing);">${Number(f.shap_value).toFixed(4)}</span>
                <span style="color: var(--text-muted);">${f.direction_label || '⊘ Opposes Prediction'}</span>
              </div>
            </div>
          `;
        });
      }
      oppContainer.innerHTML = oppHtml;
    }

    function renderFeaturesTable(feats) {
      const tbody = document.getElementById('features-tbody');
      if (!feats || feats.length === 0) {
        tbody.innerHTML = '<tr><td colspan="5" style="text-align: center; color: var(--text-muted);">Feature values not available.</td></tr>';
        return;
      }
      let html = '';
      feats.forEach((f, idx) => {
        const isPos = f.shap_value > 0;
        const color = isPos ? 'var(--supporting)' : (f.shap_value < 0 ? 'var(--opposing)' : 'var(--text-muted)');
        const sign = isPos ? '+' : '';
        html += `
          <tr>
            <td>${f.rank || (idx + 1)}</td>
            <td style="font-weight: 600; color: #fff;">${f.feature}</td>
            <td>${Number(f.value).toLocaleString()}</td>
            <td style="color: ${color}; font-weight: 700;">${sign}${Number(f.shap_value || 0).toFixed(4)}</td>
            <td style="font-size: 11px; color: var(--text-muted);">${f.direction_label || (isPos ? 'Supporting' : 'Opposing')}</td>
          </tr>
        `;
      });
      tbody.innerHTML = html;
    }

    function toggleAllFeatures() {
      const wrapper = document.getElementById('features-table-wrapper');
      const btn = document.getElementById('btn-toggle-features');
      isFeaturesExpanded = !isFeaturesExpanded;
      if (isFeaturesExpanded) {
        wrapper.style.maxHeight = 'none';
        btn.innerText = 'Hide / Collapse Features';
      } else {
        wrapper.style.maxHeight = '320px';
        btn.innerText = 'Show All 77 Features';
      }
    }

    function filterFeatureTable() {
      const query = document.getElementById('feature-search').value.toLowerCase().trim();
      const filtered = allFeaturesList.filter(f => f.feature.toLowerCase().includes(query));
      renderFeaturesTable(filtered);
    }

    function sortFeatureTable(mode) {
      currentSortMode = mode;
      let sorted = [...allFeaturesList];
      if (mode === 'shap') {
        sorted.sort((a, b) => Math.abs(b.shap_value || 0) - Math.abs(a.shap_value || 0));
      } else if (mode === 'name') {
        sorted.sort((a, b) => a.feature.localeCompare(b.feature));
      } else if (mode === 'val') {
        sorted.sort((a, b) => (b.value || 0) - (a.value || 0));
      }
      renderFeaturesTable(sorted);
    }

    function renderGlobalImportance(globalList) {
      const container = document.getElementById('global-importance-grid');
      if (!globalList || globalList.length === 0) {
        container.innerHTML = '<div style="color: var(--text-muted); font-size: 12px;">Global feature importances initialized.</div>';
        return;
      }
      let html = '';
      globalList.forEach(g => {
        html += `
          <div style="background: rgba(255,255,255,0.02); border: 1px solid var(--card-border); padding: 8px 10px; border-radius: 6px;">
            <div style="display: flex; justify-content: space-between; font-size: 11px; margin-bottom: 4px;">
              <span style="font-weight: 600;">#${g.rank} ${g.feature}</span>
              <span style="color: var(--accent-cyan); font-family: 'JetBrains Mono';">${g.importance_pct}%</span>
            </div>
            <div class="shap-bar-track">
              <div class="shap-bar-fill supporting" style="width: ${Math.min(100, g.importance_pct * 3)}%;"></div>
            </div>
          </div>
        `;
      });
      container.innerHTML = html;
    }

    function exportExplanationJSON() {
      if (!deepData) return;
      const jsonStr = JSON.stringify(deepData, null, 2);
      const blob = new Blob([jsonStr], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `AegisNIDS_Explanation_${alertId}.json`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    }

    // Initialize
    loadDeepExplanation();
  </script>
</body>
</html>
"""
