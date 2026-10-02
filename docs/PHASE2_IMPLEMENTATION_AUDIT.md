# AegisNIDS — Phase 2 Implementation Audit & Architecture Plan

**Date:** October 2, 2026  
**Auditor:** AegisNIDS Core Agent  
**Baseline Status:** Phase 1 Complete (95/95 Unit/Integration Tests Passing, Verified with Real Nmap SYN PortScan Traffic in `nids.db`)

---

## 1. Executive Summary & Objective

Phase 1 established the end-to-end detection pipeline:
```
Network Interface (Npcap/Scapy) → Flow Aggregation → 77 CICIDS2017 Features 
  → Feature Validation → ML Inference (XGBoost/Ensemble) → Dual-Signal Verdict 
  → Alert Engine & Deduplication → SQLite (nids.db) → REST API
```
A real-world PortScan was performed and validated in `nids.db` (35 flows, 35 predictions, 1 deduplicated PortScan alert with `SYN_BURST_HEURISTIC` verdict).

**Phase 2 Objective:** Transform AegisNIDS from an ML inference demo into a production-grade, operational Security Operations Center (SOC) Intrusion Detection System.

---

## 2. Component-by-Component Audit

### 2.1 Objective 9: Real-Time SOC Dashboard
* **Existing Implementation:**
  * Embedded HTML/JS dashboard served at `GET /` in `services/inference/app.py`.
  * Basic polling (1.5s–2.0s) fetching `/api/stats`, `/api/flows`, `/api/alerts`, `/api/models`.
  * Basic metrics cards (Flows, Predictions, Alerts, Precision, Severity counts).
* **Missing Functionality:**
  * Real-time WebSocket connection (`/ws/alerts`, `/ws/metrics`) with automatic reconnect & polling fallback.
  * Live SOC metrics: Flows/min, Predictions/min, Alerts/min, PortScan vs Benign vs Attack breakdown, live detection rate, confidence distribution.
  * Integrated multi-panel SOC layout (Timeline, Top Attackers, Incidents, Explainability, Replay, Demo).
* **Files to Modify:**
  * `services/inference/app.py`: Add WebSocket endpoint `/ws/live`, telemetry metrics aggregation.
  * Embedded `DASHBOARD_HTML` / frontend assets: Modernize into a high-density SOC interface.

---

### 2.2 Objective 10: Attack Timeline
* **Existing Implementation:** None (alerts queried only as a flat reverse-chronological list).
* **Missing Functionality:**
  * Query endpoint `GET /api/timeline` supporting time range filtering (`last_5m`, `last_15m`, `last_1h`, `last_24h`, `custom`), severity filter, attack type filter, source IP filter, and detection method filter.
  * Interactive visual timeline component on the dashboard rendering alert events chronologically with severity badges, detection method tags, and confidence scores.
* **Files to Modify:**
  * `services/inference/app.py`: Implement `GET /api/timeline`.
  * Dashboard frontend: Add interactive timeline widget with filter controls.

---

### 2.3 Objective 11: Top Attacking IPs Analytics
* **Existing Implementation:** None.
* **Missing Functionality:**
  * Analytical query endpoint `GET /api/analytics/top-attackers` aggregating real alerts from `nids.db`:
    * Source IP (`src_ip`)
    * Total alerts generated
    * Number of unique victim destinations (`dst_ip`)
    * Number of distinct attack types probed
    * Most frequent attack type
    * Highest severity observed
    * First seen & last seen timestamps
  * Support for `limit`, `time_range`, `attack_type` query parameters.
  * Dashboard Top Attackers table and threat ranking visualization.
* **Files to Modify:**
  * `services/inference/app.py`: Implement `GET /api/analytics/top-attackers`.
  * Dashboard frontend: Add Top Attackers table & analytics view.

---

### 2.4 Objective 12: Incident Management Workflow
* **Existing Implementation:** Basic per-alert status field (`NEW`, `ACKNOWLEDGED`, `FALSE_POSITIVE`, `ESCALATED`, `RESOLVED`) on `DBAlert`.
* **Missing Functionality:**
  * Dedicated Incident entities grouping one or more related alerts under an incident ticket (e.g., `INC-2026-0001`).
  * Database schema additions:
    * `DBIncident`: `incident_id`, `title`, `status` (`NEW`, `ACKNOWLEDGED`, `INVESTIGATING`, `RESOLVED`, `FALSE_POSITIVE`), `severity`, `attack_type`, `src_ip`, `dst_ip`, `created_at`, `updated_at`, `resolved_at`, `analyst_notes`, `resolution_reason`.
    * `DBIncidentAlert`: Association table linking `incident_id` to `alert_id`.
    * `DBIncidentNote`: Audit trail of analyst notes with timestamps.
  * REST API endpoints:
    * `GET /api/incidents` (filtering by status, severity, attack_type, src_ip)
    * `GET /api/incidents/{incident_id}`
    * `POST /api/incidents` (create manual or auto incident from alert)
    * `PATCH /api/incidents/{incident_id}` (update status, severity, resolution reason)
    * `POST /api/incidents/{incident_id}/alerts` (attach alert to incident)
    * `POST /api/incidents/{incident_id}/notes` (add analyst note)
  * Incident Management dashboard panel with status transition buttons and note logs.
* **Files to Modify:**
  * `database/models.py`: Add `DBIncident`, `DBIncidentAlert`, `DBIncidentNote`.
  * `database/db.py`: Add migrations for incident tables.
  * `services/inference/app.py`: Add Incident CRUD endpoints.
  * Dashboard frontend: Add Incident Management tab/modal.

---

### 2.5 Objective 13: SHAP Explanations & Model Transparency
* **Existing Implementation:**
  * `SHAPExplainer` in `services/inference/explainer.py` initializing `shap.TreeExplainer(model)`.
  * `shap_json` stored on `DBPrediction` and `DBAlert`.
* **Missing Functionality:**
  * Dedicated explanation endpoint `GET /api/predictions/{prediction_id}/explanation` and `GET /api/alerts/{alert_id}/explanation`.
  * Returns:
    * Prediction metadata (label, confidence, active model, detection method)
    * Sorted feature contributions: `feature_name`, `feature_value`, `shap_value`, `direction` (positive/negative), `importance`
    * Model-specific explanation attribution (e.g., XGBoost TreeExplainer vs Stacking Ensemble component explanation)
    * Plain-English human-readable rationale
  * Dashboard "Why was this detected?" interactive inspection modal.
* **Files to Modify:**
  * `services/inference/explainer.py`: Enhance robust feature extraction, directional impact, and fallback explanations.
  * `services/inference/app.py`: Add explanation API endpoints.
  * Dashboard frontend: Add interactive SHAP waterfall/bar breakdown.

---

### 2.6 Objective 14: Offline PCAP Replay Pipeline
* **Existing Implementation:** Standalone script `replay_pcap.py` generating synthetic PCAPs and extracting flows.
* **Missing Functionality:**
  * Background replay engine `PCAPReplayService` isolated from live capture (`mode="PCAP_REPLAY"` vs `mode="LIVE"`).
  * Strict offline processing: PCAP → Scapy Reader → `FlowAggregator` → `PCAPFeatureExtractor` → `FeatureValidator` → Inference → Alert Engine → `nids.db` (zero raw packet injection onto physical network).
  * Database audit table `DBPCAPReplay`: Tracks `replay_id`, `filename`, `started_at`, `completed_at`, `packets_processed`, `flows_generated`, `alerts_generated`, `status`.
  * REST API endpoints:
    * `POST /api/replay/start` (with path validation and security checks)
    * `POST /api/replay/stop`
    * `GET /api/replay/status`
    * `GET /api/replay/history`
  * Dashboard PCAP Replay panel with progress meters and synthetic sample triggers.
* **Files to Modify:**
  * `services/feature_extractor/pcap_replay.py`: New modular background replay service.
  * `database/models.py` & `database/db.py`: Add `DBPCAPReplay` table.
  * `services/inference/app.py`: Add Replay API endpoints.
  * Dashboard frontend: Add PCAP Replay management UI.

---

### 2.7 Objective 15: Controlled Authorized Nmap Demonstration
* **Existing Implementation:** Bundled Nmap portable in `tools/nmap-7.92/`.
* **Missing Functionality:**
  * Authorized lab demonstration runner `services/demo/nmap_demo.py`.
  * Strict Security Guardrails:
    * Target restriction: ONLY `127.0.0.1`, `localhost`, and RFC1918 private IP ranges (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`) allowed. Any public/external IP is strictly rejected.
    * No arbitrary command strings: Command constructed safely via parameter validation (`scan_type`, `ports`, `target`, `timing_template`).
    * Timeout enforcement (`timeout <= 30s`).
  * Demonstration flow:
    1. Start capture on loopback or local interface.
    2. Trigger validated Nmap SYN scan against authorized target.
    3. Live packets sniffed → FlowAggregator → PortScan detected via SYN Heuristic / ML → Alert persisted to `nids.db` → Dashboard updates in real time.
  * REST API endpoints:
    * `POST /api/demo/nmap/start`
    * `GET /api/demo/nmap/status`
  * Dashboard Authorized Lab Mode panel with live demonstration status.
* **Files to Modify:**
  * `services/demo/nmap_demo.py`: Create safe demo runner.
  * `services/inference/app.py`: Add Demo endpoints.
  * Dashboard frontend: Add Lab Mode demonstration panel.

---

## 3. Architecture & Data Flow

```
                                  ┌────────────────────────────────────────┐
                                  │           Network Traffic              │
                                  │ (Live Interface / Offline PCAP Replay) │
                                  └───────────────────┬────────────────────┘
                                                      │
                                                      ▼
                                       ┌─────────────────────────────┐
                                       │    Flow Aggregator (77)     │
                                       └──────────────┬──────────────┘
                                                      │
                                                      ▼
                                       ┌─────────────────────────────┐
                                       │      Feature Validator      │
                                       └──────────────┬──────────────┘
                                                      │
                                                      ▼
                                       ┌─────────────────────────────┐
                                       │  ML Inference & SYN Burst   │
                                       └──────────────┬──────────────┘
                                                      │
                                                      ▼
                                       ┌─────────────────────────────┐
                                       │ Alert Engine & Deduplication│
                                       └──────────────┬──────────────┘
                                                      │
                                 ┌────────────────────┴────────────────────┐
                                 ▼                                         ▼
                   ┌───────────────────────────┐             ┌───────────────────────────┐
                   │    SQLite DB (nids.db)    │             │   WebSocket Event Broad-  │
                   │  - flows                  │             │   caster & PubSub Hub     │
                   │  - predictions            │             └─────────────┬─────────────┘
                   │  - alerts                 │                           │
                   │  - incidents (NEW)        │                           │
                   │  - pcap_replays (NEW)     │                           ▼
                   └─────────────┬─────────────┘             ┌───────────────────────────┐
                                 │                           │   Real-Time SOC Dashboard │
                                 └──────────────────────────►│  - Live Alerts & Metrics  │
                                                             │  - Attack Timeline        │
                                                             │  - Top Attacking IPs      │
                                                             │  - Incident Management    │
                                                             │  - SHAP Explainability    │
                                                             │  - PCAP Replay Controller │
                                                             │  - Authorized Nmap Demo   │
                                                             └───────────────────────────┘
```

---

## 4. Regression Risks & Mitigation Strategy

| Risk | Potential Impact | Mitigation Strategy |
| :--- | :--- | :--- |
| **Database Corruption / Record Loss** | Loss of real PortScan evidence in `nids.db` | Use additive SQLAlchemy migrations (`_sqlite_add_column_if_missing` and `create_all`). NEVER drop or overwrite `nids.db`. |
| **Feature Schema Disruption** | Broken ML inference or validator errors | Keep `feature_schema.json` and 77 canonical features completely unchanged. |
| **Breaking Phase 1 APIs** | Failure of existing 95 tests | Preserve all existing endpoint signatures, request schemas, and response formats (`/predict`, `/health`, `/model`, `/models`, `/api/stats`, `/api/alerts`, `/api/flows`, `/api/capture/*`). |
| **Capture Latency Spikes from SHAP** | Delayed packet processing or dropped packets | Perform SHAP explanations asynchronously or on-demand upon analyst alert query. live inference pipeline computes fast ML prediction + heuristic verdict. |
| **Unsafe Nmap Execution** | Arbitrary command injection or unauthorized network scans | Strict IP validation (RFC1918 + loopback only), no shell execution (`shell=False`), parameterized argument list, strict timeouts. |
| **PCAP Replay Packet Leakage** | Transmitting synthetic attack packets onto production LAN | PCAP Replay reads directly via Scapy `PcapReader` in memory into `FlowAggregator` without calling any `sendp()` or socket transmit routines. |

---

## 5. Implementation Roadmap (Phase 2.1 – 2.7)

1. **Phase 2.1:** Real-Time Event Hub & Dashboard Modernization (WebSocket broadcasting + resilient polling fallback).
2. **Phase 2.2:** Attack Timeline (`/api/timeline`) & Top Attacking IP Analytics (`/api/analytics/top-attackers`).
3. **Phase 2.3:** Incident Management Schema, Migrations, APIs (`/api/incidents*`), and SOC Triage Workflow.
4. **Phase 2.4:** On-Demand SHAP Explanation Engine (`/api/predictions/{id}/explanation`, `/api/alerts/{id}/explanation`) and Interactive Visualizer.
5. **Phase 2.5:** Offline PCAP Replay Service (`services/feature_extractor/pcap_replay.py`), Replay APIs, and UI Controls.
6. **Phase 2.6:** Authorized Controlled Nmap Demonstration Engine (`services/demo/nmap_demo.py`), Safety Guardrails, and End-to-End Verification.
7. **Phase 2.7:** Regression Testing (Pass all 95 Phase 1 tests + comprehensive Phase 2 suite) and Final Production Documentation.
