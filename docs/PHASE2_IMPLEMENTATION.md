# AegisNIDS — Phase 2 Architecture & Implementation Specification

## 1. Executive Summary
**AegisNIDS Phase 2** upgrades the foundational machine learning intrusion detection pipeline developed in Phase 1 into a full-scale, operational Security Operations Center (SOC) platform. Building upon the verified 77-feature extraction engine and the dual-signal inference architecture (ML + SYN-Burst Heuristics), Phase 2 introduces:

1. **Real-Time SOC Monitoring & WebSocket Telemetry**
2. **Dynamic Attack Timeline with Granular Filtering**
3. **Top Attacking IPs Threat Analytics**
4. **End-to-End Security Incident Lifecycle Management**
5. **Scientifically Grounded SHAP Explanations & Plain-English Rationale**
6. **Offline Isolated PCAP Replay Engine with Progress Auditing**
7. **Controlled & Authorized Nmap PortScan Demonstration Guardrails**

---

## 2. Real-Time Event Architecture & Pipeline Dataflow

```
   Raw Wire Traffic / Replay PCAP
                ↓
    [LiveCaptureService / PCAPReplayService]
                ↓
    [FlowAggregator (Bi-Directional Trackers)]
                ↓
    [PCAPFeatureExtractor (77 Canonical Features)]
                ↓
    [FeatureValidator (Schema & Numerical Range)]
                ↓
    [Deep Learning & Ensemble Models (CICIDS2017)]
                ↓
    [Dual-Signal Verdict (ML + SYN-Burst Heuristic)]
                ↓
    [Alert Engine (Confidence Threshold & 120s Dedup)]
                ↓
    [Database Persistence (SQLite nids.db)]
          ↙           ↘
 [WebSocket Broadcast]    [REST API Hub]
          ↓                   ↓
  [Real-Time SOC Dashboard & Timeline]
```

### Event Chain Guarantees
- **Single Source of Truth:** All live dashboard metrics, timeline events, and attacker aggregations are derived from SQLite (`nids.db`) with zero fabricated demo values.
- **WebSocket Streaming:** Real-time push notifications over `/ws/live` and `/ws/alerts` for zero-polling instant incident discovery.
- **Deduplication:** Repeated bursts of attack packets within a 120-second rolling window are consolidated into a single alert ticket, updating flow counts and timestamps.

---

## 3. Database Schema Extensions

The existing Phase 1 database schema (`flows`, `predictions`, `alerts`, `model_cards`, `analyst_feedback`) was preserved and extended without data loss:

| Table | Description | Key Fields |
|---|---|---|
| `incidents` | Core incident ticket record | `id`, `incident_id`, `title`, `status`, `severity`, `attack_type`, `src_ip`, `dst_ip`, `assigned_analyst`, `resolution_reason`, `created_at`, `updated_at`, `resolved_at` |
| `incident_alerts` | Association table linking alerts to incidents | `id`, `incident_id`, `alert_id`, `added_at` |
| `incident_notes` | Chronological analyst audit log | `id`, `incident_id`, `author`, `note`, `created_at` |
| `pcap_replays` | Historical PCAP replay audit record | `id`, `replay_id`, `filename`, `status`, `packets_processed`, `flows_generated`, `predictions_generated`, `alerts_generated`, `duration_seconds`, `started_at`, `completed_at` |
| `alerts` *(extended)* | Added foreign reference | `incident_id` (Nullable string referencing `incidents.incident_id`) |

---

## 4. Operational Modules & API Endpoints

### 4.1 Telemetry & Analytics
- `GET /api/stats` — Real-time telemetry, packet counters, active flows, rates per minute (flows, predictions, alerts), PortScan vs. Benign breakdown, and detection rates.
- `GET /api/timeline` — Chronological security alerts with filters for `time_range` (`5m`, `15m`, `1h`, `24h`, `all`), `severity`, `attack_type`, and `src_ip`.
- `GET /api/analytics/top-attackers` — Threat ranking by alert frequency, unique targeted destinations, attack variety, and activity timestamps.

### 4.2 Incident Management
- `GET /api/incidents` — List active/resolved incidents with filtering.
- `GET /api/incidents/{id}` — Full incident view with linked alert objects and timeline notes.
- `POST /api/incidents` — Create new incident ticket and optionally associate alerts.
- `PATCH /api/incidents/{id}` — State transitions (`NEW` → `ACKNOWLEDGED` → `INVESTIGATING` → `RESOLVED` / `FALSE_POSITIVE`).
- `POST /api/incidents/{id}/alerts` — Link additional alerts.
- `POST /api/incidents/{id}/notes` — Append analyst investigation findings.

### 4.3 Model Explainability (SHAP)
- `GET /api/predictions/{id}/explanation` — Computes or retrieves exact SHAP contributions, signs (`positive`/`negative`), and plain-English summaries.
- `GET /api/alerts/{id}/explanation` — Retrieves stored feature importance from detection time.

### 4.4 Offline PCAP Replay
- `POST /api/replay/start` — Validates file existence and streams flows offline into the detection engine without transmitting wire packets.
- `POST /api/replay/stop` — Safely aborts active replay sessions.
- `GET /api/replay/status` — Live telemetry on processing rate and generated events.
- `GET /api/replay/history` — Audit log of historical PCAP tests.
- `POST /api/replay/generate_synthetic` — Instant generation of multi-stage security scenario PCAPs.

### 4.5 Controlled Authorized Nmap Demonstration
- `POST /api/demo/nmap/start` — Safe execution against verified lab targets (loopback `127.0.0.1` and RFC1918 private subnets only; external public targets strictly forbidden).
- `GET /api/demo/nmap/status` — Real-time execution logs and database delta verification.

---

## 5. Summary Status
- **Phase 1 Baseline:** 100% OPERATIONAL & VERIFIED (95/95 tests passing).
- **Phase 2 Expansion:** 100% OPERATIONAL & TESTED (18/18 Phase 2 tests passing, 113/113 total test suite passing).
- **Zero Mock / Demo Code in Detection Path:** All metrics and detections derive directly from ML models, packet parsers, and SQLite tables.
