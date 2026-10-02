# Real-Time SOC Intrusion Detection Dashboard

## 1. Overview
The AegisNIDS Real-Time Security Operations Center (SOC) dashboard serves as the central command console for security analysts. It streams wire-level packet captures, flow extractions, machine learning classifications, alerts, incidents, timeline visualizations, and explainability attributions without requiring page reloads.

---

## 2. Dashboard Layout & Visual Design

```
+-------------------------------------------------------------------------------+
|  AEGIS // Security Operations Center                     [Live WS: Connected] |
|  Capture: [ACTIVE]  |  Model: [Stacking Ensemble]  |  DB: [SQLite Persisted]  |
+-------------------------------------------------------------------------------+
| SYSTEM OVERVIEW                                                               |
| [Packets] 12,450  | [Flows] 164  | [Alerts] 112  | [Rate] 42/min  | [Det] 68%  |
+-------------------------------------------------------------------------------+
| [LIVE SOC TABS]:                                                              |
| (1) Real-Time Stream  (2) Attack Timeline  (3) Top Attackers  (4) Incidents   |
| (5) PCAP Replay       (6) Authorized Nmap Demo  (7) Models & SHAP             |
+-------------------------------------------------------------------------------+
| LIVE SECURITY ALERTS STREAM               | LIVE 77-FEATURE FLOW STREAM       |
| Time | Sev | Attack | Src | Dst | Action  | Flow | Pkts | Bytes | Verdict     |
| 15:50| MED | PortScan | 192.168.1.40...   | 192.168.1.40:5342->192.168.1.1:80 |
+-------------------------------------------------------------------------------+
| SHAP EXPLAINABILITY INSPECTOR (Top Discriminating Features & Rationale)      |
| [Init Fwd Win Bytes: 1024] ==============================> Impact: +1.017     |
| [SYN Flag Count: 1]        ==================> Impact: +0.477                 |
+-------------------------------------------------------------------------------+
```

---

## 3. Real-Time Telemetry & WebSocket Event Bus

### Endpoints
- **WebSocket URL:** `ws://localhost:8000/ws/live` and `ws://localhost:8000/ws/alerts`
- **REST Telemetry Fallback:** `GET /api/stats` (polled periodically as fallback)

### Broadcast Events
1. `type: "alert"` — Dispatched immediately when `AlertEngine` evaluates a positive detection.
```json
{
  "type": "alert",
  "data": {
    "alert_id": "ALT-20261002-155012-A1B2",
    "timestamp": "2026-10-02T15:50:12.345Z",
    "severity": "MEDIUM",
    "attack_type": "PortScan",
    "confidence": 0.8539,
    "src_ip": "192.168.1.40",
    "dst_ip": "192.168.1.1",
    "src_port": 49152,
    "dst_port": 80,
    "detection_method": "SYN_BURST_HEURISTIC",
    "model_used": "weighted_voting_ensemble",
    "status": "NEW"
  }
}
```
2. `type: "flow"` — Emitted for every completed bidirectional flow with extracted duration, packet count, and ML verdict.

---

## 4. Live Metrics Derivation
All displayed counters are strictly backed by SQLite database records:
- **Flows / Minute:** Count of `DBFlow` rows within the rolling 60-second window.
- **Predictions / Minute:** Count of `DBPrediction` rows within the rolling 60-second window.
- **Alerts / Minute:** Count of non-false-positive `DBAlert` rows within the rolling 60-second window.
- **Detection Rate:** Calculated as `(Total Attacks / Total Predictions) * 100%`.
- **Recent Confidences:** Last 10 classification confidence values plotted dynamically.
