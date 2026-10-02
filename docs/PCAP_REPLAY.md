# Offline PCAP Replay Pipeline & Testing Architecture

## 1. Overview
The **PCAP Replay Service** allows recorded packet captures to be replayed through the complete AegisNIDS feature extraction, validation, ML inference, and alert generation pipeline.

### Critical Safety Guarantee: Strict Offline Isolation
**PCAP replay strictly parses packets offline in-memory and NEVER transmits raw frames onto a physical or virtual network adapter.** No packets are injected into the kernel network stack or transmitted over physical wires during replay mode.

---

## 2. Replay Dataflow

```
   [Offline PCAP File]
           ↓
   [PcapReader Streaming (Memory-Safe Chunking)]
           ↓
   [FlowAggregator (Bi-Directional Trackers)]
           ↓
   [PCAPFeatureExtractor (77 CICIDS2017 Features)]
           ↓
   [FeatureValidator (Schema & Numerical Range)]
           ↓
   [Deep Learning & Ensemble Models]
           ↓
   [Dual-Signal Verdict (ML + SYN Burst)]
           ↓
   [Alert Engine & Deduplication]
           ↓
   [Database Persistence & WebSocket Broadcast]
           ↓
   [DBPCAPReplay Audit Log Entry]
```

---

## 3. PCAP Replay APIs

### 3.1 Start Replay
`POST /api/replay/start`
```json
{
  "pcap_path": "scratch/demo_attack_scenario.pcap",
  "delay": 0.01
}
```
**Response:**
```json
{
  "status": "started",
  "replay_id": "REPLAY-1727889123",
  "filename": "demo_attack_scenario.pcap",
  "total_packets": 37,
  "message": "Offline PCAP replay initiated successfully"
}
```

### 3.2 Stop Replay
`POST /api/replay/stop`

### 3.3 Replay Status & Telemetry
`GET /api/replay/status`
```json
{
  "is_replaying": false,
  "replay_id": "REPLAY-1727889123",
  "filename": "demo_attack_scenario.pcap",
  "packets_processed": 37,
  "total_packets": 37,
  "flows_generated": 10,
  "predictions_generated": 10,
  "alerts_generated": 2,
  "progress_pct": 100.0,
  "duration_seconds": 0.85
}
```

### 3.4 Replay History Audit
`GET /api/replay/history`
Returns historical records from the `pcap_replays` database table.

### 3.5 Generate Synthetic Attack PCAP
`POST /api/replay/generate_synthetic`
Creates a realistic multi-stage attack scenario PCAP in the `scratch/` directory for immediate offline testing.
