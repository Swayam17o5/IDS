# Controlled Authorized Nmap Demonstration & Lab Safety Architecture

## 1. Overview
AegisNIDS includes a controlled demonstration module that allows security researchers and system administrators to validate end-to-end intrusion detection against real authorized network traffic in a sandbox or private laboratory environment.

---

## 2. Strict Safety & Guardrail Enforcement

To ensure AegisNIDS cannot be misused as an arbitrary scanning or attack utility:

1. **Strict Target Validation:**
   - Targets MUST be either loopback (`127.0.0.1`, `localhost`) or private RFC1918 IPv4 address ranges (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`).
   - Any public or external IP (e.g. `8.8.8.8`, `example.com`, `142.250.x.x`) is **immediately rejected with HTTP 400**.
2. **Zero Arbitrary Shell Injection:**
   - Shell commands are never constructed from raw user strings.
   - All port lists and scan types are rigorously parsed, validated against integer bounds (`1-65535`), and passed as strict argv lists to `subprocess.Popen`.
3. **Execution Timeouts:**
   - All scan executions are hard-limited to a configurable timeout (default 25 seconds).
4. **Dual Engine Execution:**
   - Runs portable native `nmap.exe` when present; falls back to an integrated raw Python Scapy TCP SYN scanner (`tools/nmap_scan.py`) ensuring 100% reliable packet emission across any test machine.

---

## 3. Demonstration End-to-End Workflow

```
[Start Controlled Demo: Target 192.168.1.1 / Ports 21-8443]
                          ↓
[Nmap / Scapy Emits TCP SYN Probes Across Wire]
                          ↓
[LiveCaptureService Captures Frames via Npcap / Raw Socket]
                          ↓
[FlowAggregator Groups Packets into Bi-Directional 5-Tuples]
                          ↓
[PCAPFeatureExtractor Computes 77 CICIDS2017 Statistical Metrics]
                          ↓
[ML Inference Evaluates Features (PortScan Prob > 80%)]
                          ↓
[SYN-Burst Heuristic Identifies Rapid Multi-Port Sweep]
                          ↓
[Dual-Signal Engine Emits Verified PortScan Verdict]
                          ↓
[Alert Engine Deduplicates and Persists Alert to SQLite nids.db]
                          ↓
[WebSocket Broadcast Dispatches Alert to SOC Dashboard]
                          ↓
[Attack Timeline & Top Attacker Rankings Update in Real Time]
                          ↓
[Security Analyst Triages & Creates Incident INC-...]
```

---

## 4. API Endpoints

### 4.1 Launch Controlled Demo
`POST /api/demo/nmap/start`
```json
{
  "target": "192.168.1.1",
  "ports": "21,22,23,53,80,443,8080,8443",
  "scan_type": "syn",
  "timeout_seconds": 25
}
```

### 4.2 Status & Live Output Logs
`GET /api/demo/nmap/status`
```json
{
  "is_running": false,
  "status": "COMPLETED",
  "demo_id": "DEMO-1727889500",
  "target": "192.168.1.1",
  "scan_type": "syn",
  "duration_seconds": 3.42,
  "verification": {
    "flows_generated": 35,
    "predictions_generated": 35,
    "portscan_predictions": 3,
    "alerts_persisted": 1,
    "total_db_flows": 164,
    "total_db_alerts": 112
  }
}
```
