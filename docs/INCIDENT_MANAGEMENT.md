# Incident Management Workflow & Architecture

## 1. Overview
AegisNIDS Phase 2 elevates atomic alerts into cohesive, actionable **Security Incident Tickets**. This enables security analysts to triage related threats, document investigative findings, assign ownership, track remediation status, and maintain immutable audit histories without deleting underlying security alerts.

---

## 2. Incident State Machine

```
   [ NEW ]
      ↓  (Analyst Acknowledges Threat)
[ ACKNOWLEDGED ]
      ↓  (Investigation Commences / Evidence Collected)
[ INVESTIGATING ]
      ↓
 ┌────┴──────────────────────────┐
 ↓                               ↓
[ RESOLVED ]           [ FALSE_POSITIVE ]
(Incident Remediated)  (Benign Activity / Scanner Logged)
```

### State Definitions
- **`NEW`:** Automated detection created from alert triggers. Awaiting triage.
- **`ACKNOWLEDGED`:** An analyst has claimed the ticket and is reviewing indicators of compromise (IoCs).
- **`INVESTIGATING`:** Active threat hunting, host forensics, and packet payload inspection in progress.
- **`RESOLVED`:** Remediation complete (e.g. firewall rule added, malicious process terminated).
- **`FALSE_POSITIVE`:** Legitimate authorized network activity (e.g. scheduled vulnerability audit).

---

## 3. Data Model & Relationships

```
┌─────────────────────────────────────────┐
│               DBIncident                │
│-----------------------------------------│
│ id: Integer (PK)                        │
│ incident_id: String(64) [INC-...] (UQ)  │
│ title: String(255)                      │
│ status: String(32)                      │
│ severity: String(32)                    │
│ attack_type: String(64)                 │
│ src_ip / dst_ip: String(64)             │
│ assigned_analyst: String(128)           │
│ resolution_reason: Text                 │
│ created_at / updated_at / resolved_at   │
└────────────────────┬────────────────────┘
                     │ 1:N
     ┌───────────────┴───────────────┐
     ▼                               ▼
┌──────────────────────┐  ┌──────────────────────┐
│   DBIncidentAlert    │  │    DBIncidentNote    │
│----------------------│  │----------------------│
│ incident_id          │  │ incident_id          │
│ alert_id (FK DBAlert)│  │ author               │
│ added_at             │  │ note: Text           │
└──────────────────────┘  │ created_at           │
                          └──────────────────────┘
```

---

## 4. Incident Management REST APIs

### 4.1 Create Incident
`POST /api/incidents`
```json
{
  "title": "PortScan Surge on DMZ Subnet",
  "severity": "MEDIUM",
  "attack_type": "PortScan",
  "src_ip": "192.168.1.40",
  "dst_ip": "192.168.1.1",
  "assigned_analyst": "SOC Lead",
  "notes": "Correlated across 35 port probes.",
  "alert_ids": ["ALT-20261002-155012-A1B2"]
}
```

### 4.2 State Transitions & Updates
`PATCH /api/incidents/{incident_id}`
```json
{
  "status": "RESOLVED",
  "resolution_reason": "Host 192.168.1.40 isolated at switch port; vulnerability scan completed."
}
```

### 4.3 Append Analyst Note
`POST /api/incidents/{incident_id}/notes`
```json
{
  "author": "Analyst Alpha",
  "note": "Firewall logs confirm SYN packets dropped on port 445."
}
```

### 4.4 Associate Additional Alerts
`POST /api/incidents/{incident_id}/alerts`
```json
{
  "alert_ids": ["ALT-20261002-155100-C3D4", "ALT-20261002-155105-E5F6"]
}
```
