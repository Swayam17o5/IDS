"""
tests/test_phase2_soc_features.py
-----------------------------------
Comprehensive test suite for Phase 2 SOC features in AegisNIDS:
  1. Real-Time SOC Telemetry & Dashboard Stats (/api/stats, rates, counts)
  2. Attack Timeline with Time-Range & Attribute Filtering (/api/timeline)
  3. Top Attacking IP Analytics (/api/analytics/top-attackers)
  4. Incident Management Workflow (/api/incidents, /api/incidents/{id}, /api/incidents/{id}/alerts, /api/incidents/{id}/notes)
  5. SHAP Local Explanations & Plain-English Rationale (/api/predictions/{id}/explanation, /api/alerts/{id}/explanation)
  6. Offline PCAP Replay Pipeline & Audit History (/api/replay/*)
  7. Controlled Nmap PortScan Demonstration Guardrails (/api/demo/nmap/*)
"""

import os
import json
import time
import pytest
from fastapi.testclient import TestClient
from services.inference.app import app, init_models
from database.db import SessionLocal, init_db
from database.models import DBAlert, DBFlow, DBPrediction, DBIncident, DBIncidentAlert, DBIncidentNote, DBPCAPReplay
from services.demo.nmap_demo import is_authorized_lab_target, validate_port_spec

@pytest.fixture(scope="module")
def client():
    init_db()
    init_models("cicids2017")
    return TestClient(app)

@pytest.fixture(scope="module")
def canonical_features():
    with open("models/cicids2017/feature_list.json") as f:
        return json.load(f)

# ─── 1. REAL-TIME DASHBOARD TELEMETRY TESTS ─────────────────────────────────

class TestRealTimeDashboardStats:
    def test_stats_contains_phase2_metrics(self, client):
        """Verifies /api/stats includes rates, attack counts, active model, and detection rate."""
        res = client.get("/api/stats")
        assert res.status_code == 200
        data = res.json()
        assert "packets_captured" in data
        assert "active_flows" in data
        assert "total_flows_processed" in data
        assert "total_predictions" in data
        assert "total_alerts" in data
        assert "flows_per_minute" in data
        assert "predictions_per_minute" in data
        assert "alerts_per_minute" in data
        assert "portscan_count" in data
        assert "benign_count" in data
        assert "attack_count" in data
        assert "detection_rate" in data
        assert "recent_confidences" in data
        assert isinstance(data["recent_confidences"], list)
        assert data["database_status"] == "CONNECTED"

    def test_dashboard_html_serves_ok(self, client):
        """Verifies GET / returns 200 with complete SOC HTML interface."""
        res = client.get("/")
        assert res.status_code == 200
        assert "text/html" in res.headers["content-type"]
        assert "AegisNIDS" in res.text
        assert "Security Operations Center" in res.text

# ─── 2. ATTACK TIMELINE TESTS ──────────────────────────────────────────────

class TestAttackTimeline:
    def test_timeline_endpoint_default(self, client):
        """Tests /api/timeline returns list of chronological security events."""
        res = client.get("/api/timeline")
        assert res.status_code == 200
        data = res.json()
        assert "events" in data
        assert "total_events" in data
        assert isinstance(data["events"], list)
        for ev in data["events"]:
            assert "alert_id" in ev
            assert "timestamp" in ev
            assert "attack_type" in ev
            assert "severity" in ev
            assert "confidence" in ev
            assert "src_ip" in ev
            assert "dst_ip" in ev
            assert "detection_method" in ev

    def test_timeline_filtering_by_severity(self, client):
        """Tests filtering timeline by severity."""
        res = client.get("/api/timeline?severity=MEDIUM")
        assert res.status_code == 200
        data = res.json()
        for ev in data["events"]:
            assert ev["severity"].upper() == "MEDIUM"

    def test_timeline_filtering_by_attack_type(self, client):
        """Tests filtering timeline by attack type."""
        res = client.get("/api/timeline?attack_type=PortScan")
        assert res.status_code == 200
        data = res.json()
        for ev in data["events"]:
            assert ev["attack_type"] == "PortScan"

    def test_timeline_filtering_by_time_range(self, client):
        """Tests preset time ranges (5m, 15m, 1h, 24h, all)."""
        for r in ["5m", "15m", "1h", "24h", "all"]:
            res = client.get(f"/api/timeline?time_range={r}")
            assert res.status_code == 200
            assert "events" in res.json()

# ─── 3. TOP ATTACKING IP ANALYTICS TESTS ────────────────────────────────────

class TestTopAttackingIPs:
    def test_top_attackers_endpoint(self, client):
        """Tests /api/analytics/top-attackers calculates accurate metrics per attacking IP."""
        res = client.get("/api/analytics/top-attackers?limit=10")
        assert res.status_code == 200
        data = res.json()
        assert "attackers" in data
        assert "total_attackers" in data
        assert isinstance(data["attackers"], list)
        for att in data["attackers"]:
            assert "src_ip" in att
            assert "alerts" in att
            assert "affected_destinations" in att
            assert "attack_types_count" in att
            assert "most_common_attack" in att
            assert "highest_severity" in att
            assert "first_seen" in att
            assert "last_seen" in att
            assert att["alerts"] >= 1

# ─── 4. INCIDENT MANAGEMENT WORKFLOW TESTS ─────────────────────────────────

class TestIncidentManagementWorkflow:
    def test_create_and_manage_incident_lifecycle(self, client):
        """
        Tests the full lifecycle of an incident ticket:
        1. Create incident with custom title, severity, analyst notes
        2. Verify initial status is NEW
        3. Transition to ACKNOWLEDGED
        4. Transition to INVESTIGATING
        5. Append analyst notes to timeline
        6. Attach alert ID to the incident
        7. Transition to RESOLVED with resolution reason
        8. Verify audit timestamps & integrity
        """
        # 1. Create Incident
        payload = {
            "title": "Lab PortScan Investigation",
            "severity": "MEDIUM",
            "attack_type": "PortScan",
            "src_ip": "192.168.1.40",
            "dst_ip": "192.168.1.1",
            "assigned_analyst": "SOC Lead",
            "notes": "Initiated investigation based on multiple TCP SYN probes"
        }
        res_create = client.post("/api/incidents", json=payload)
        assert res_create.status_code == 200
        create_data = res_create.json()
        assert create_data["status"] == "success"
        inc_id = create_data["incident_id"]
        assert inc_id.startswith("INC-")

        # 2. Verify Created Incident Detail
        res_detail = client.get(f"/api/incidents/{inc_id}")
        assert res_detail.status_code == 200
        inc_data = res_detail.json()
        assert inc_data["incident_id"] == inc_id
        assert inc_data["status"] == "NEW"
        assert inc_data["severity"] == "MEDIUM"
        assert inc_data["assigned_analyst"] == "SOC Lead"
        assert len(inc_data["notes"]) == 1
        assert "Initiated investigation" in inc_data["notes"][0]["note"]

        # 3. Transition to ACKNOWLEDGED
        res_ack = client.patch(f"/api/incidents/{inc_id}", json={"status": "ACKNOWLEDGED"})
        assert res_ack.status_code == 200
        assert res_ack.json()["current_status"] == "ACKNOWLEDGED"

        # 4. Transition to INVESTIGATING & Add Note
        res_inv = client.patch(f"/api/incidents/{inc_id}", json={
            "status": "INVESTIGATING",
            "notes": "Cross-referenced firewall drop logs; source IP confirmed internal lab host."
        })
        assert res_inv.status_code == 200
        assert res_inv.json()["current_status"] == "INVESTIGATING"

        # 5. Add direct note via dedicated endpoint
        res_note = client.post(f"/api/incidents/{inc_id}/notes", json={
            "author": "SOC Analyst 2",
            "note": "Host administrator contacted. Scanner activity validated."
        })
        assert res_note.status_code == 200
        assert "note_id" in res_note.json()

        # 6. Attach Alert to Incident
        db = SessionLocal()
        first_alert = db.query(DBAlert).first()
        db.close()
        if first_alert:
            res_attach = client.post(f"/api/incidents/{inc_id}/alerts", json={
                "alert_ids": [first_alert.alert_id]
            })
            assert res_attach.status_code == 200
            assert res_attach.json()["alerts_attached"] == 1

        # 7. Transition to RESOLVED
        res_res = client.patch(f"/api/incidents/{inc_id}", json={
            "status": "RESOLVED",
            "resolution_reason": "Scheduled penetration testing exercise concluded."
        })
        assert res_res.status_code == 200
        assert res_res.json()["current_status"] == "RESOLVED"

        # 8. Verify final incident state
        res_final = client.get(f"/api/incidents/{inc_id}")
        assert res_final.status_code == 200
        final_data = res_final.json()
        assert final_data["status"] == "RESOLVED"
        assert final_data["resolved_at"] is not None
        assert final_data["resolution_reason"] == "Scheduled penetration testing exercise concluded."
        assert len(final_data["notes"]) == 3

    def test_invalid_incident_status_transition_rejected(self, client):
        """Verifies rejected transition for invalid status strings."""
        res_create = client.post("/api/incidents", json={"title": "Status Test"})
        inc_id = res_create.json()["incident_id"]
        res_patch = client.patch(f"/api/incidents/{inc_id}", json={"status": "INVALID_STATUS"})
        assert res_patch.status_code == 400
        assert "Invalid status" in res_patch.json()["detail"]

# ─── 5. SHAP EXPLANATION TESTS ──────────────────────────────────────────────

class TestSHAPExplanations:
    def test_alert_explanation_endpoint(self, client):
        """Verifies /api/alerts/{id}/explanation returns stored feature attributions & rationale."""
        db = SessionLocal()
        alert = db.query(DBAlert).first()
        db.close()
        if alert:
            res = client.get(f"/api/alerts/{alert.alert_id}/explanation")
            assert res.status_code == 200
            data = res.json()
            assert data["alert_id"] == alert.alert_id
            assert "attack_type" in data
            assert "features" in data
            assert isinstance(data["features"], list)
            assert "explanation" in data

    def test_prediction_explanation_endpoint(self, client):
        """Verifies /api/predictions/{id}/explanation returns computed SHAP features and plain-English text."""
        db = SessionLocal()
        pred = db.query(DBPrediction).first()
        db.close()
        if pred:
            res = client.get(f"/api/predictions/{pred.id}/explanation")
            assert res.status_code == 200
            data = res.json()
            assert data["prediction_id"] == pred.id
            assert "label" in data
            assert "confidence" in data
            assert "features" in data
            assert "plain_explanation" in data

# ─── 6. PCAP REPLAY TESTS ──────────────────────────────────────────────────

class TestPCAPReplay:
    def test_generate_synthetic_pcap(self, client):
        """Tests creation of synthetic multi-stage attack PCAP in scratch directory."""
        res = client.post("/api/replay/generate_synthetic")
        assert res.status_code == 200
        data = res.json()
        assert data["status"] == "success"
        assert os.path.exists(data["pcap_path"])

    def test_replay_nonexistent_file_rejected(self, client):
        """Tests that invalid PCAP file paths return 400."""
        res = client.post("/api/replay/start", json={"pcap_path": "nonexistent_file_12345.pcap"})
        assert res.status_code == 400
        assert "does not exist" in res.json()["detail"].lower()

    def test_replay_status_and_history(self, client):
        """Tests GET /api/replay/status and /api/replay/history."""
        res_status = client.get("/api/replay/status")
        assert res_status.status_code == 200
        status_data = res_status.json()
        assert "is_replaying" in status_data
        assert "packets_processed" in status_data

        res_hist = client.get("/api/replay/history")
        assert res_hist.status_code == 200
        assert isinstance(res_hist.json(), list)

# ─── 7. CONTROLLED NMAP DEMONSTRATION TESTS ─────────────────────────────────

class TestNmapDemonstrationGuardrails:
    def test_authorized_lab_target_validation(self):
        """Verifies IP validator strictly allows loopback & RFC1918 private subnets and rejects external/public IPs."""
        valid, _ = is_authorized_lab_target("127.0.0.1")
        assert valid is True
        valid, _ = is_authorized_lab_target("192.168.1.1")
        assert valid is True
        valid, _ = is_authorized_lab_target("10.0.0.5")
        assert valid is True
        valid, _ = is_authorized_lab_target("172.16.0.1")
        assert valid is True
        valid, _ = is_authorized_lab_target("localhost")
        assert valid is True

        # Reject public IPs
        valid, _ = is_authorized_lab_target("8.8.8.8")
        assert valid is False
        valid, _ = is_authorized_lab_target("1.1.1.1")
        assert valid is False
        valid, _ = is_authorized_lab_target("example.com")
        assert valid is False
        valid, _ = is_authorized_lab_target("142.250.190.46")
        assert valid is False

    def test_port_spec_validation(self):
        """Verifies port range & comma-delimited port specification validator."""
        valid, _, _ = validate_port_spec("80,443,8080")
        assert valid is True

        valid, _, _ = validate_port_spec("1-1024")
        assert valid is True

        valid, err, _ = validate_port_spec("70000")
        assert valid is False
        assert "out of" in err.lower() or "bounds" in err.lower()

        valid, _, _ = validate_port_spec("abc; rm -rf /")
        assert valid is False

    def test_nmap_demo_rejects_unauthorized_external_target(self, client):
        """Verifies /api/demo/nmap/start rejects requests targeting public IPs."""
        res = client.post("/api/demo/nmap/start", json={
            "target": "8.8.8.8",
            "ports": "80,443"
        })
        assert res.status_code == 400
        assert "restricted" in res.json()["detail"].lower() or "unauthorized" in res.json()["detail"].lower()

    def test_nmap_demo_status_endpoint(self, client):
        """Verifies GET /api/demo/nmap/status returns execution metadata."""
        res = client.get("/api/demo/nmap/status")
        assert res.status_code == 200
        data = res.json()
        assert "is_running" in data
        assert "status" in data
        assert "verification" in data
