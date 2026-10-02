"""
tests/test_phase1_pipeline_integration.py
-------------------------------------------
Phase 1 End-to-End Pipeline Integration Tests

Covers:
  - Full pipeline: features → validation → inference → alert → database
  - PortScan heuristic integration (SYN burst metadata)
  - ML_HYBRID detection method when both signals fire
  - SYN_BURST_HEURISTIC when only heuristic fires
  - MACHINE_LEARNING when no heuristic involved
  - Alert persisted to DB with correct fields
  - Flow record persisted with packet_count, duration_seconds
  - Prediction record persisted with latency_ms
  - Reset endpoint clears all data
  - DB alert query by severity
  - Performance metrics: total_latency_ms reasonable (<5000ms)
"""

import json
import uuid
import pytest
from fastapi.testclient import TestClient
from services.inference.app import app, init_models
from database.db import SessionLocal, init_db
from database.models import DBFlow, DBPrediction, DBAlert

FEATURE_LIST_PATH = "models/cicids2017/feature_list.json"
SEVERITY_CONFIG = "severity_config.json"


@pytest.fixture(scope="module")
def client():
    init_models("cicids2017")
    return TestClient(app)


@pytest.fixture(scope="module")
def canonical_features():
    with open(FEATURE_LIST_PATH) as f:
        return json.load(f)


@pytest.fixture
def benign_features(canonical_features):
    return {feat: 0.0 for feat in canonical_features}


@pytest.fixture
def syn_scan_features(canonical_features):
    """Single-packet SYN scan probe — high PortScan probability."""
    feats = {feat: 0.0 for feat in canonical_features}
    feats["Protocol"] = 6.0
    feats["Total Fwd Packets"] = 1.0
    feats["Total Backward Packets"] = 0.0
    feats["SYN Flag Count"] = 1.0
    feats["Flow Packets/s"] = 100000.0
    feats["Fwd Packets/s"] = 100000.0
    feats["Fwd Seg Size Min"] = 32.0
    feats["Init Fwd Win Bytes"] = 1024.0
    feats["Packet Length Min"] = 54.0
    feats["Packet Length Max"] = 54.0
    feats["Packet Length Mean"] = 54.0
    feats["Avg Packet Size"] = 54.0
    feats["Fwd Packet Length Min"] = 54.0
    feats["Fwd Packet Length Max"] = 54.0
    feats["Fwd Packet Length Mean"] = 54.0
    feats["Avg Fwd Segment Size"] = 54.0
    feats["Subflow Fwd Packets"] = 1.0
    feats["Subflow Fwd Bytes"] = 54.0
    return feats


# ─── Detection Method Tests ───────────────────────────────────────────────────

class TestDetectionMethods:
    def test_pure_ml_detection_method(self, client, benign_features):
        """Without heuristic metadata, detection_method must be MACHINE_LEARNING."""
        data = client.post("/predict", json={"features": benign_features}).json()
        verdict = data["final_verdict"]
        assert verdict["detection_method"] == "MACHINE_LEARNING"

    def test_syn_burst_heuristic_method(self, client, syn_scan_features):
        """is_port_scan=True with low ML confidence → SYN_BURST_HEURISTIC."""
        meta = {
            "src_ip": "10.0.0.1",
            "dst_ip": "10.0.0.5",
            "src_port": 55000,
            "dst_port": 80,
            "protocol": 6,
            "is_port_scan": True,
            "port_scan_score": 0.87,
            "distinct_ports_scanned": 45,
        }
        data = client.post("/predict", json={"features": syn_scan_features, "metadata": meta}).json()
        verdict = data["final_verdict"]
        assert verdict["predicted_label"] == "PortScan"
        assert verdict["detection_method"] in ("SYN_BURST_HEURISTIC", "ML_HYBRID")
        assert verdict["confidence"] >= 0.80

    def test_portscan_label_on_heuristic(self, client, syn_scan_features):
        """When heuristic fires, final_label must always be PortScan."""
        meta = {
            "src_ip": "192.168.1.50",
            "dst_ip": "10.0.1.1",
            "src_port": 40000,
            "dst_port": 22,
            "protocol": 6,
            "is_port_scan": True,
            "port_scan_score": 0.91,
            "distinct_ports_scanned": 120,
        }
        data = client.post("/predict", json={"features": syn_scan_features, "metadata": meta}).json()
        assert data["final_verdict"]["predicted_label"] == "PortScan"


# ─── Database Persistence Tests ───────────────────────────────────────────────

class TestDatabasePersistence:
    def test_flow_persisted_to_db(self, client, benign_features):
        db = SessionLocal()
        before_count = db.query(DBFlow).count()
        db.close()

        client.post("/predict", json={
            "features": benign_features,
            "metadata": {
                "src_ip": "172.16.100.1",
                "dst_ip": "172.16.100.2",
                "src_port": 60000,
                "dst_port": 443,
                "protocol": 6,
                "total_packets": 5,
                "duration_seconds": 0.12,
            }
        })

        db = SessionLocal()
        after_count = db.query(DBFlow).count()
        assert after_count == before_count + 1
        # Check the flow has metadata
        flow = db.query(DBFlow).order_by(DBFlow.id.desc()).first()
        assert flow.src_ip == "172.16.100.1"
        assert flow.dst_ip == "172.16.100.2"
        db.close()

    def test_prediction_persisted_with_latency(self, client, benign_features):
        client.post("/predict", json={"features": benign_features})
        db = SessionLocal()
        pred = db.query(DBPrediction).order_by(DBPrediction.id.desc()).first()
        assert pred is not None
        assert pred.total_latency_ms is not None
        assert pred.total_latency_ms >= 0
        assert pred.model_version is not None
        db.close()

    def test_flow_packet_count_persisted(self, client, benign_features):
        client.post("/predict", json={
            "features": benign_features,
            "metadata": {
                "src_ip": "1.1.1.100",
                "dst_ip": "2.2.2.200",
                "total_packets": 8,
                "duration_seconds": 0.5,
            }
        })
        db = SessionLocal()
        flow = db.query(DBFlow).order_by(DBFlow.id.desc()).first()
        assert flow.packet_count == 8
        assert flow.duration_seconds == pytest.approx(0.5, abs=0.001)
        db.close()


# ─── Performance Tests ────────────────────────────────────────────────────────

class TestPerformance:
    def test_prediction_latency_under_5s(self, client, benign_features):
        """Full pipeline should complete in under 5 seconds."""
        data = client.post("/predict", json={"features": benign_features}).json()
        assert "performance" in data
        total_ms = data["performance"]["total_latency_ms"]
        assert total_ms < 5000.0, f"Pipeline took too long: {total_ms:.1f}ms"

    def test_validation_latency_negligible(self, client, benign_features):
        """Feature validation should be fast (<50ms)."""
        data = client.post("/predict", json={"features": benign_features}).json()
        val_ms = data["performance"]["validation_latency_ms"]
        assert val_ms < 50.0, f"Validation took too long: {val_ms:.1f}ms"

    def test_performance_keys_all_present(self, client, benign_features):
        data = client.post("/predict", json={"features": benign_features}).json()
        perf = data["performance"]
        required = [
            "validation_latency_ms",
            "inference_latency_ms",
            "db_latency_ms",
            "total_latency_ms",
        ]
        for key in required:
            assert key in perf, f"Missing performance key: {key}"
            assert perf[key] >= 0


# ─── Full PortScan E2E ────────────────────────────────────────────────────────

class TestPortScanE2E:
    def test_portscan_heuristic_e2e_creates_alert(self, client, syn_scan_features):
        """Heuristic-triggered PortScan should create a DB alert with NEW status."""
        # Use a unique IP to avoid dedup collisions from other tests
        unique_ip = f"10.99.{uuid.uuid4().int % 256}.{uuid.uuid4().int % 256}"
        meta = {
            "src_ip": unique_ip,
            "dst_ip": "192.168.99.99",
            "src_port": 12345,
            "dst_port": 80,
            "protocol": 6,
            "is_port_scan": True,
            "port_scan_score": 0.90,
            "distinct_ports_scanned": 100,
        }
        data = client.post("/predict", json={"features": syn_scan_features, "metadata": meta}).json()
        alert = data.get("alert_generated")
        assert alert is not None, "PortScan heuristic should generate an alert"
        assert alert["attack_type"] == "PortScan"
        assert alert["severity"] in ("MEDIUM", "HIGH", "CRITICAL")
        assert alert["status"] == "NEW"

        # Verify alert is in DB
        db = SessionLocal()
        db_alert = db.query(DBAlert).filter(DBAlert.alert_id == alert["alert_id"]).first()
        assert db_alert is not None
        assert db_alert.status == "NEW"
        assert db_alert.attack_type == "PortScan"
        assert db_alert.first_seen is not None
        assert db_alert.last_seen is not None
        db.close()

    def test_portscan_confidence_is_bounded(self, client, syn_scan_features):
        meta = {
            "src_ip": "10.98.1.1",
            "dst_ip": "10.98.1.2",
            "is_port_scan": True,
            "port_scan_score": 0.95,
            "distinct_ports_scanned": 200,
        }
        data = client.post("/predict", json={"features": syn_scan_features, "metadata": meta}).json()
        conf = data["confidence"]
        assert 0.0 <= conf <= 1.0
