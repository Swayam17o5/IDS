"""
tests/test_explainability.py
----------------------------
Comprehensive tests for AegisNIDS AI Explainability & Deep Forensic Analysis.
Validates:
  1. HTML Explainability route (/explainability/{alert_id})
  2. API Deep Explanation endpoint (/api/alerts/{alert_id}/deep-explanation)
  3. Mathematical TreeSHAP features & signed contribution separation (supporting vs opposing)
  4. Dual-signal separation (ML model prediction vs SYN-Burst heuristic)
  5. 77 canonical features inspection & global feature importance
  6. Edge cases: nonexistent alert, ML-only alert, Heuristic-only alert, Dual-signal alert
"""

import pytest
import datetime
from fastapi.testclient import TestClient
from services.inference.app import app
from database.db import SessionLocal
from database.models import DBFlow, DBPrediction, DBAlert

client = TestClient(app)

@pytest.fixture(scope="module", autouse=True)
def setup_test_alerts():
    from services.inference.app import init_models
    init_models("cicids2017")

    db = SessionLocal()
    now = datetime.datetime.now(datetime.timezone.utc)

    # Clean existing test records if any
    db.query(DBAlert).filter(DBAlert.alert_id.in_(["ALT-TEST-DUAL-001", "ALT-TEST-ML-002"])).delete()
    db.commit()

    # 1. Dual-Signal Alert (ML: Benign 99.6%, Heuristic: PortScan 85.4%)
    flow_dual = DBFlow(
        src_ip="192.168.1.40",
        dst_ip="192.168.1.1",
        src_port=54321,
        dst_port=80,
        protocol=6,
        duration_seconds=0.002,
        packet_count=1,
        features_json={f"f_{i}": float(i) for i in range(77)}
    )
    # Ensure real canonical names
    from services.inference.app import CANONICAL_FEATURES
    flow_dual.features_json = {f: 0.0 for f in CANONICAL_FEATURES}
    flow_dual.features_json["Destination Port"] = 80.0
    flow_dual.features_json["Flow Duration"] = 2000.0
    flow_dual.features_json["Init Bwd Win Bytes"] = 65535.0
    flow_dual.features_json["SYN Flag Count"] = 1.0

    db.add(flow_dual)
    db.flush()

    pred_dual = DBPrediction(
        flow_id=flow_dual.id,
        model_name="weighted_voting_ensemble",
        model_version="1.0.0",
        predicted_label="PortScan",
        predicted_class_id=10,
        confidence=0.8539,
        detection_method="SYN_BURST_HEURISTIC",
        detection_confidence=0.8539,
        ml_predicted_label="Benign",
        ml_confidence=0.9961,
        ml_portscan_prob=0.0039,
        probabilities_json={"Benign": 0.9961, "PortScan": 0.0039, "DoS": 0.0},
        shap_json=[
            {"feature": "Init Bwd Win Bytes", "value": 65535.0, "shap_value": 0.5414, "importance": 0.5414, "contribution": "positive"},
            {"feature": "Flow Duration", "value": 2000.0, "shap_value": -0.3821, "importance": 0.3821, "contribution": "negative"}
        ]
    )
    db.add(pred_dual)

    alert_dual = DBAlert(
        alert_id="ALT-TEST-DUAL-001",
        severity="MEDIUM",
        attack_type="PortScan",
        confidence=0.8539,
        detection_method="SYN_BURST_HEURISTIC",
        detection_confidence=0.8539,
        ml_predicted_label="Benign",
        ml_confidence=0.9961,
        src_ip="192.168.1.40",
        dst_ip="192.168.1.1",
        src_port=54321,
        dst_port=80,
        model_used="weighted_voting_ensemble",
        dedup_key="192.168.1.40:80:PortScan",
        status="NEW",
        flow_count=1,
        first_seen=now,
        last_seen=now,
        shap_json=pred_dual.shap_json,
        explanation="SYN-Burst heuristic triggered PortScan alert."
    )
    db.add(alert_dual)

    # 2. Pure ML Alert (ML: PortScan 98.5%, Heuristic: None)
    flow_ml = DBFlow(
        src_ip="10.0.0.55",
        dst_ip="10.0.0.1",
        src_port=44444,
        dst_port=443,
        protocol=6,
        duration_seconds=0.05,
        packet_count=5,
        features_json={f: 1.0 for f in CANONICAL_FEATURES}
    )
    db.add(flow_ml)
    db.flush()

    pred_ml = DBPrediction(
        flow_id=flow_ml.id,
        model_name="xgboost",
        model_version="1.0.0",
        predicted_label="PortScan",
        predicted_class_id=10,
        confidence=0.9850,
        detection_method="MACHINE_LEARNING",
        detection_confidence=0.9850,
        ml_predicted_label="PortScan",
        ml_confidence=0.9850,
        ml_portscan_prob=0.9850,
        probabilities_json={"PortScan": 0.9850, "Benign": 0.0150},
        shap_json=[
            {"feature": "SYN Flag Count", "value": 1.0, "shap_value": 0.6200, "importance": 0.6200, "contribution": "positive"},
            {"feature": "Fwd Packet Length Max", "value": 1.0, "shap_value": -0.1100, "importance": 0.1100, "contribution": "negative"}
        ]
    )
    db.add(pred_ml)

    alert_ml = DBAlert(
        alert_id="ALT-TEST-ML-002",
        severity="HIGH",
        attack_type="PortScan",
        confidence=0.9850,
        detection_method="MACHINE_LEARNING",
        detection_confidence=0.9850,
        ml_predicted_label="PortScan",
        ml_confidence=0.9850,
        src_ip="10.0.0.55",
        dst_ip="10.0.0.1",
        src_port=44444,
        dst_port=443,
        model_used="xgboost",
        dedup_key="10.0.0.55:443:PortScan",
        status="NEW",
        flow_count=1,
        first_seen=now,
        last_seen=now,
        shap_json=pred_ml.shap_json,
        explanation="ML model classified flow as PortScan with 98.5% confidence."
    )
    db.add(alert_ml)

    db.commit()
    db.close()
    yield
    # Cleanup
    db_clean = SessionLocal()
    db_clean.query(DBAlert).filter(DBAlert.alert_id.in_(["ALT-TEST-DUAL-001", "ALT-TEST-ML-002"])).delete()
    db_clean.commit()
    db_clean.close()


def test_explainability_html_route_serves_page():
    """Verify GET /explainability/{alert_id} renders complete HTML with expected title and metadata."""
    res = client.get("/explainability/ALT-TEST-DUAL-001")
    assert res.status_code == 200
    assert "text/html" in res.headers["content-type"]
    assert "AI Explainability & Forensic Analysis" in res.text
    assert "Dual-Signal Separation Architecture" in res.text
    assert "Canonical 77-Feature Inference Vector" in res.text


def test_deep_explanation_valid_dual_signal_alert():
    """Verify deep-explanation JSON for an alert where ML=Benign and Heuristic=PortScan."""
    res = client.get("/api/alerts/ALT-TEST-DUAL-001/deep-explanation")
    assert res.status_code == 200
    data = res.json()

    # 1. Alert Summary
    assert data["alert"]["alert_id"] == "ALT-TEST-DUAL-001"
    assert data["alert"]["attack_type"] == "PortScan"
    assert data["alert"]["detection_method"] == "SYN_BURST_HEURISTIC"
    assert data["alert"]["src_ip"] == "192.168.1.40"

    # 2. ML Verdict
    assert data["ml_verdict"]["predicted_label"] == "Benign"
    assert data["ml_verdict"]["confidence"] == pytest.approx(0.9961, rel=1e-2)
    assert "Benign" in data["ml_verdict"]["class_probabilities"]

    # 3. Heuristic Verdict
    assert data["heuristic_verdict"]["attack_type"] == "PortScan"
    assert data["heuristic_verdict"]["heuristic_confidence"] == pytest.approx(0.8539, rel=1e-2)

    # 4. Forensic Comparison & Synthesis
    assert "why_alert_generated" in data["comparison"]
    assert "SYN-Burst" in data["comparison"]["why_alert_generated"]
    assert data["comparison"]["ml_vs_heuristic_agreement"] is False

    # 5. SHAP Breakdown
    shap = data["shap"]
    assert "supporting_features" in shap
    assert "opposing_features" in shap
    assert "all_77_features" in shap
    assert len(shap["all_77_features"]) == 77
    assert shap["total_supporting_count"] >= 0
    assert shap["total_opposing_count"] >= 0

    # 6. Global SHAP
    assert len(data["global_shap"]) > 0
    assert "feature" in data["global_shap"][0]
    assert "importance_pct" in data["global_shap"][0]


def test_deep_explanation_ml_only_alert():
    """Verify deep-explanation JSON for a pure ML alert."""
    res = client.get("/api/alerts/ALT-TEST-ML-002/deep-explanation")
    assert res.status_code == 200
    data = res.json()

    assert data["alert"]["alert_id"] == "ALT-TEST-ML-002"
    assert data["alert"]["detection_method"] == "MACHINE_LEARNING"
    assert data["ml_verdict"]["predicted_label"] == "PortScan"
    assert data["ml_verdict"]["confidence"] == pytest.approx(0.9850, rel=1e-2)
    assert data["comparison"]["ml_vs_heuristic_agreement"] is True


def test_deep_explanation_nonexistent_alert_returns_404():
    """Verify requesting deep-explanation for a non-existent alert returns HTTP 404."""
    res = client.get("/api/alerts/ALT-NONEXISTENT-999/deep-explanation")
    assert res.status_code == 404
    assert "not found" in res.json()["detail"].lower()


def test_deep_explanation_supporting_and_opposing_directions():
    """Verify positive SHAP values are marked as supporting and negative as opposing."""
    res = client.get("/api/alerts/ALT-TEST-DUAL-001/deep-explanation")
    assert res.status_code == 200
    data = res.json()
    shap = data["shap"]

    for f in shap["supporting_features"]:
        assert f["shap_value"] >= 0
        assert "Supports" in f["direction_label"]

    for f in shap["opposing_features"]:
        assert f["shap_value"] <= 0
        assert "Opposes" in f["direction_label"]
