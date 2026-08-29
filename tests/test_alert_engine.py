import pytest
from services.alert_engine.engine import AlertEngine

def test_benign_produces_no_alert():
    engine = AlertEngine()
    prediction_payload = {
        "final_verdict": {
            "predicted_label": "Benign",
            "confidence": 0.99,
            "active_model_used": "stacking_ensemble"
        }
    }
    alert = engine.process_prediction(prediction_payload, {"src_ip": "192.168.1.5", "dst_port": 80})
    assert alert is None

def test_attack_triggers_alert():
    engine = AlertEngine()
    prediction_payload = {
        "final_verdict": {
            "predicted_label": "DDoS",
            "confidence": 0.98,
            "active_model_used": "xgboost"
        },
        "shap_explanations": [{"feature": "Flow Packets/s", "importance": 0.45}]
    }
    alert = engine.process_prediction(prediction_payload, {"src_ip": "192.168.1.100", "dst_ip": "10.0.0.1", "dst_port": 80})
    assert alert is not None
    assert alert["severity"] == "CRITICAL"
    assert alert["attack_type"] == "DDoS"
    assert alert["src_ip"] == "192.168.1.100"

def test_alert_deduplication():
    engine = AlertEngine(dedup_window_seconds=300)
    prediction_payload = {
        "final_verdict": {
            "predicted_label": "PortScan",
            "confidence": 0.95,
            "active_model_used": "xgboost"
        }
    }
    meta = {"src_ip": "192.168.1.200", "dst_ip": "10.0.0.1", "dst_port": 22}
    
    alert1 = engine.process_prediction(prediction_payload, meta)
    assert alert1 is not None
    
    # Second immediate attack from same source is deduplicated
    alert2 = engine.process_prediction(prediction_payload, meta)
    assert alert2 is None
