import requests
import json
import time

BASE_URL = "http://127.0.0.1:8000"

def test_health():
    res = requests.get(f"{BASE_URL}/health")
    assert res.status_code == 200, f"Health check failed: {res.text}"
    print("[PASS] Backend /health OK")

def test_models_list():
    res = requests.get(f"{BASE_URL}/api/models")
    assert res.status_code == 200, f"Models list failed: {res.text}"
    data = res.json()
    models = data if isinstance(data, list) else data.get("models", [])
    print(f"[PASS] Registered models: {[m['name'] for m in models]}")

def test_flow_ml_classification():
    # 1. Normal traffic flow with is_port_scan = False
    dummy_features = {f"f_{i}": 0.0 for i in range(77)}
    payload = {
        "features": dummy_features,
        "metadata": {
            "src_ip": "192.168.1.50",
            "dst_ip": "192.168.1.1",
            "src_port": 54321,
            "dst_port": 80,
            "protocol": 6,
            "is_port_scan": False,
            "port_scan_score": 0.0,
            "distinct_ports_scanned": 0
        }
    }
    res = requests.post(f"{BASE_URL}/api/predict", json=payload)
    assert res.status_code == 200, f"Predict failed: {res.text}"
    data = res.json()
    verdict = data["final_verdict"]
    print("\n--- ML BENIGN FLOW TEST ---")
    print(json.dumps(verdict, indent=2))
    assert verdict["detection_method"] == "MACHINE_LEARNING"
    assert verdict["predicted_label"] == verdict["ml_predicted_label"]
    assert verdict["confidence"] == verdict["ml_confidence"]
    print("[PASS] Pure ML flow evaluated correctly")

def test_portscan_heuristic_separation():
    # 2. PortScan flow detected via SYN Burst Heuristic (e.g. 8 distinct ports probed -> score ~0.8539)
    dummy_features = {f"f_{i}": 0.0 for i in range(77)}
    dyn_port = int(time.time()) % 60000 + 1024
    payload = {
        "features": dummy_features,
        "metadata": {
            "src_ip": f"10.0.1.{int(time.time()) % 250 + 1}",
            "dst_ip": "10.0.0.1",
            "src_port": dyn_port,
            "dst_port": 8080,
            "protocol": 6,
            "is_port_scan": True,
            "port_scan_score": 0.8539,
            "distinct_ports_scanned": 8
        }
    }
    res = requests.post(f"{BASE_URL}/api/predict", json=payload)
    assert res.status_code == 200, f"Predict failed: {res.text}"
    data = res.json()
    verdict = data["final_verdict"]
    print("\n--- PORTSCAN HEURISTIC DETECTION TEST ---")
    print(json.dumps(verdict, indent=2))
    
    assert verdict["predicted_label"] == "PortScan"
    assert verdict["predicted_class_id"] == 10
    assert verdict["detection_method"] == "SYN_BURST_HEURISTIC"
    assert 0.80 <= verdict["confidence"] <= 0.99
    assert verdict["confidence"] == verdict["heuristic_score"]
    assert verdict["ml_predicted_label"] == "Benign"
    assert verdict["ml_confidence"] > 0.50
    assert verdict["ml_portscan_probability"] < 0.05
    print("[PASS] PortScan heuristic detected with genuine heuristic score (85.39%) while preserving ML Benign probability!")

    # Check alert was generated with proper explanation
    assert data.get("alert_generated") is not None, "Alert was not generated for PortScan!"
    alert = data["alert_generated"]
    print(f"[PASS] Alert ID: {alert['alert_id']}")
    print(f"[PASS] Alert Explanation: {alert['explanation']}")
    assert "SYN Burst Heuristic" in alert["explanation"]
    assert alert["confidence"] == verdict["confidence"]

def test_all_models_active():
    models_to_test = [
        "weighted_voting_ensemble_cicids2017",
        "xgboost_cicids2017",
        "lightgbm_cicids2017",
        "hist_gradient_boosting_cicids2017",
        "mlp_classifier_cicids2017",
        "tabnet_cicids2017",
        "ft_transformer_cicids2017"
    ]
    dummy_features = {f"f_{i}": 0.0 for i in range(77)}
    payload = {
        "features": dummy_features,
        "metadata": {
            "src_ip": "10.0.0.105",
            "dst_ip": "10.0.0.1",
            "src_port": 49201,
            "dst_port": 443,
            "protocol": 6,
            "is_port_scan": True,
            "port_scan_score": 0.9197,
            "distinct_ports_scanned": 12
        }
    }
    print("\n--- TESTING ACTIVE MODEL SWITCHING FOR DUAL CONFIDENCE ---")
    for m in models_to_test:
        # Switch model
        sw = requests.post(f"{BASE_URL}/api/models/switch_active", json={"model_id": m})
        assert sw.status_code == 200, f"Failed to switch to {m}"
        
        # Predict
        res = requests.post(f"{BASE_URL}/api/predict", json=payload)
        assert res.status_code == 200
        verdict = res.json()["final_verdict"]
        print(f"Model: {m:25s} -> Verdict: {verdict['predicted_label']} (Conf: {verdict['confidence']:.4f}, Method: {verdict['detection_method']}) | ML Pred: {verdict['ml_predicted_label']} (ML Conf: {verdict['ml_confidence']:.4f}, PortScan Prob: {verdict['ml_portscan_probability']:.6f})")
        assert verdict["predicted_label"] == "PortScan"
        assert verdict["detection_method"] == "SYN_BURST_HEURISTIC"
        assert verdict["confidence"] == 0.9197
        assert verdict["ml_confidence"] > 0.0  # Real ML probability

    # Switch back to weighted_voting_ensemble
    requests.post(f"{BASE_URL}/api/models/switch_active", json={"model_id": "weighted_voting_ensemble_cicids2017"})
    print("[PASS] All 7 models successfully validated with dual confidence architecture!")

def test_api_flows_and_alerts():
    flows_res = requests.get(f"{BASE_URL}/api/flows?limit=5")
    assert flows_res.status_code == 200
    flows = flows_res.json()
    print("\n--- RECENT FLOWS API SAMPLE ---")
    print(json.dumps(flows[0], indent=2))
    assert "detection_method" in flows[0]
    assert "detection_confidence" in flows[0]

    alerts_res = requests.get(f"{BASE_URL}/api/alerts?limit=5")
    assert alerts_res.status_code == 200
    alerts = alerts_res.json()
    print("\n--- RECENT ALERTS API SAMPLE ---")
    print(json.dumps(alerts[0], indent=2))
    assert "detection_method" in alerts[0]
    assert "explanation" in alerts[0]
    print("[PASS] /api/flows and /api/alerts serialized correctly")

if __name__ == "__main__":
    test_health()
    test_models_list()
    test_flow_ml_classification()
    test_portscan_heuristic_separation()
    test_all_models_active()
    test_api_flows_and_alerts()
    print("\n==========================================")
    print("ALL DUAL-CONFIDENCE TESTS PASSED PERFECTLY!")
    print("==========================================")
