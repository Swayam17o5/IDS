import os
import sys
import time
import json
from fastapi.testclient import TestClient

sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

from services.inference.app import app, init_models
from services.alert_engine.engine import AlertEngine, SEVERITY_MAP

print("=== INITIALIZING LIVE INFERENCE & ALERT ENGINE ===")
init_models("cicids2017")
client = TestClient(app)
engine = AlertEngine(min_confidence_threshold=0.70, dedup_window_seconds=60)

with open("models/cicids2017/feature_list.json") as f:
    feature_names = json.load(f)

# 1. Test Benign Flow through Live Model -> AlertEngine
print("\n--- 1. Testing Live Benign Traffic Flow ---")
benign_feats = {f: 0.0 for f in feature_names}
benign_payload = {
    "features": benign_feats,
    "metadata": {"src_ip": "192.168.1.100", "dst_ip": "10.0.0.1", "dst_port": 80}
}
resp_benign = client.post("/predict", json=benign_payload).json()
alert_benign = engine.process_prediction(resp_benign, benign_payload["metadata"])
print(f"Model Verdict: {resp_benign['final_verdict']['predicted_label']} (Conf: {resp_benign['final_verdict']['confidence']:.4f})")
print(f"Alert Generated: {alert_benign}")
assert alert_benign is None, "Benign traffic should NOT generate an alert!"
print("[PASSED] Benign traffic correctly produced no alert.")

# 2. Test Real Attack Predictions (XGBoost predicting Web Attack - XSS)
print("\n--- 2. Testing Live Attack Prediction & Severity Mapping (XGBoost Active) ---")
client.post("/models/switch_active", json={"model_id": "xgboost"})

xss_feats = {f: 0.0 for f in feature_names}
xss_feats["Protocol"] = 6.0
xss_feats["Flow Duration"] = 20000.0
xss_feats["Total Fwd Packets"] = 22.0
xss_feats["Total Backward Packets"] = 24.0
xss_feats["Fwd Packets Length Total"] = 1800.0
xss_feats["Bwd Packets Length Total"] = 4000.0
xss_feats["Init Fwd Win Bytes"] = 29200.0
xss_feats["Init Bwd Win Bytes"] = 28960.0
xss_feats["Fwd Seg Size Min"] = 32.0

attack_payload = {
    "features": xss_feats,
    "metadata": {"src_ip": "172.16.0.4", "dst_ip": "192.168.1.1", "dst_port": 80}
}

resp_attack = client.post("/predict", json=attack_payload).json()
print(f"Active Model: {resp_attack['final_verdict']['active_model_used']}")
print(f"Predicted Attack: {resp_attack['final_verdict']['predicted_label']} (Conf: {resp_attack['final_verdict']['confidence']:.4f})")

first_alert = engine.process_prediction(resp_attack, attack_payload["metadata"])
assert first_alert is not None, "Real attack prediction must generate an alert!"
print(f"Generated Alert ID: {first_alert['alert_id']}")
print(f"Attack Type: {first_alert['attack_type']}")
print(f"Severity: {first_alert['severity']} (Expected: {SEVERITY_MAP.get(first_alert['attack_type'])})")
print(f"Dedup Key: {first_alert['dedup_key']}")
print(f"SHAP Explanations Count: {len(first_alert['shap_explanations'])}")
assert first_alert["severity"] == "MEDIUM", f"Expected MEDIUM severity for Web Attack - XSS, got {first_alert['severity']}"
print("[PASSED] Attack prediction successfully triggered mapped severity alert with SHAP context.")

# 3. Test Burst of 50 Repeated Attacks for Deduplication
print("\n--- 3. Testing Burst Deduplication (50 Repeated Attacks in 100ms) ---")
suppressed_count = 0
generated_count = 0

for i in range(50):
    al = engine.process_prediction(resp_attack, attack_payload["metadata"])
    if al is None:
        suppressed_count += 1
    else:
        generated_count += 1

print(f"Total Attack Invocations in Burst: 50")
print(f"Suppressed Duplicates: {suppressed_count}")
print(f"New Alerts Emitted: {generated_count}")
assert suppressed_count == 50, "All subsequent repeated attacks within dedup window must be suppressed!"
print("[PASSED] Burst deduplication successfully suppressed 100% of duplicate alerts.")

# 4. Test Attack from New Source IP (Should emit new alert)
print("\n--- 4. Testing Attack from New Source IP ---")
attack_new_src = {
    "features": xss_feats,
    "metadata": {"src_ip": "10.99.99.1", "dst_ip": "192.168.1.1", "dst_port": 80}
}
new_alert = engine.process_prediction(resp_attack, attack_new_src["metadata"])
assert new_alert is not None, "Attack from different IP must generate a distinct alert!"
print(f"New Alert ID: {new_alert['alert_id']} from {new_alert['src_ip']}")
print("[PASSED] Distinct attacker generated new alert.")

# 5. Test Critical Severity (DDoS via LightGBM)
print("\n--- 5. Testing Critical Severity Alert (DDoS with LightGBM) ---")
client.post("/models/switch_active", json={"model_id": "lightgbm"})
ddos_feats = {f: 0.0 for f in feature_names}
ddos_feats["Protocol"] = 6.0
ddos_feats["Flow Duration"] = 80000000.0
ddos_feats["Total Fwd Packets"] = 7.0
ddos_feats["Total Backward Packets"] = 6.0
ddos_feats["Fwd Packets Length Total"] = 380.0
ddos_feats["Bwd Packets Length Total"] = 11595.0
ddos_feats["Fwd Packet Length Max"] = 380.0
ddos_feats["Bwd Packet Length Max"] = 4344.0
ddos_feats["Flow IAT Mean"] = 6600000.0
ddos_feats["Fwd IAT Mean"] = 13000000.0
ddos_feats["Bwd IAT Mean"] = 16000000.0
ddos_feats["Init Fwd Win Bytes"] = 29200.0
ddos_feats["Init Bwd Win Bytes"] = 235.0
ddos_feats["Fwd Seg Size Min"] = 32.0

ddos_payload = {
    "features": ddos_feats,
    "metadata": {"src_ip": "185.220.101.5", "dst_ip": "192.168.1.50", "dst_port": 443}
}
resp_ddos = client.post("/predict", json=ddos_payload).json()
print(f"Predicted: {resp_ddos['final_verdict']['predicted_label']} (Conf: {resp_ddos['final_verdict']['confidence']:.4f})")
alert_ddos = engine.process_prediction(resp_ddos, ddos_payload["metadata"])
assert alert_ddos is not None and alert_ddos["severity"] == "CRITICAL"
print(f"Generated Alert ID: {alert_ddos['alert_id']} | Severity: {alert_ddos['severity']}")
print("[PASSED] CRITICAL severity correctly mapped for DDoS.")

counts = engine.get_active_alert_counts()
print(f"\nActive Alert Rollup Counts: {counts}")
print("\n[SUCCESS] Alert engine and real prediction wiring verified 100%!")
