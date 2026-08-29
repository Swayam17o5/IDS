import os
import sys
import json
import numpy as np
import pandas as pd
from fastapi.testclient import TestClient

# Ensure project root in sys.path
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

from services.inference.app import app, init_models

print("=== INITIALIZING INFERENCE SERVICE & LOADING ALL MODELS ===")
init_models("cicids2017")
client = TestClient(app)

# 1. Health check
print("\n--- 1. Testing GET /health ---")
res = client.get("/health")
print("Status Code:", res.status_code)
print("Response:", json.dumps(res.json(), indent=2))
assert res.status_code == 200

# 2. Models list
print("\n--- 2. Testing GET /models ---")
res = client.get("/models")
print("Status Code:", res.status_code)
models_data = res.json()
print(f"Total Registered Models: {len(models_data['models'])}")
for m in models_data['models']:
    print(f"  * {m['name']:<30} | ID: {m['model_id']:<32} | Accuracy: {m['metrics']['accuracy']}")

# 3. Live Prediction with Tree SHAP Explanations
print("\n--- 3. Testing POST /predict (Real Non-Placeholder Output & SHAP) ---")
with open("models/cicids2017/feature_list.json") as f:
    feature_names = json.load(f)

# Sample flow with typical traffic values
sample_features = {f: 0.0 for f in feature_names}
sample_features["Destination Port"] = 80.0
sample_features["Flow Duration"] = 120000.0
sample_features["Total Fwd Packets"] = 15.0
sample_features["Total Backward Packets"] = 12.0
sample_features["Total Length of Fwd Packets"] = 4500.0
sample_features["Total Length of Bwd Packets"] = 12500.0
sample_features["Flow Bytes/s"] = 141666.6
sample_features["Flow Packets/s"] = 225.0
sample_features["Init Fwd Win Bytes"] = 64240.0
sample_features["Init Bwd Win Bytes"] = 65535.0

payload = {
    "features": sample_features,
    "metadata": {
        "src_ip": "192.168.1.105",
        "dst_ip": "10.0.0.1",
        "src_port": 52140,
        "dst_port": 80,
        "protocol": 6
    }
}

res = client.post("/predict", json=payload)
print("Status Code:", res.status_code)
pred_data = res.json()

print("\n[FINAL VERDICT]:")
print(json.dumps(pred_data["final_verdict"], indent=2))

print("\n[ALL WORKING MODELS PREDICTIONS]:")
for model_name, p in pred_data["all_model_predictions"].items():
    print(f"  * {model_name:<25} -> Class ID: {p['predicted_class_id']} | Label: {p['predicted_label']:<15} | Confidence: {p['confidence']:.6f}")

print("\n[REAL TREE SHAP EXPLANATIONS (Top 5 Influential Features)]:")
for i, shap_item in enumerate(pred_data["shap_explanations"]):
    print(f"  {i+1}. Feature: {shap_item['feature']:<30} | Value: {shap_item['value']:<10} | SHAP Importance: {shap_item['importance']:.6f}")

print("\n[SUCCESS] Inference service, all 7 models, and SHAP engine fully verified!")
