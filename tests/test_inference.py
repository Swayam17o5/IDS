import json
import pytest
from fastapi.testclient import TestClient
from services.inference.app import app, init_models

@pytest.fixture(scope="module")
def client():
    init_models("cicids2017")
    return TestClient(app)

def test_health_endpoint(client):
    res = client.get("/health")
    assert res.status_code == 200
    data = res.json()
    # Phase 1: status is 'healthy' (was 'ok' in Phase 0)
    assert data["status"] in ("healthy", "degraded")
    assert "xgboost" in data["loaded_models"]
    assert "weighted_voting_ensemble" in data["loaded_models"] or "stacking_ensemble" in data["loaded_models"]
    # Phase 1: additional component health fields
    assert data["feature_count"] == 77
    assert "components" in data
    assert data["model_loaded"] is True

def test_models_registry_endpoint(client):
    res = client.get("/models")
    assert res.status_code == 200
    data = res.json()
    assert data["dataset"] == "cicids2017"
    assert len(data["models"]) >= 6

def test_predict_endpoint(client):
    with open("models/cicids2017/feature_list.json") as f:
        features_list = json.load(f)
    
    # Create sample benign feature dict
    sample_features = {feat: 0.0 for feat in features_list}
    payload = {
        "features": sample_features,
        "metadata": {"src_ip": "10.0.0.1", "dst_ip": "10.0.0.2", "dst_port": 443}
    }
    
    res = client.post("/predict", json=payload)
    assert res.status_code == 200
    data = res.json()
    
    assert "final_verdict" in data
    assert "predicted_label" in data["final_verdict"]
    assert "all_model_predictions" in data
    assert "xgboost" in data["all_model_predictions"]
    assert "lightgbm" in data["all_model_predictions"]
    assert ("weighted_voting_ensemble" in data["all_model_predictions"] or "stacking_ensemble" in data["all_model_predictions"])
    assert "shap_explanations" in data
    assert len(data["shap_explanations"]) > 0


