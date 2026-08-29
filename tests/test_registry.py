import pytest
from services.registry.registry import ModelRegistry

def test_model_registry_discovery():
    reg = ModelRegistry("models")
    datasets = reg.list_datasets()
    assert "cicids2017" in datasets

def test_model_cards_validity():
    reg = ModelRegistry("models")
    val = reg.validate_all_cards()
    assert val["valid_count"] == 7
    assert len(val["errors"]) == 0

def test_specific_model_metrics():
    reg = ModelRegistry("models")
    xgb_card = reg.get_model_card("cicids2017", "xgboost")
    assert xgb_card is not None
    assert xgb_card["feature_count"] == 77
    assert xgb_card["metrics"]["accuracy"] > 0.99

def test_deep_loaded_models_validation():
    reg = ModelRegistry("models")
    val_deep = reg.validate_loaded_models()
    assert len(val_deep["verified_models"]) == 7
    assert len(val_deep["errors"]) == 0
