import os
import shutil
import json

# Create directory structure
os.makedirs("models/cicids2017/model_cards", exist_ok=True)
os.makedirs("models/nsl_kdd/model_cards", exist_ok=True)
os.makedirs("models/unsw_nb15/model_cards", exist_ok=True)
os.makedirs("models/backdoor/model_cards", exist_ok=True)

# Copy/Move working models into models/cicids2017/
files_to_copy = [
    "xgboost_cicids2017.pkl",
    "lightgbm_cicids2017.pkl",
    "hist_gradient_boosting_cicids2017.pkl",
    "mlp_classifier_cicids2017.pkl",
    "tabnet_cicids2017.zip",
    "ft_transformer_cicids2017.pth",
    "feature_list.json",
    "label_mapping.json",
    "label_encoder.pkl",
    "stacking_ensemble.pkl"
]

for f in files_to_copy:
    if os.path.exists(f):
        shutil.copy(f, os.path.join("models/cicids2017", f))

print("Copied files to models/cicids2017/")

# Create model cards based on actual notebook training results
metrics_data = {
    "xgboost": {
        "model_id": "xgboost_cicids2017",
        "name": "XGBoost Classifier",
        "dataset": "CICIDS2017",
        "framework": "xgboost",
        "file_path": "models/cicids2017/xgboost_cicids2017.pkl",
        "feature_count": 77,
        "classes_count": 15,
        "metrics": {
            "accuracy": 0.998772,
            "precision": 0.998734,
            "recall": 0.998772,
            "f1_score": 0.998740,
            "training_time_seconds": 107.10
        },
        "supports_shap": True
    },
    "lightgbm": {
        "model_id": "lightgbm_cicids2017",
        "name": "LightGBM Classifier",
        "dataset": "CICIDS2017",
        "framework": "lightgbm",
        "file_path": "models/cicids2017/lightgbm_cicids2017.pkl",
        "feature_count": 77,
        "classes_count": 15,
        "metrics": {
            "accuracy": 0.998495,
            "precision": 0.998463,
            "recall": 0.998495,
            "f1_score": 0.998466,
            "training_time_seconds": 4.47
        },
        "supports_shap": True
    },
    "hist_gradient_boosting": {
        "model_id": "hist_gradient_boosting_cicids2017",
        "name": "Hist Gradient Boosting",
        "dataset": "CICIDS2017",
        "framework": "scikit-learn",
        "file_path": "models/cicids2017/hist_gradient_boosting_cicids2017.pkl",
        "feature_count": 77,
        "classes_count": 15,
        "metrics": {
            "accuracy": 0.991556,
            "precision": 0.995898,
            "recall": 0.991556,
            "f1_score": 0.993635,
            "training_time_seconds": 37.39
        },
        "supports_shap": False
    },
    "mlp_classifier": {
        "model_id": "mlp_classifier_cicids2017",
        "name": "MLP Classifier (Neural Net)",
        "dataset": "CICIDS2017",
        "framework": "scikit-learn",
        "file_path": "models/cicids2017/mlp_classifier_cicids2017.pkl",
        "feature_count": 77,
        "classes_count": 15,
        "metrics": {
            "accuracy": 0.996545,
            "precision": 0.996538,
            "recall": 0.996545,
            "f1_score": 0.996120,
            "training_time_seconds": 1981.10
        },
        "supports_shap": False
    },
    "tabnet": {
        "model_id": "tabnet_cicids2017",
        "name": "TabNet Attention Model",
        "dataset": "CICIDS2017",
        "framework": "pytorch-tabnet",
        "file_path": "models/cicids2017/tabnet_cicids2017.zip",
        "feature_count": 77,
        "classes_count": 15,
        "metrics": {
            "accuracy": 0.951441,
            "precision": 0.960350,
            "recall": 0.951441,
            "f1_score": 0.952951,
            "training_time_seconds": 1213.50
        },
        "supports_shap": False
    },
    "ft_transformer": {
        "model_id": "ft_transformer_cicids2017",
        "name": "FT-Transformer",
        "dataset": "CICIDS2017",
        "framework": "pytorch/rtdl",
        "file_path": "models/cicids2017/ft_transformer_cicids2017.pth",
        "feature_count": 77,
        "classes_count": 15,
        "metrics": {
            "accuracy": 0.964034,
            "precision": 0.961708,
            "recall": 0.964034,
            "f1_score": 0.961841,
            "training_time_seconds": 10716.78
        },
        "supports_shap": False
    },
    "stacking_ensemble": {
        "model_id": "stacking_ensemble_cicids2017",
        "name": "Stacking / Blending Ensemble",
        "dataset": "CICIDS2017",
        "framework": "custom_ensemble",
        "file_path": "models/cicids2017/stacking_ensemble.pkl",
        "feature_count": 77,
        "classes_count": 15,
        "metrics": {
            "accuracy": 0.998772,
            "precision": 0.998734,
            "recall": 0.998772,
            "f1_score": 0.998740,
            "training_time_seconds": 148.96
        },
        "supports_shap": False
    }
}

for k, card in metrics_data.items():
    card_path = os.path.join("models/cicids2017/model_cards", f"{k}.json")
    with open(card_path, "w") as f:
        json.dump(card, f, indent=2)
    print(f"Wrote {card_path}")

