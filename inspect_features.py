import joblib
import os
import sys

files = ["X_train.pkl", "X_test.pkl", "y_train.pkl", "y_test.pkl"]

for f in files:
    print(f"\n--- Checking {f} (size: {os.path.getsize(f)} bytes) ---")
    try:
        data = joblib.load(f)
        print(f"[OK] {f}: type={type(data)}, shape={getattr(data, 'shape', 'N/A')}")
        if hasattr(data, "columns"):
            print(f"Columns ({len(data.columns)}): {list(data.columns)[:10]} ...")
    except Exception as e:
        print(f"[ERROR] {f}: {e}")

# Check feature names on scikit-learn / xgboost / lightgbm models
rf = joblib.load("random_forest_cicids2017.pkl")
xgb = joblib.load("xgboost_cicids2017.pkl")
lgb = joblib.load("lightgbm_cicids2017.pkl")

print("\n--- Model Feature Names ---")
print("RF feature_names_in_ len:", len(getattr(rf, "feature_names_in_", [])))
print("RF feature names:", getattr(rf, "feature_names_in_", None))
print("XGB feature_names_in_ len:", len(getattr(xgb, "feature_names_in_", [])))
print("LGB feature_names_in_ len:", len(getattr(lgb, "feature_names_in_", [])))

# Check MLP scaler details from notebook or mlp weights
mlp = joblib.load("mlp_classifier_cicids2017.pkl")
print("MLP n_features_in_:", mlp.n_features_in_)
print("MLP coefs_ shapes:", [c.shape for c in mlp.coefs_])

