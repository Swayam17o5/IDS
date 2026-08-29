import joblib
import json
import numpy as np
import pandas as pd

xgb = joblib.load("xgboost_cicids2017.pkl")
lgb = joblib.load("lightgbm_cicids2017.pkl")
hgb = joblib.load("hist_gradient_boosting_cicids2017.pkl")

exact_xgb_features = [str(x) for x in xgb.feature_names_in_]
print("Exact feature names from XGBoost (77):")
print(exact_xgb_features)

with open("feature_list.json", "w") as f:
    json.dump(exact_xgb_features, f, indent=2)

print("Saved feature_list.json!")

# Save label encoding mapping
label_mapping = {
    0: "Benign",
    1: "Bot",
    2: "DDoS",
    3: "DoS GoldenEye",
    4: "DoS Hulk",
    5: "DoS Slowhttptest",
    6: "DoS slowloris",
    7: "FTP-Patator",
    8: "Heartbleed",
    9: "Infiltration",
    10: "PortScan",
    11: "SSH-Patator",
    12: "Web Attack - Brute Force",
    13: "Web Attack - Sql Injection",
    14: "Web Attack - XSS"
}

with open("label_mapping.json", "w") as f:
    json.dump(label_mapping, f, indent=2)

from sklearn.preprocessing import LabelEncoder
le = LabelEncoder()
le.classes_ = np.array([label_mapping[i] for i in range(15)])
joblib.dump(le, "label_encoder.pkl")
print("Saved label_encoder.pkl and label_mapping.json!")

# Test with DataFrame using exact_xgb_features
sample_df = pd.DataFrame(np.zeros((1, 77), dtype=np.float32), columns=exact_xgb_features)
print("XGBoost prediction:", xgb.predict_proba(sample_df))

# LightGBM requires column names matching its training names
lgb_cols = [str(x) for x in lgb.feature_names_in_]
sample_lgb_df = pd.DataFrame(np.zeros((1, 77), dtype=np.float32), columns=lgb_cols)
print("LightGBM prediction:", lgb.predict_proba(sample_lgb_df))

print("HistGradientBoosting prediction:", hgb.predict_proba(sample_df.values))

