import joblib
import json
import numpy as np
import pandas as pd

with open("models/cicids2017/feature_list.json") as f:
    cols = json.load(f)

xgb = joblib.load("models/cicids2017/xgboost_cicids2017.pkl")
lgb = joblib.load("models/cicids2017/lightgbm_cicids2017.pkl")
hgb = joblib.load("models/cicids2017/hist_gradient_boosting_cicids2017.pkl")
mlp = joblib.load("models/cicids2017/mlp_classifier_cicids2017.pkl")

with open("models/cicids2017/label_mapping.json") as f:
    label_map = {int(k): v for k, v in json.load(f).items()}

print("Label mapping:", label_map)

# Let's search tree splits or test various feature combinations to find clear attack vectors
# For PortScan / DoS:
df = pd.DataFrame(np.zeros((10, 77), dtype=np.float32), columns=cols)

# Row 0: DoS Hulk / Slowhttptest
df.loc[0, "Protocol"] = 6.0
df.loc[0, "Flow Duration"] = 80000000.0
df.loc[0, "Total Fwd Packets"] = 7.0
df.loc[0, "Total Backward Packets"] = 6.0
df.loc[0, "Fwd Packets Length Total"] = 380.0
df.loc[0, "Bwd Packets Length Total"] = 11595.0
df.loc[0, "Fwd Packet Length Max"] = 380.0
df.loc[0, "Bwd Packet Length Max"] = 4344.0
df.loc[0, "Flow IAT Mean"] = 6600000.0
df.loc[0, "Fwd IAT Mean"] = 13000000.0
df.loc[0, "Bwd IAT Mean"] = 16000000.0
df.loc[0, "Init Fwd Win Bytes"] = 29200.0
df.loc[0, "Init Bwd Win Bytes"] = 235.0
df.loc[0, "Fwd Seg Size Min"] = 32.0

# Row 1: PortScan
df.loc[1, "Protocol"] = 6.0
df.loc[1, "Flow Duration"] = 30.0
df.loc[1, "Total Fwd Packets"] = 1.0
df.loc[1, "Total Backward Packets"] = 1.0
df.loc[1, "Fwd Header Length"] = 40.0
df.loc[1, "Bwd Header Length"] = 20.0
df.loc[1, "Fwd Seg Size Min"] = 40.0
df.loc[1, "Init Fwd Win Bytes"] = 1024.0
df.loc[1, "SYN Flag Count"] = 1.0

# Row 2: DDoS
df.loc[2, "Protocol"] = 6.0
df.loc[2, "Flow Duration"] = 1200000.0
df.loc[2, "Total Fwd Packets"] = 3.0
df.loc[2, "Total Backward Packets"] = 0.0
df.loc[2, "Fwd Packets Length Total"] = 18.0
df.loc[2, "Fwd Packet Length Max"] = 6.0
df.loc[2, "Fwd Packet Length Min"] = 6.0
df.loc[2, "Fwd Packet Length Mean"] = 6.0
df.loc[2, "Flow Packets/s"] = 2.5
df.loc[2, "Init Fwd Win Bytes"] = 256.0
df.loc[2, "Fwd Seg Size Min"] = 20.0

# Row 3: FTP-Patator / SSH-Patator
df.loc[3, "Protocol"] = 6.0
df.loc[3, "Flow Duration"] = 20000.0
df.loc[3, "Total Fwd Packets"] = 22.0
df.loc[3, "Total Backward Packets"] = 24.0
df.loc[3, "Fwd Packets Length Total"] = 1800.0
df.loc[3, "Bwd Packets Length Total"] = 4000.0
df.loc[3, "Init Fwd Win Bytes"] = 29200.0
df.loc[3, "Init Bwd Win Bytes"] = 28960.0
df.loc[3, "Fwd Seg Size Min"] = 32.0

for i in range(4):
    p_xgb = xgb.predict_proba(df.iloc[[i]])[0]
    c_xgb = int(np.argmax(p_xgb))
    
    # For LightGBM rename columns
    df_lgb = df.iloc[[i]].copy()
    df_lgb.columns = [c.replace(" ", "_").replace("-", "_") for c in df_lgb.columns]
    p_lgb = lgb.predict_proba(df_lgb)[0]
    c_lgb = int(np.argmax(p_lgb))

    p_hgb = hgb.predict_proba(df.iloc[[i]].values)[0]
    c_hgb = int(np.argmax(p_hgb))

    print(f"Row {i}:")
    print(f"  XGBoost: Class {c_xgb} ({label_map[c_xgb]}), Conf: {p_xgb[c_xgb]:.4f}")
    print(f"  LightGBM: Class {c_lgb} ({label_map[c_lgb]}), Conf: {p_lgb[c_lgb]:.4f}")
    print(f"  HistGB:  Class {c_hgb} ({label_map[c_hgb]}), Conf: {p_hgb[c_hgb]:.4f}")
