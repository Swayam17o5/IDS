import joblib
import torch
import numpy as np
import pandas as pd
from pytorch_tabnet.tab_model import TabNetClassifier
import rtdl_revisiting_models as rtdl

import json

with open("models/cicids2017/feature_list.json") as f:
    feature_cols = json.load(f)

print(f"Total features: {len(feature_cols)}")

# Generate a sample flow
sample_df = pd.DataFrame(np.zeros((1, 77), dtype=np.float32), columns=feature_cols)

# Load models
xgb = joblib.load("xgboost_cicids2017.pkl")
lgb = joblib.load("lightgbm_cicids2017.pkl")
hgb = joblib.load("hist_gradient_boosting_cicids2017.pkl")
mlp = joblib.load("mlp_classifier_cicids2017.pkl")

tabnet = TabNetClassifier()
tabnet.load_model("tabnet_cicids2017.zip")

ft = rtdl.FTTransformer(n_cont_features=77, cat_cardinalities=[], d_out=15, **rtdl.FTTransformer.get_default_kwargs())
ft.load_state_dict(torch.load("ft_transformer_cicids2017.pth", map_location="cpu"))
ft.eval()

print("\n=== RUNNING TEST PREDICTIONS ===")
xgb_pred = xgb.predict_proba(sample_df)
print(f"XGBoost top class: {np.argmax(xgb_pred)}, prob: {np.max(xgb_pred):.4f}")

lgb_pred = lgb.predict_proba(sample_df)
print(f"LightGBM top class: {np.argmax(lgb_pred)}, prob: {np.max(lgb_pred):.4f}")

hgb_pred = hgb.predict_proba(sample_df)
print(f"HistGradientBoosting top class: {np.argmax(hgb_pred)}, prob: {np.max(hgb_pred):.4f}")

mlp_pred = mlp.predict_proba(sample_df)
print(f"MLPClassifier top class: {np.argmax(mlp_pred)}, prob: {np.max(mlp_pred):.4f}")

tabnet_pred = tabnet.predict_proba(sample_df.values)
print(f"TabNet top class: {np.argmax(tabnet_pred)}, prob: {np.max(tabnet_pred):.4f}")

with torch.no_grad():
    t_out = ft(torch.tensor(sample_df.values, dtype=torch.float32), None)
    ft_probs = torch.softmax(t_out, dim=1).numpy()
print(f"FT-Transformer top class: {np.argmax(ft_probs)}, prob: {np.max(ft_probs):.4f}")

print("\nALL 6 WORKING MODELS EXECUTED PREDICTIONS SUCCESSFULLY!")
