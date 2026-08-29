import joblib
import torch
import numpy as np
import pandas as pd
import xgboost as xgb
import lightgbm as lgb
from pytorch_tabnet.tab_model import TabNetClassifier
import rtdl_revisiting_models as rtdl
import os

print("=== 1. CHECKING MODELS ===")
models = {}
for name, fname in [
    ("XGBoost", "xgboost_cicids2017.pkl"),
    ("LightGBM", "lightgbm_cicids2017.pkl"),
    ("HistGradientBoosting", "hist_gradient_boosting_cicids2017.pkl"),
    ("MLPClassifier", "mlp_classifier_cicids2017.pkl"),
    ("RandomForest", "random_forest_cicids2017.pkl"),
    ("ExtraTrees", "extra_trees_cicids2017.pkl")
]:
    try:
        m = joblib.load(fname)
        models[name] = m
        print(f"[SUCCESS] {name} ({fname}): type={type(m)}, n_features_in_={getattr(m, 'n_features_in_', 'N/A')}")
    except Exception as e:
        print(f"[FAIL] {name} ({fname}): {type(e).__name__}: {e}")

print("\n=== 2. CHECKING TABNET ===")
try:
    tabnet = TabNetClassifier()
    tabnet.load_model("tabnet_cicids2017.zip")
    print(f"[SUCCESS] TabNet loaded: input_dim={tabnet.input_dim}, output_dim={tabnet.output_dim}")
except Exception as e:
    print(f"[FAIL] TabNet load: {e}")

print("\n=== 3. CHECKING FT-TRANSFORMER ===")
try:
    import torch.nn as nn
    class FTTransformerModel(nn.Module):
        def __init__(self, n_num_features=77, cat_cardinalities=[], d_out=15):
            super().__init__()
            self.tokenizer = rtdl.FeatureTokenizer(
                n_num_features=n_num_features,
                cat_cardinalities=cat_cardinalities,
                d_token=192
            )
            self.transformer = rtdl.Transformer(
                d_token=192,
                n_blocks=3,
                attention_n_heads=8,
                attention_dropout=0.2,
                ffn_d_hidden_multiplier=4/3,
                ffn_dropout=0.1,
                residual_dropout=0.0,
                d_out=d_out
            )
        def forward(self, x_num, x_cat=None):
            x = self.tokenizer(x_num, x_cat)
            x = self.transformer(x)
            return x

    ft_model1 = FTTransformerModel(n_num_features=77, cat_cardinalities=[], d_out=15)
    ft_sd1 = torch.load("FTTransformer_cicids2017.pth", map_location="cpu")
    ft_model1.load_state_dict(ft_sd1)
    ft_model1.eval()
    print("[SUCCESS] FTTransformer_cicids2017.pth loaded into FTTransformerModel (77 feats -> 15 classes)")

    ft_model2 = FTTransformerModel(n_num_features=77, cat_cardinalities=[], d_out=15)
    ft_sd2 = torch.load("ft_transformer_cicids2017.pth", map_location="cpu")
    ft_model2.load_state_dict(ft_sd2)
    ft_model2.eval()
    print("[SUCCESS] ft_transformer_cicids2017.pth loaded into FTTransformerModel (77 feats -> 15 classes)")
except Exception as e:
    print(f"[FAIL] FT-Transformer load: {e}")

print("\n=== 4. CHECKING FEATURE NAMES FROM LOADED TREE MODELS ===")
if "XGBoost" in models:
    xgb_feats = list(models["XGBoost"].feature_names_in_) if hasattr(models["XGBoost"], "feature_names_in_") else None
    print(f"XGBoost features ({len(xgb_feats) if xgb_feats else 0}): {xgb_feats}")
if "LightGBM" in models:
    lgb_feats = list(models["LightGBM"].feature_names_in_) if hasattr(models["LightGBM"], "feature_names_in_") else None
    print(f"LightGBM features ({len(lgb_feats) if lgb_feats else 0}): {lgb_feats}")
if "HistGradientBoosting" in models:
    hgb_feats = list(models["HistGradientBoosting"].feature_names_in_) if hasattr(models["HistGradientBoosting"], "feature_names_in_") else None
    print(f"HistGradientBoosting features ({len(hgb_feats) if hgb_feats else 0}): {hgb_feats}")
