import json
import joblib
import torch
import os

with open("ids.ipynb", "r", encoding="utf-8") as f:
    nb = json.load(f)

print("=== CHECKING ALL CELL OUTPUTS FOR LABELS AND METRICS ===")
for i, c in enumerate(nb['cells']):
    for out in c.get('outputs', []):
        text = ""
        if 'text' in out:
            text = "".join(out['text'])
        elif 'data' in out:
            for mime, val in out['data'].items():
                text += str(val) + "\n"
        
        if any(kw in text.lower() for kw in ["benign", "ddos", "portscan", "bot", "dos", "patator", "web attack", "infiltration", "heartbleed", "stacking", "voting"]):
            print(f"--- Cell {i} output snippet ---")
            print(text[:1000])

print("=== CHECKING MODEL FILES LOADABILITY ===")
model_files = [
    "xgboost_cicids2017.pkl",
    "lightgbm_cicids2017.pkl",
    "extra_trees_cicids2017.pkl",
    "random_forest_cicids2017.pkl",
    "hist_gradient_boosting_cicids2017.pkl",
    "mlp_classifier_cicids2017.pkl",
]

for mf in model_files:
    if os.path.exists(mf):
        try:
            m = joblib.load(mf)
            print(f"[OK] {mf}: type={type(m)}, n_features_in_={getattr(m, 'n_features_in_', 'N/A')}, classes_={getattr(m, 'classes_', 'N/A')}")
        except Exception as e:
            print(f"[FAIL] {mf}: {e}")
    else:
        print(f"[MISSING] {mf}")

print("\n=== CHECKING PYTORCH & TABNET ===")
# PyTorch
try:
    sd1 = torch.load("FTTransformer_cicids2017.pth", map_location="cpu")
    print(f"[OK] FTTransformer_cicids2017.pth keys count: {len(sd1)}")
    sd2 = torch.load("ft_transformer_cicids2017.pth", map_location="cpu")
    print(f"[OK] ft_transformer_cicids2017.pth keys count: {len(sd2)}")
except Exception as e:
    print(f"PyTorch load error: {e}")

# TabNet
if os.path.exists("tabnet_cicids2017.zip"):
    print("[OK] tabnet_cicids2017.zip exists (size: " + str(os.path.getsize("tabnet_cicids2017.zip")) + " bytes)")

