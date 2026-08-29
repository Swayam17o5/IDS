import pickle
import joblib
import os
import sys

print("Python version:", sys.version)
try:
    import sklearn
    print("sklearn version:", sklearn.__version__)
except Exception as e:
    print("sklearn:", e)

try:
    import pandas as pd
    print("pandas version:", pd.__version__)
except Exception as e:
    print("pandas:", e)

try:
    import numpy as np
    print("numpy version:", np.__version__)
except Exception as e:
    print("numpy:", e)

try:
    import xgboost
    print("xgboost version:", xgboost.__version__)
except Exception as e:
    print("xgboost:", e)

try:
    import lightgbm
    print("lightgbm version:", lightgbm.__version__)
except Exception as e:
    print("lightgbm:", e)

try:
    import torch
    print("torch version:", torch.__version__)
except Exception as e:
    print("torch:", e)

files = [
    "xgboost_cicids2017.pkl",
    "lightgbm_cicids2017.pkl",
    "extra_trees_cicids2017.pkl",
    "random_forest_cicids2017.pkl",
    "hist_gradient_boosting_cicids2017.pkl",
    "mlp_classifier_cicids2017.pkl",
    "X_train.pkl",
    "X_test.pkl",
    "y_train.pkl",
    "y_test.pkl",
    "FTTransformer_cicids2017.pth",
    "ft_transformer_cicids2017.pth",
    "tabnet_cicids2017.zip"
]

print("\n" + "="*60)
print("TESTING FILE LOADABILITY WITH PICKLE & JOBLIB")
print("="*60)

for f in files:
    if not os.path.exists(f):
        print(f"[-] {f} does NOT exist")
        continue
    size = os.path.getsize(f)
    print(f"\nFile: {f} ({size:,} bytes)")
    
    # Try joblib
    if f.endswith(".pkl"):
        try:
            obj_j = joblib.load(f)
            print(f"  [JOBLIB SUCCESS] type: {type(obj_j)}")
            if hasattr(obj_j, "shape"):
                print(f"  shape: {obj_j.shape}")
            if hasattr(obj_j, "classes_"):
                print(f"  classes: {obj_j.classes_}")
            if hasattr(obj_j, "n_features_in_"):
                print(f"  n_features_in_: {obj_j.n_features_in_}")
        except Exception as e:
            print(f"  [JOBLIB FAILED]: {type(e).__name__}: {e}")
            
        # Try raw pickle
        try:
            with open(f, "rb") as fp:
                obj_p = pickle.load(fp)
            print(f"  [PICKLE SUCCESS] type: {type(obj_p)}")
        except Exception as e:
            print(f"  [PICKLE FAILED]: {type(e).__name__}: {e}")

    elif f.endswith(".pth"):
        try:
            weights = torch.load(f, map_location="cpu")
            print(f"  [TORCH SUCCESS] keys: {len(weights)}")
        except Exception as e:
            print(f"  [TORCH FAILED]: {e}")

    elif f.endswith(".zip"):
        import zipfile
        try:
            with zipfile.ZipFile(f, 'r') as z:
                print(f"  [ZIP SUCCESS] namelist: {z.namelist()}")
        except Exception as e:
            print(f"  [ZIP FAILED]: {e}")
