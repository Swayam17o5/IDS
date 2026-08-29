import json
import joblib
import torch
import numpy as np
import pandas as pd
import hashlib

def hash_file(filepath):
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(8192):
            h.update(chunk)
    return h.hexdigest()

print("=== CHECKING FTTRANSFORMER FILES ===")
h1 = hash_file("FTTransformer_cicids2017.pth")
h2 = hash_file("ft_transformer_cicids2017.pth")
print(f"FTTransformer_cicids2017.pth SHA256: {h1}")
print(f"ft_transformer_cicids2017.pth SHA256: {h2}")
print(f"Exact match? {h1 == h2}")

print("\n=== INSPECTING CELLS 95-144 OF ids.ipynb ===")
with open("ids.ipynb", "r", encoding="utf-8") as f:
    nb = json.load(f)

for i in range(95, len(nb['cells'])):
    c = nb['cells'][i]
    src = "".join(c.get('source', []))
    outputs = c.get('outputs', [])
    print(f"\n--- Cell {i} ({c.get('cell_type')}) ---")
    print("SOURCE:")
    print(src)
    if outputs:
        print("OUTPUTS:")
        for out in outputs:
            if 'text' in out:
                print("".join(out['text'])[:500])
            elif 'data' in out and 'text/plain' in out['data']:
                print("".join(out['data']['text/plain'])[:500])

print("\n=== INSPECTING X_train, X_test, y_train, y_test ===")
X_train = joblib.load("X_train.pkl")
X_test = joblib.load("X_test.pkl")
y_train = joblib.load("y_train.pkl")
y_test = joblib.load("y_test.pkl")

print(f"X_train shape: {X_train.shape}, type: {type(X_train)}")
print(f"X_test shape: {X_test.shape}")
print(f"y_train shape: {y_train.shape}, unique: {np.unique(y_train)}")
print(f"y_test shape: {y_test.shape}, unique: {np.unique(y_test)}")
print(f"Feature columns ({len(X_train.columns)}): {list(X_train.columns)}")
print(f"dtypes:\n{X_train.dtypes.value_counts()}")
print(f"Nulls in X_train: {X_train.isna().sum().sum()}")
print(f"Infs in X_train: {np.isinf(X_train.values).sum()}")

print("\n=== CLASS DISTRIBUTION IN y_train ===")
print(y_train.value_counts().sort_index())
