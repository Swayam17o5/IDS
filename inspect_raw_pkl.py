import sys
import os

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
    "y_test.pkl"
]

print("=== CHECKING FILE SIZES AND STRUCTURE ===")
for f in files:
    if os.path.exists(f):
        size = os.path.getsize(f)
        with open(f, "rb") as fp:
            data = fp.read()
        print(f"File: {f:35s} | Size on disk: {size:12,d} bytes | Read: {len(data):12,d} bytes")
        # Find all occurrences of pickle protocol headers or strings
        print(f"  First 32 bytes: {data[:32]}")
        print(f"  Last 32 bytes:  {data[-32:]}")

