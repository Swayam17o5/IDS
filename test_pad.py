import os
import joblib
import io

def try_pad_and_load(filename, missing_bytes_approx=500000):
    print(f"\n--- Testing pad on {filename} ---")
    with open(filename, "rb") as f:
        data = f.read()
    
    # Try padding with various byte amounts
    for pad_size in [1000, 6040, 10000, 69344, 100000, 262144, 524288, 1048576]:
        padded = data + b'\x00' * pad_size
        buf = io.BytesIO(padded)
        try:
            obj = joblib.load(buf)
            print(f"[PAD SUCCESS with {pad_size} bytes] Loaded {type(obj)}! n_estimators={len(getattr(obj, 'estimators_', [])) if hasattr(obj, 'estimators_') else 'N/A'}")
            return obj, pad_size
        except Exception as e:
            pass
    print("Pad did not succeed with simple zero padding.")
    return None, None

rf_obj, pad = try_pad_and_load("random_forest_cicids2017.pkl")
et_obj, pad2 = try_pad_and_load("extra_trees_cicids2017.pkl")
xtr_obj, pad3 = try_pad_and_load("X_train.pkl")
xte_obj, pad4 = try_pad_and_load("X_test.pkl")

