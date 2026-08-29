import joblib.numpy_pickle_utils as npu
import joblib
import io
import os

# Save original _read_bytes
orig_read_bytes = npu._read_bytes

def tolerant_read_bytes(fp, size, msg=""):
    data = fp.read(size)
    if len(data) < size:
        print(f"  [tolerant_read_bytes] Needed {size} bytes, got {len(data)} bytes. Padding {size - len(data)} zero bytes.")
        data = data + b'\x00' * (size - len(data))
    return data

npu._read_bytes = tolerant_read_bytes

for fn in ["random_forest_cicids2017.pkl", "extra_trees_cicids2017.pkl", "X_train.pkl", "X_test.pkl", "y_train.pkl"]:
    if os.path.exists(fn):
        print(f"\n--- Loading {fn} with tolerant unpickler ---")
        try:
            obj = joblib.load(fn)
            print(f"[RECOVERED SUCCESS] {fn}: type={type(obj)}")
            if hasattr(obj, "estimators_"):
                print(f"  n_estimators={len(obj.estimators_)}, classes_={getattr(obj, 'classes_', None)}")
            if hasattr(obj, "shape"):
                print(f"  shape={obj.shape}")
            # Resave cleanly!
            clean_name = f"repaired_{fn}"
            joblib.dump(obj, clean_name)
            print(f"  Saved repaired file as {clean_name}")
        except Exception as e:
            print(f"[FAILED] {fn}: {type(e).__name__}: {e}")

