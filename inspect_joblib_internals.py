import joblib
from joblib.numpy_pickle import _unpickle, NumpyPickler, NumpyUnpickler
import struct
import io
import os

print("=== INSPECTING JOBLIB HEADERS ===")
for fname in ["random_forest_cicids2017.pkl", "extra_trees_cicids2017.pkl", "X_train.pkl", "X_test.pkl", "y_train.pkl", "y_test.pkl"]:
    if not os.path.exists(fname): continue
    size = os.path.getsize(fname)
    print(f"\n--- {fname} (size: {size}) ---")
    with open(fname, "rb") as f:
        magic = f.read(2)
        f.seek(0)
        content = f.read()
        print(f"Magic / First 16 bytes: {content[:16]}")
        # Search for occurrences of expected sizes or sub-pickles
        # Check if joblib magic \x80\x04 is present
        print(f"Joblib header type: {content[:2]}")

