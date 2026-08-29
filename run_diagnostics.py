import os
import traceback
import joblib

def test_load(filename):
    print("=" * 80)
    print(f"TESTING FILE: {filename}")
    size = os.path.getsize(filename)
    print(f"File size on disk: {size:,} bytes ({size / (1024*1024):.2f} MB)")
    print("-" * 80)
    try:
        obj = joblib.load(filename)
        print(f"[SUCCESS] Loaded successfully! Type: {type(obj)}")
    except Exception as e:
        print(f"[EXACT EXCEPTION TYPE]: {type(e).__name__}")
        print(f"[EXACT EXCEPTION MESSAGE]: {e}")
        print("\n[FULL TRACEBACK]:")
        traceback.print_exc()

print("1. CHECKING RANDOM FOREST AND EXTRA TREES:")
test_load("random_forest_cicids2017.pkl")
test_load("extra_trees_cicids2017.pkl")

print("\n2. CHECKING DATASET SPLIT ARTIFACTS:")
test_load("X_train.pkl")
test_load("X_test.pkl")
test_load("y_train.pkl")
test_load("y_test.pkl")

