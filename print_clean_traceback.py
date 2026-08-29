import os
import traceback
import joblib

for filename in ["random_forest_cicids2017.pkl", "extra_trees_cicids2017.pkl", "X_train.pkl", "X_test.pkl", "y_train.pkl", "y_test.pkl"]:
    size = os.path.getsize(filename)
    print("=" * 80)
    print(f"FILE: {filename}")
    print(f"Size on disk: {size:,} bytes ({size / (1024*1024):.2f} MB)")
    try:
        obj = joblib.load(filename)
        print(f"Status: SUCCESS - Loaded {type(obj)}")
    except Exception as e:
        print("Status: FAILED")
        print(f"Error: {type(e).__name__}: {e}")
        print("Traceback:")
        traceback.print_exc(limit=3)
    print()

