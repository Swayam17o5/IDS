import os
import joblib
from joblib.numpy_pickle import NumpyUnpickler

def debug_unpickle(filename):
    print(f"\n================ Debugging {filename} ================")
    print("File size:", os.path.getsize(filename))
    with open(filename, "rb") as f:
        unpickler = NumpyUnpickler(filename, f, False)
        try:
            res = unpickler.load()
            print("Loaded successfully:", type(res))
        except Exception as e:
            print("Failed at file tell():", f.tell(), "/", os.path.getsize(filename))
            print("Exception:", type(e), e)

for fn in ["random_forest_cicids2017.pkl", "extra_trees_cicids2017.pkl", "X_train.pkl", "X_test.pkl", "y_train.pkl"]:
    if os.path.exists(fn):
        debug_unpickle(fn)

