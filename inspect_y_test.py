import joblib
import pandas as pd

y_test = joblib.load("y_test.pkl")
print("=== y_test info ===")
print("Type:", type(y_test))
print("Shape:", y_test.shape)
print("Unique classes:", sorted(y_test.unique()))
print("Class counts:\n", y_test.value_counts().sort_index())

