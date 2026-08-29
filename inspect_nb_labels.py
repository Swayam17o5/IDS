import json
import os

with open("ids.ipynb", "r", encoding="utf-8") as f:
    nb = json.load(f)

print("=== CELL 16, 17, 18 ===")
for i in [13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25]:
    c = nb['cells'][i]
    print(f"--- Cell {i} ---")
    print("".join(c.get('source', [])))
    print("OUTPUTS:")
    for out in c.get('outputs', []):
        if 'text' in out:
            print("".join(out['text']))
        elif 'data' in out:
            for k, v in out['data'].items():
                print(f"[{k}] {v[:300] if isinstance(v, str) else v}")

print("\n=== CELL 118-126 ===")
for i in range(118, 127):
    c = nb['cells'][i]
    print(f"--- Cell {i} ---")
    print("".join(c.get('source', [])))
    print("OUTPUTS:")
    for out in c.get('outputs', []):
        if 'text' in out:
            print("".join(out['text']))
        elif 'data' in out:
            for k, v in out['data'].items():
                print(f"[{k}] {v[:300] if isinstance(v, str) else v}")

print("\n=== CHECKING FIRST 100 BYTES OF SPLIT FILES ===")
for f in ["X_train.pkl", "X_test.pkl", "y_train.pkl", "y_test.pkl"]:
    with open(f, "rb") as fp:
        head = fp.read(100)
        print(f"{f}: size={os.path.getsize(f)}, head={head[:50]}")
