import json
import re

with open("ids.ipynb", "r", encoding="utf-8") as f:
    nb = json.load(f)

print("=== SEARCHING NOTEBOOK FOR CLASS LABELS ===")
for i, c in enumerate(nb['cells']):
    src = "".join(c.get('source', []))
    for out in c.get('outputs', []):
        text = ""
        if 'text' in out:
            text = "".join(out['text'])
        elif 'data' in out:
            for k, v in out['data'].items():
                text += str(v) + "\n"
        
        # Look for classification report or class names
        if "precision" in text and "recall" in text:
            print(f"\n--- Classification Report in Cell {i} ---")
            print(text[:1500])
        if "encoder.classes_" in src or "le.classes_" in src or "classes_" in src:
            print(f"\n--- classes_ in Cell {i} ---")
            print(src)
            print("Output:", text[:500])

