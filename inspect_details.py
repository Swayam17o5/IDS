import json
import joblib
import torch
import os
import sys

def print_section(title):
    print("\n" + "="*50)
    print(f" {title} ")
    print("="*50)

# 1. Inspect all notebook cells with relevant keywords
with open("ids.ipynb", "r", encoding="utf-8") as f:
    nb = json.load(f)

print_section("NOTEBOOK CELL CONTENTS SUMMARY")
for i, cell in enumerate(nb['cells']):
    src = "".join(cell.get("source", []))
    # Look for key operations
    keywords = ["fit", "LabelEncoder", "StandardScaler", "Stacking", "Voting", "save", "dump", "torch.save", "columns", "drop", "transform", "results"]
    if any(k in src for k in keywords):
        print(f"\n--- Cell {i} ({cell.get('cell_type')}) ---")
        print(src)

