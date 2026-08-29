import json
import os
import sys

def inspect_notebook(nb_path):
    print("=== INSPECTING NOTEBOOK ===")
    with open(nb_path, "r", encoding="utf-8") as f:
        nb = json.load(f)
    print(f"Total cells in {nb_path}: {len(nb['cells'])}")
    for i, cell in enumerate(nb['cells']):
        source = "".join(cell.get("source", []))
        cell_type = cell.get("cell_type", "")
        # print first line or header
        first_line = source.strip().split("\n")[0] if source.strip() else "(empty)"
        print(f"Cell {i} [{cell_type}]: {first_line[:100]}")

if __name__ == "__main__":
    inspect_notebook("ids.ipynb")
