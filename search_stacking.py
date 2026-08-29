import json
import re

with open("ids.ipynb", "r", encoding="utf-8") as f:
    nb = json.load(f)

print("=== SEARCHING ENTIRE NOTEBOOK FOR STACKING / ENSEMBLE ===")
found = False
for i, c in enumerate(nb['cells']):
    src = "".join(c.get('source', []))
    for term in ["stack", "Stacking", "ensemble", "voting", "Voting", "blend", "meta"]:
        if term in src:
            print(f"Cell {i} contains '{term}':\n{src}\n")
            found = True

if not found:
    print("No cells mentioned stacking / ensemble in code source!")

