import json

with open("ids.ipynb", "r", encoding="utf-8") as f:
    nb = json.load(f)

for idx in [64, 69, 84]:
    print(f"\n================ CELL {idx} OUTPUT RAW ================")
    for out in nb['cells'][idx].get('outputs', []):
        if 'text' in out:
            print("".join(out['text']))

