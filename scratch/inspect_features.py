import os
import sys
import json
import numpy as np
import pandas as pd

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from database.db import SessionLocal
from database.models import DBFlow, DBPrediction, DBAlert

db = SessionLocal()
flows = db.query(DBFlow).limit(10).all()

with open("models/cicids2017/feature_list.json") as f:
    canon_feats = json.load(f)

print("="*80)
print("INSPECTING 77-FEATURE VECTORS OF CAPTURED LIVE FLOWS")
print("="*80)

for idx in [0, 1, 2, 4]:
    if idx >= len(flows): break
    f = flows[idx]
    feats = f.features_json
    print(f"\n>>> FLOW #{idx+1} [ID={f.id}]: {f.src_ip}:{f.src_port} -> {f.dst_ip}:{f.dst_port} (Proto {f.protocol})")
    
    # Key diagnostic features
    diag_keys = [
        "Protocol", "Destination Port", "Flow Duration",
        "Total Fwd Packets", "Total Backward Packets",
        "Fwd Packets Length Total", "Bwd Packets Length Total",
        "Fwd Packet Length Mean", "Bwd Packet Length Mean",
        "Flow IAT Mean", "Flow IAT Max", "Flow IAT Min",
        "Fwd IAT Mean", "Bwd IAT Mean",
        "Flow Packets/s", "Flow Bytes/s",
        "Init Fwd Win Bytes", "Init Bwd Win Bytes",
        "Fwd Header Length", "Bwd Header Length",
        "Fwd Seg Size Min", "SYN Flag Count", "ACK Flag Count", "FIN Flag Count", "RST Flag Count"
    ]
    
    print("  Key Extracted Features:")
    for k in diag_keys:
        v = feats.get(k, 0.0)
        print(f"    {k:30s}: {v:15.4f}")
    
    # Check for anomalies (zeros, negative, NaNs, infs)
    nans = [k for k, v in feats.items() if np.isnan(v)]
    infs = [k for k, v in feats.items() if np.isinf(v)]
    negs = [k for k, v in feats.items() if v < 0]
    print(f"  Integrity Check: NaNs={len(nans)}, Infs={len(infs)}, Negatives={len(negs)}")
