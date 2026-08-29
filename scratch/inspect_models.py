import os
import sys
import json
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from database.db import SessionLocal
from database.models import DBFlow, DBPrediction, DBAlert
from services.inference.app import execute_flow_prediction, FlowPredictRequest, init_models

init_models("cicids2017")
db = SessionLocal()
flows = db.query(DBFlow).limit(5).all()

for i, flow in enumerate(flows):
    print("="*70)
    print(f"FLOW #{i+1} (ID={flow.id}): {flow.src_ip}:{flow.src_port} -> {flow.dst_ip}:{flow.dst_port}")
    req = FlowPredictRequest(
        features=flow.features_json,
        metadata={"src_ip": flow.src_ip, "dst_ip": flow.dst_ip, "src_port": flow.src_port, "dst_port": flow.dst_port, "protocol": flow.protocol}
    )
    res = execute_flow_prediction(req, db)
    print(f"Active Model Final Verdict: {res['final_verdict']['active_model_used']} -> {res['final_verdict']['predicted_label']} ({res['final_verdict']['confidence']:.4f})")
    print("All Model Predictions:")
    for m, p in res["all_model_predictions"].items():
        print(f"  {m:25s}: {p['predicted_label']:25s} | Conf={p['confidence']:.4f}")
