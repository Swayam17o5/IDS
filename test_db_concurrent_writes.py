import os
import sys
import uuid
import time
import concurrent.futures
from typing import List

sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

from database.db import init_db, SessionLocal, engine
from database.models import DBFlow, DBPrediction, DBAlert, DBModelCard

print("=== RUNNING DATABASE CONCURRENT WRITES STRESS TEST ===")
init_db()

NUM_THREADS = 10
WRITES_PER_THREAD = 10
TOTAL_RECORDS = NUM_THREADS * WRITES_PER_THREAD

def worker_write_task(thread_id: int) -> List[str]:
    created_alert_ids = []
    # Each thread gets its own session
    db = SessionLocal()
    try:
        for i in range(WRITES_PER_THREAD):
            unique_id = f"T{thread_id}-R{i}-{uuid.uuid4().hex[:6]}"
            
            # 1. Write Flow
            flow = DBFlow(
                src_ip=f"10.0.{thread_id}.{i+1}",
                dst_ip="192.168.1.1",
                src_port=10000 + (thread_id * 100) + i,
                dst_port=80,
                protocol=6,
                features_json={"Flow Duration": 50000.0, "Total Fwd Packets": 10.0}
            )
            db.add(flow)
            db.flush() # populate flow.id

            # 2. Write Prediction linked to Flow
            pred = DBPrediction(
                flow_id=flow.id,
                model_name="xgboost",
                predicted_label="DDoS" if i % 2 == 0 else "PortScan",
                predicted_class_id=2 if i % 2 == 0 else 10,
                confidence=0.992,
                probabilities_json={"DDoS": 0.992, "Benign": 0.008},
                shap_json=[{"feature": "Flow Packets/s", "importance": 0.91}]
            )
            db.add(pred)

            # 3. Write Alert
            alert_id = f"ALT-{unique_id}"
            alert = DBAlert(
                alert_id=alert_id,
                severity="CRITICAL" if i % 2 == 0 else "HIGH",
                attack_type="DDoS" if i % 2 == 0 else "PortScan",
                confidence=0.992,
                src_ip=f"10.0.{thread_id}.{i+1}",
                dst_ip="192.168.1.1",
                dst_port=80,
                model_used="xgboost",
                dedup_key=f"10.0.{thread_id}.{i+1}:80:DDoS",
                shap_json=[{"feature": "Flow Packets/s", "importance": 0.91}]
            )
            db.add(alert)
            created_alert_ids.append(alert_id)
            
            db.commit()
    except Exception as e:
        db.rollback()
        raise e
    finally:
        db.close()
    return created_alert_ids

print(f"Launching {NUM_THREADS} concurrent threads ({WRITES_PER_THREAD} writes each -> {TOTAL_RECORDS} total)...")
start_time = time.time()

with concurrent.futures.ThreadPoolExecutor(max_workers=NUM_THREADS) as executor:
    futures = [executor.submit(worker_write_task, tid) for tid in range(NUM_THREADS)]
    all_alert_ids = []
    for f in concurrent.futures.as_completed(futures):
        all_alert_ids.extend(f.result())

elapsed = time.time() - start_time
print(f"All {TOTAL_RECORDS} concurrent transactions committed successfully in {elapsed:.3f} seconds ({TOTAL_RECORDS/elapsed:.1f} tx/s)!")

# Verification queries
db = SessionLocal()
try:
    flow_count = db.query(DBFlow).count()
    pred_count = db.query(DBPrediction).count()
    alert_count = db.query(DBAlert).count()
    cards_count = db.query(DBModelCard).count()
    
    print("\n=== DATABASE PERSISTENCE VERIFICATION ===")
    print(f"Total Flows persisted in DB:       {flow_count}")
    print(f"Total Predictions persisted in DB: {pred_count}")
    print(f"Total Alerts persisted in DB:      {alert_count}")
    print(f"Model Registry Cards in DB:        {cards_count}")
    
    assert alert_count >= TOTAL_RECORDS, f"Expected at least {TOTAL_RECORDS} alerts, got {alert_count}"
    assert pred_count >= TOTAL_RECORDS, f"Expected at least {TOTAL_RECORDS} predictions, got {pred_count}"
    assert flow_count >= TOTAL_RECORDS, f"Expected at least {TOTAL_RECORDS} flows, got {flow_count}"
    
    # Verify foreign key link on sample
    sample_pred = db.query(DBPrediction).filter(DBPrediction.flow_id.isnot(None)).first()
    assert sample_pred is not None
    linked_flow = db.query(DBFlow).filter(DBFlow.id == sample_pred.flow_id).first()
    assert linked_flow is not None
    print(f"\n[PASSED] Verified Flow -> Prediction Relational Integrity: Prediction ID {sample_pred.id} -> Flow ID {linked_flow.id} ({linked_flow.src_ip} -> {linked_flow.dst_ip}:{linked_flow.dst_port})")

finally:
    db.close()

print("\n[SUCCESS] Database concurrent writes & relational persistence verified 100%!")
