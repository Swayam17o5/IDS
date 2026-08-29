import uuid
import pytest
from database.db import init_db, SessionLocal
from database.models import DBFlow, DBPrediction, DBAlert, DBModelCard

def test_database_init_and_seeding():
    init_db()
    db = SessionLocal()
    try:
        cards = db.query(DBModelCard).all()
        assert len(cards) >= 6
        xgb_card = db.query(DBModelCard).filter(DBModelCard.model_id == "xgboost_cicids2017").first()
        assert xgb_card is not None
        assert xgb_card.accuracy > 0.99
    finally:
        db.close()

def test_alert_persistence():
    init_db()
    db = SessionLocal()
    test_id = f"ALT-TEST-{uuid.uuid4().hex[:8]}"
    try:
        new_alert = DBAlert(
            alert_id=test_id,
            severity="CRITICAL",
            attack_type="DDoS",
            confidence=0.99,
            src_ip="192.168.1.10",
            dst_ip="192.168.1.1",
            dst_port=80,
            model_used="xgboost",
            dedup_key=f"192.168.1.10:80:DDoS-{test_id}",
            shap_json=[{"feature": "Flow Packets/s", "importance": 0.88}]
        )
        db.add(new_alert)
        db.commit()
        
        fetched = db.query(DBAlert).filter(DBAlert.alert_id == test_id).first()
        assert fetched is not None
        assert fetched.attack_type == "DDoS"
        assert fetched.severity == "CRITICAL"
        
        # Cleanup
        db.delete(fetched)
        db.commit()
    finally:
        db.close()
