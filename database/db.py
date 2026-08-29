import os
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from database.models import Base, DBModelCard
from services.registry.registry import ModelRegistry

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./nids.db")

engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

from sqlalchemy import text

def init_db():
    Base.metadata.create_all(bind=engine)
    
    # Ensure any new columns exist in SQLite tables if migrating existing DB
    with engine.connect() as conn:
        for tbl, col, col_type in [
            ("predictions", "detection_method", "VARCHAR(50) DEFAULT 'MACHINE_LEARNING'"),
            ("predictions", "detection_confidence", "FLOAT"),
            ("predictions", "ml_predicted_label", "VARCHAR(100)"),
            ("predictions", "ml_confidence", "FLOAT"),
            ("predictions", "ml_portscan_prob", "FLOAT"),
            ("alerts", "detection_method", "VARCHAR(50) DEFAULT 'MACHINE_LEARNING'"),
            ("alerts", "detection_confidence", "FLOAT"),
            ("alerts", "ml_predicted_label", "VARCHAR(100)"),
            ("alerts", "ml_confidence", "FLOAT"),
        ]:
            try:
                conn.execute(text(f"ALTER TABLE {tbl} ADD COLUMN {col} {col_type}"))
                conn.commit()
            except Exception:
                pass  # Column already exists
    
    # Seed model registry from model cards
    db = SessionLocal()
    try:
        reg = ModelRegistry("models")
        for dataset in reg.list_datasets():
            models = reg.get_models_for_dataset(dataset)
            for m in models:
                existing = db.query(DBModelCard).filter(DBModelCard.model_id == m["model_id"]).first()
                if not existing:
                    mc = DBModelCard(
                        model_id=m["model_id"],
                        name=m["name"],
                        dataset=m["dataset"],
                        framework=m["framework"],
                        accuracy=m["metrics"].get("accuracy"),
                        precision=m["metrics"].get("precision"),
                        recall=m["metrics"].get("recall"),
                        f1_score=m["metrics"].get("f1_score"),
                        training_time_seconds=m["metrics"].get("training_time_seconds", 0.0),
                        is_active=(m["model_id"] == "stacking_ensemble_cicids2017"),
                        metadata_json=m
                    )
                    db.add(mc)
                else:
                    existing.name = m["name"]
                    existing.framework = m["framework"]
                    existing.accuracy = m["metrics"].get("accuracy")
                    existing.precision = m["metrics"].get("precision")
                    existing.recall = m["metrics"].get("recall")
                    existing.f1_score = m["metrics"].get("f1_score")
                    existing.training_time_seconds = m["metrics"].get("training_time_seconds", 0.0)
                    existing.metadata_json = m
        db.commit()
    finally:
        db.close()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

if __name__ == "__main__":
    init_db()
    print("Database initialized and seeded successfully!")
