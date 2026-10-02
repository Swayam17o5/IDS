"""
database/db.py
---------------
Database engine and session factory.

Supports both SQLite (default, dev/test) and PostgreSQL (production).

Set the DATABASE_URL environment variable to switch:
  SQLite  (default): sqlite:///./nids.db
  Postgres:          postgresql://user:password@host:5432/nids

Phase 1 additions
-----------------
  - WAL mode for SQLite (reduces write contention)
  - Column migration helper so existing SQLite DBs get new Phase 1 columns
  - Model card seeding
"""

import os
import logging
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker
from database.models import Base, DBModelCard
from services.registry.registry import ModelRegistry

logger = logging.getLogger("aegis.database")

# ─── Connection URL ─────────────────────────────────────────────────────────
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./nids.db")

_IS_SQLITE = DATABASE_URL.startswith("sqlite")
_IS_POSTGRES = DATABASE_URL.startswith("postgresql") or DATABASE_URL.startswith("postgres")

# ─── Engine ──────────────────────────────────────────────────────────────────
_connect_args = {}
if _IS_SQLITE:
    _connect_args["check_same_thread"] = False

engine = create_engine(
    DATABASE_URL,
    connect_args=_connect_args,
    # PostgreSQL connection pooling tuning (no-op for SQLite)
    pool_size=10 if _IS_POSTGRES else 5,
    max_overflow=20 if _IS_POSTGRES else 10,
    pool_pre_ping=True,
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


# ─── Migration helpers ───────────────────────────────────────────────────────

def _sqlite_add_column_if_missing(conn, table: str, col: str, col_type: str) -> None:
    """Idempotent ALTER TABLE for SQLite (which does not support IF NOT EXISTS)."""
    try:
        conn.execute(text(f"ALTER TABLE {table} ADD COLUMN {col} {col_type}"))
        conn.commit()
        logger.debug("Migration: added column %s.%s", table, col)
    except Exception:
        pass  # Column already exists — expected on subsequent starts


_SQLITE_MIGRATIONS = [
    # (table, column, type_spec)
    ("flows",       "flow_id",          "VARCHAR(100)"),
    ("flows",       "duration_seconds", "FLOAT"),
    ("flows",       "packet_count",     "INTEGER"),
    ("flows",       "byte_count",       "INTEGER"),
    ("predictions", "model_version",    "VARCHAR(50) DEFAULT '1.0'"),
    ("predictions", "detection_method", "VARCHAR(50) DEFAULT 'MACHINE_LEARNING'"),
    ("predictions", "detection_confidence", "FLOAT"),
    ("predictions", "ml_predicted_label",   "VARCHAR(100)"),
    ("predictions", "ml_confidence",    "FLOAT"),
    ("predictions", "ml_portscan_prob", "FLOAT"),
    ("predictions", "extraction_latency_ms",  "FLOAT"),
    ("predictions", "validation_latency_ms",  "FLOAT"),
    ("predictions", "inference_latency_ms",   "FLOAT"),
    ("predictions", "db_latency_ms",          "FLOAT"),
    ("predictions", "total_latency_ms",       "FLOAT"),
    ("alerts",      "detection_method",       "VARCHAR(50) DEFAULT 'MACHINE_LEARNING'"),
    ("alerts",      "detection_confidence",   "FLOAT"),
    ("alerts",      "ml_predicted_label",     "VARCHAR(100)"),
    ("alerts",      "ml_confidence",          "FLOAT"),
    ("alerts",      "src_port",               "INTEGER"),
    ("alerts",      "flow_count",             "INTEGER DEFAULT 1"),
    ("alerts",      "first_seen",             "DATETIME"),
    ("alerts",      "last_seen",              "DATETIME"),
    ("alerts",      "incident_id",            "VARCHAR(50)"),
]


def init_db() -> None:
    """Create all tables, run migrations, seed model registry."""
    logger.info("Initialising database: %s", DATABASE_URL.split("@")[-1] if "@" in DATABASE_URL else DATABASE_URL)

    # Create tables (idempotent)
    Base.metadata.create_all(bind=engine)

    # SQLite column migrations for existing databases
    if _IS_SQLITE:
        with engine.connect() as conn:
            for table, col, col_type in _SQLITE_MIGRATIONS:
                _sqlite_add_column_if_missing(conn, table, col, col_type)

        # Enable WAL mode to reduce lock contention under concurrent writes
        with engine.connect() as conn:
            conn.execute(text("PRAGMA journal_mode=WAL"))
            conn.commit()
            logger.debug("SQLite WAL mode enabled")

    # Seed model registry from model cards on disk
    _seed_model_registry()

    logger.info("Database initialised successfully")


def _seed_model_registry() -> None:
    """Upsert model cards from disk into the model_registry table."""
    db = SessionLocal()
    try:
        reg = ModelRegistry("models")
        seeded = 0
        for dataset in reg.list_datasets():
            for card in reg.get_models_for_dataset(dataset):
                existing = db.query(DBModelCard).filter(
                    DBModelCard.model_id == card["model_id"]
                ).first()
                metrics = card.get("metrics", {})
                if not existing:
                    db.add(DBModelCard(
                        model_id=card["model_id"],
                        name=card.get("name"),
                        dataset=card.get("dataset"),
                        framework=card.get("framework"),
                        accuracy=metrics.get("accuracy"),
                        precision=metrics.get("precision"),
                        recall=metrics.get("recall"),
                        f1_score=metrics.get("f1_score"),
                        training_time_seconds=metrics.get("training_time_seconds", 0.0),
                        is_active=(card["model_id"] == "stacking_ensemble_cicids2017"),
                        metadata_json=card,
                    ))
                    seeded += 1
                else:
                    existing.name = card.get("name")
                    existing.framework = card.get("framework")
                    existing.accuracy = metrics.get("accuracy")
                    existing.precision = metrics.get("precision")
                    existing.recall = metrics.get("recall")
                    existing.f1_score = metrics.get("f1_score")
                    existing.training_time_seconds = metrics.get("training_time_seconds", 0.0)
                    existing.metadata_json = card
        db.commit()
        if seeded:
            logger.info("Seeded %d new model card(s) into model_registry", seeded)
    except Exception as exc:
        db.rollback()
        logger.error("Model registry seeding failed: %s", exc)
    finally:
        db.close()


def get_db():
    """FastAPI dependency: yields a DB session and closes it on teardown."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    init_db()
    print("Database initialised and seeded successfully!")
