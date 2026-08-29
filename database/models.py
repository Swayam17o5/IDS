import os
import datetime
from sqlalchemy import (
    create_engine, Column, Integer, String, Float, Boolean, DateTime, Text, JSON, ForeignKey
)
from sqlalchemy.orm import declarative_base, sessionmaker, relationship

Base = declarative_base()

# Valid alert statuses for the triage workflow
ALERT_STATUSES = ("NEW", "ACKNOWLEDGED", "FALSE_POSITIVE", "ESCALATED", "RESOLVED")

class DBFlow(Base):
    __tablename__ = "flows"
    id = Column(Integer, primary_key=True, autoincrement=True)
    timestamp = Column(DateTime, default=lambda: datetime.datetime.now(datetime.timezone.utc))
    src_ip = Column(String(50), index=True)
    dst_ip = Column(String(50), index=True)
    src_port = Column(Integer)
    dst_port = Column(Integer, index=True)
    protocol = Column(Integer)
    features_json = Column(JSON)

class DBPrediction(Base):
    __tablename__ = "predictions"
    id = Column(Integer, primary_key=True, autoincrement=True)
    flow_id = Column(Integer, ForeignKey("flows.id"), nullable=True)
    timestamp = Column(DateTime, default=lambda: datetime.datetime.now(datetime.timezone.utc))
    model_name = Column(String(100), index=True)
    predicted_label = Column(String(100), index=True)
    predicted_class_id = Column(Integer)
    confidence = Column(Float)
    detection_method = Column(String(50), default="MACHINE_LEARNING")
    detection_confidence = Column(Float, nullable=True)
    ml_predicted_label = Column(String(100), nullable=True)
    ml_confidence = Column(Float, nullable=True)
    ml_portscan_prob = Column(Float, nullable=True)
    probabilities_json = Column(JSON)
    shap_json = Column(JSON, nullable=True)

class DBAlert(Base):
    __tablename__ = "alerts"
    id = Column(Integer, primary_key=True, autoincrement=True)
    alert_id = Column(String(50), unique=True, index=True)
    timestamp = Column(DateTime, default=lambda: datetime.datetime.now(datetime.timezone.utc))
    severity = Column(String(20), index=True) # CRITICAL, HIGH, MEDIUM, LOW
    attack_type = Column(String(100), index=True)
    confidence = Column(Float)
    detection_method = Column(String(50), default="MACHINE_LEARNING")
    detection_confidence = Column(Float, nullable=True)
    ml_predicted_label = Column(String(100), nullable=True)
    ml_confidence = Column(Float, nullable=True)
    src_ip = Column(String(50), index=True)
    dst_ip = Column(String(50), index=True)
    dst_port = Column(Integer)
    model_used = Column(String(100))
    dedup_key = Column(String(200), index=True)
    # Triage workflow: replaces the old boolean is_acknowledged
    status = Column(String(20), default="NEW", index=True)  # NEW, ACKNOWLEDGED, FALSE_POSITIVE, ESCALATED, RESOLVED
    shap_json = Column(JSON, nullable=True)
    explanation = Column(Text, nullable=True)  # Plain-language alert explanation

    @property
    def is_acknowledged(self):
        """Backward-compatible property: True if status is anything other than NEW."""
        return self.status != "NEW"

class DBAnalystFeedback(Base):
    """
    Stores analyst corrections when an alert is marked as FALSE_POSITIVE.
    Schema is designed for future retraining: captures the full feature vector,
    the model's original prediction, and the analyst's corrected label.
    """
    __tablename__ = "analyst_feedback"
    id = Column(Integer, primary_key=True, autoincrement=True)
    alert_id = Column(String(50), ForeignKey("alerts.alert_id"), index=True)
    timestamp = Column(DateTime, default=lambda: datetime.datetime.now(datetime.timezone.utc))
    original_label = Column(String(100), nullable=False)     # Model's predicted attack type
    corrected_label = Column(String(100), nullable=False)    # Analyst's correction (e.g. "Benign")
    features_json = Column(JSON, nullable=False)             # Full 77-feature vector snapshot
    shap_json = Column(JSON, nullable=True)                  # SHAP explanations at time of alert
    analyst_notes = Column(Text, nullable=True)              # Free-text justification
    model_used = Column(String(100))                         # Which model generated the prediction
    confidence = Column(Float)                               # Original model confidence

class DBModelCard(Base):
    __tablename__ = "model_registry"
    id = Column(Integer, primary_key=True, autoincrement=True)
    model_id = Column(String(100), unique=True, index=True)
    name = Column(String(150))
    dataset = Column(String(50), index=True)
    framework = Column(String(50))
    accuracy = Column(Float)
    precision = Column(Float)
    recall = Column(Float)
    f1_score = Column(Float)
    training_time_seconds = Column(Float)
    is_active = Column(Boolean, default=False)
    metadata_json = Column(JSON)
