"""
database/models.py
--------------------
SQLAlchemy ORM models for AegisNIDS Phase 1.

Schema
------
flows        – one row per completed network flow (metadata only)
predictions  – one ML inference result per flow
alerts       – deduplicated security incident, grouped by (src_ip, dst_ip, attack_type)
analyst_feedback – analyst triage corrections for retraining
model_registry   – model cards seeded from models/*/model_cards/*.json

Phase 1 additions
-----------------
  - alerts.flow_count  (count of flows grouped into this incident)
  - alerts.first_seen  (timestamp of first detection in the group)
  - alerts.last_seen   (timestamp of most recent detection)
  - alerts.src_port    (source port – was missing)
  - flows.duration_seconds, packet_count, byte_count (richer flow context)
  - Indexes on all commonly-queried columns
"""

import datetime
from sqlalchemy import (
    Column, Integer, String, Float, Boolean,
    DateTime, Text, JSON, ForeignKey, Index,
)
from sqlalchemy.orm import declarative_base, relationship

Base = declarative_base()

# Valid triage statuses
ALERT_STATUSES = ("NEW", "ACKNOWLEDGED", "FALSE_POSITIVE", "ESCALATED", "RESOLVED")


# ---------------------------------------------------------------------------
# flows
# ---------------------------------------------------------------------------

class DBFlow(Base):
    __tablename__ = "flows"

    id               = Column(Integer, primary_key=True, autoincrement=True)
    flow_id          = Column(String(100), nullable=True, index=True)  # optional external id
    timestamp        = Column(
        DateTime(timezone=True),
        default=lambda: datetime.datetime.now(datetime.timezone.utc),
        index=True,
    )
    src_ip           = Column(String(50), nullable=False, index=True)
    dst_ip           = Column(String(50), nullable=False, index=True)
    src_port         = Column(Integer, nullable=True)
    dst_port         = Column(Integer, nullable=True, index=True)
    protocol         = Column(Integer, nullable=True)
    duration_seconds = Column(Float,   nullable=True)   # Phase 1 addition
    packet_count     = Column(Integer, nullable=True)   # Phase 1 addition
    byte_count       = Column(Integer, nullable=True)   # Phase 1 addition
    features_json    = Column(JSON,    nullable=True)   # full 77-feature snapshot

    __table_args__ = (
        Index("ix_flows_timestamp_src", "timestamp", "src_ip"),
        Index("ix_flows_timestamp_dst", "timestamp", "dst_ip"),
    )


# ---------------------------------------------------------------------------
# predictions
# ---------------------------------------------------------------------------

class DBPrediction(Base):
    __tablename__ = "predictions"

    id                  = Column(Integer, primary_key=True, autoincrement=True)
    flow_id             = Column(Integer, ForeignKey("flows.id"), nullable=True, index=True)
    timestamp           = Column(
        DateTime(timezone=True),
        default=lambda: datetime.datetime.now(datetime.timezone.utc),
        index=True,
    )
    model_name          = Column(String(100), nullable=False, index=True)
    model_version       = Column(String(50),  nullable=True, default="1.0")  # Phase 1 addition
    predicted_label     = Column(String(100), nullable=False, index=True)
    predicted_class_id  = Column(Integer,     nullable=True)
    confidence          = Column(Float,        nullable=False)
    detection_method    = Column(String(50),   nullable=True, default="MACHINE_LEARNING")
    detection_confidence = Column(Float,       nullable=True)
    ml_predicted_label  = Column(String(100),  nullable=True)
    ml_confidence       = Column(Float,        nullable=True)
    ml_portscan_prob    = Column(Float,        nullable=True)
    probabilities_json  = Column(JSON,         nullable=True)
    shap_json           = Column(JSON,         nullable=True)
    # Performance timing (Phase 1)
    extraction_latency_ms  = Column(Float, nullable=True)
    validation_latency_ms  = Column(Float, nullable=True)
    inference_latency_ms   = Column(Float, nullable=True)
    db_latency_ms          = Column(Float, nullable=True)
    total_latency_ms       = Column(Float, nullable=True)


# ---------------------------------------------------------------------------
# alerts
# ---------------------------------------------------------------------------

class DBAlert(Base):
    __tablename__ = "alerts"

    id                   = Column(Integer, primary_key=True, autoincrement=True)
    alert_id             = Column(String(50), unique=True, nullable=False, index=True)
    timestamp            = Column(
        DateTime(timezone=True),
        default=lambda: datetime.datetime.now(datetime.timezone.utc),
        index=True,
    )
    severity             = Column(String(20), nullable=False, index=True)
    attack_type          = Column(String(100), nullable=False, index=True)
    confidence           = Column(Float, nullable=False)
    detection_method     = Column(String(50),  nullable=True, default="MACHINE_LEARNING")
    detection_confidence = Column(Float,        nullable=True)
    ml_predicted_label   = Column(String(100),  nullable=True)
    ml_confidence        = Column(Float,        nullable=True)
    src_ip               = Column(String(50), nullable=True, index=True)
    dst_ip               = Column(String(50), nullable=True, index=True)
    src_port             = Column(Integer,    nullable=True)           # Phase 1 addition
    dst_port             = Column(Integer,    nullable=True)
    model_used           = Column(String(100), nullable=True)
    dedup_key            = Column(String(200), nullable=True, index=True)

    # Triage workflow
    status               = Column(String(20), nullable=False, default="NEW", index=True)

    # Incident grouping (Phase 1)
    flow_count           = Column(Integer, nullable=False, default=1)
    first_seen           = Column(DateTime(timezone=True), nullable=True)
    last_seen            = Column(DateTime(timezone=True), nullable=True)

    # Explainability
    shap_json            = Column(JSON, nullable=True)
    explanation          = Column(Text, nullable=True)

    # Incident linkage (Phase 2)
    incident_id          = Column(String(50), ForeignKey("incidents.incident_id"), nullable=True, index=True)

    __table_args__ = (
        Index("ix_alerts_attack_status", "attack_type", "status"),
        Index("ix_alerts_src_attack", "src_ip", "attack_type"),
        Index("ix_alerts_timestamp_sev", "timestamp", "severity"),
    )

    @property
    def is_acknowledged(self) -> bool:
        """Backward-compatible: True if triage status is not NEW."""
        return self.status != "NEW"


# ---------------------------------------------------------------------------
# incidents (Phase 2)
# ---------------------------------------------------------------------------

INCIDENT_STATUSES = ("NEW", "ACKNOWLEDGED", "INVESTIGATING", "RESOLVED", "FALSE_POSITIVE")

class DBIncident(Base):
    __tablename__ = "incidents"

    id                 = Column(Integer, primary_key=True, autoincrement=True)
    incident_id        = Column(String(50), unique=True, nullable=False, index=True)
    title              = Column(String(200), nullable=False)
    status             = Column(String(30), nullable=False, default="NEW", index=True)
    severity           = Column(String(20), nullable=False, default="MEDIUM", index=True)
    attack_type        = Column(String(100), nullable=False, index=True)
    src_ip             = Column(String(50), nullable=True, index=True)
    dst_ip             = Column(String(50), nullable=True, index=True)
    created_at         = Column(
        DateTime(timezone=True),
        default=lambda: datetime.datetime.now(datetime.timezone.utc),
        index=True,
    )
    updated_at         = Column(
        DateTime(timezone=True),
        default=lambda: datetime.datetime.now(datetime.timezone.utc),
        onupdate=lambda: datetime.datetime.now(datetime.timezone.utc),
    )
    resolved_at        = Column(DateTime(timezone=True), nullable=True)
    assigned_analyst   = Column(String(100), nullable=True)
    analyst_notes      = Column(Text, nullable=True)
    resolution_reason  = Column(Text, nullable=True)

    alerts = relationship("DBAlert", backref="incident", lazy="joined", foreign_keys=[DBAlert.incident_id])


class DBIncidentAlert(Base):
    __tablename__ = "incident_alerts"

    id          = Column(Integer, primary_key=True, autoincrement=True)
    incident_id = Column(String(50), ForeignKey("incidents.incident_id"), nullable=False, index=True)
    alert_id    = Column(String(50), ForeignKey("alerts.alert_id"), nullable=False, index=True)
    added_at    = Column(
        DateTime(timezone=True),
        default=lambda: datetime.datetime.now(datetime.timezone.utc),
    )


class DBIncidentNote(Base):
    __tablename__ = "incident_notes"

    id          = Column(Integer, primary_key=True, autoincrement=True)
    incident_id = Column(String(50), ForeignKey("incidents.incident_id"), nullable=False, index=True)
    author      = Column(String(100), default="Analyst")
    note        = Column(Text, nullable=False)
    created_at  = Column(
        DateTime(timezone=True),
        default=lambda: datetime.datetime.now(datetime.timezone.utc),
    )


# ---------------------------------------------------------------------------
# pcap_replays (Phase 2)
# ---------------------------------------------------------------------------

class DBPCAPReplay(Base):
    __tablename__ = "pcap_replays"

    id                    = Column(Integer, primary_key=True, autoincrement=True)
    replay_id             = Column(String(50), unique=True, nullable=False, index=True)
    filename              = Column(String(255), nullable=False)
    status                = Column(String(30), nullable=False, default="COMPLETED", index=True)
    started_at            = Column(
        DateTime(timezone=True),
        default=lambda: datetime.datetime.now(datetime.timezone.utc),
    )
    completed_at          = Column(DateTime(timezone=True), nullable=True)
    packets_processed     = Column(Integer, default=0)
    flows_generated       = Column(Integer, default=0)
    predictions_generated = Column(Integer, default=0)
    alerts_generated      = Column(Integer, default=0)
    duration_seconds      = Column(Float, default=0.0)
    error_message         = Column(Text, nullable=True)


# ---------------------------------------------------------------------------
# analyst_feedback
# ---------------------------------------------------------------------------

class DBAnalystFeedback(Base):
    """Analyst corrections captured for future retraining."""
    __tablename__ = "analyst_feedback"

    id              = Column(Integer, primary_key=True, autoincrement=True)
    alert_id        = Column(String(50), ForeignKey("alerts.alert_id"), index=True)
    timestamp       = Column(
        DateTime(timezone=True),
        default=lambda: datetime.datetime.now(datetime.timezone.utc),
    )
    original_label  = Column(String(100), nullable=False)
    corrected_label = Column(String(100), nullable=False)
    features_json   = Column(JSON,        nullable=False)
    shap_json       = Column(JSON,        nullable=True)
    analyst_notes   = Column(Text,        nullable=True)
    model_used      = Column(String(100), nullable=True)
    confidence      = Column(Float,       nullable=True)


# ---------------------------------------------------------------------------
# model_registry
# ---------------------------------------------------------------------------

class DBModelCard(Base):
    __tablename__ = "model_registry"

    id                      = Column(Integer, primary_key=True, autoincrement=True)
    model_id                = Column(String(100), unique=True, nullable=False, index=True)
    name                    = Column(String(150), nullable=True)
    dataset                 = Column(String(50),  nullable=True, index=True)
    framework               = Column(String(50),  nullable=True)
    accuracy                = Column(Float, nullable=True)
    precision               = Column(Float, nullable=True)
    recall                  = Column(Float, nullable=True)
    f1_score                = Column(Float, nullable=True)
    training_time_seconds   = Column(Float, nullable=True)
    is_active               = Column(Boolean, default=False)
    metadata_json           = Column(JSON,    nullable=True)

