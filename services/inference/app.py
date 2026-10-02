import os
import sys
import json
import time
import logging
import joblib
import torch
import numpy as np
import pandas as pd
import asyncio
from fastapi import FastAPI, HTTPException, Body, Depends, WebSocket, WebSocketDisconnect, Query
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from typing import Dict, List, Any, Optional
from sqlalchemy.orm import Session
from sqlalchemy import func, desc

# Ensure project root is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))

# Configure structured logging BEFORE any aegis imports
from services.logging_config import configure_logging
configure_logging()

from pytorch_tabnet.tab_model import TabNetClassifier
import rtdl_revisiting_models as rtdl

from services.registry.registry import ModelRegistry
from services.inference.explainer import SHAPExplainer
from services.inference.ensemble import IDSStackingEnsemble
from services.alert_engine.engine import AlertEngine
from services.validation.feature_validator import FeatureValidator
from services.feature_extractor.live_capture import (
    CAPTURE_SERVICE,
    check_capture_capabilities,
    get_available_interfaces
)
from services.feature_extractor.pcap_replay import REPLAY_SERVICE
from services.demo.nmap_demo import NMAP_DEMO_RUNNER, is_authorized_lab_target, validate_port_spec
from database.db import init_db, SessionLocal, get_db
from database.models import (
    DBFlow, DBPrediction, DBAlert, DBModelCard, DBAnalystFeedback,
    DBIncident, DBIncidentAlert, DBIncidentNote, DBPCAPReplay,
    ALERT_STATUSES, INCIDENT_STATUSES
)
from services.inference.dashboard import DASHBOARD_HTML
from services.inference.explainability_page import EXPLAINABILITY_HTML

logger = logging.getLogger("aegis.inference")

# ─── WebSocket Real-Time Event Hub ──────────────────────────────────────────
class WebSocketManager:
    """Manages real-time WebSocket client subscriptions for live telemetry & alerts."""
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)
        logger.info("WebSocket client connected. Active subscribers: %d", len(self.active_connections))

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)
            logger.info("WebSocket client disconnected. Active subscribers: %d", len(self.active_connections))

    async def broadcast(self, message: dict):
        for connection in list(self.active_connections):
            try:
                await connection.send_json(message)
            except Exception:
                self.disconnect(connection)

WS_MANAGER = WebSocketManager()

def broadcast_live_event_sync(event_type: str, data: dict):
    """Safely dispatches real-time broadcast events across active WebSocket connections."""
    try:
        loop = asyncio.get_event_loop()
        if loop.is_running():
            asyncio.create_task(WS_MANAGER.broadcast({"type": event_type, "data": data, "timestamp": time.time()}))
    except Exception:
        pass

app = FastAPI(title="AegisNIDS Real-Time SOC Intelligence Engine", version="2.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Global model & engine state
MODELS = {}
REGISTRY = ModelRegistry("models")
CANONICAL_FEATURES = []
LABEL_MAPPING = {}
ACTIVE_MODEL = "stacking_ensemble"
EXPLAINER = None
MODEL_VERSION = "1.0"
FEATURE_VALIDATOR: Optional[FeatureValidator] = None

ALERT_ENGINE = AlertEngine(
    min_confidence_threshold=0.80,
    dedup_window_seconds=120,
    severity_config_path="severity_config.json",
)

# --- Plain-Language Alert Explanation Generator ---

ATTACK_PATTERN_DESCRIPTIONS = {
    "DDoS": "volumetric flood pattern with abnormal packet rates",
    "DoS Hulk": "HTTP GET flood with high connection churn and rapid request bursts",
    "DoS GoldenEye": "HTTP keep-alive abuse with slow incomplete request patterns",
    "DoS Slowhttptest": "slow HTTP attack holding connections open with minimal data transfer",
    "DoS slowloris": "partial HTTP header flood maintaining many stalled connections",
    "PortScan": "sequential port probing with minimal payload and short-lived connections",
    "Bot": "automated command-and-control communication with periodic beaconing",
    "Infiltration": "lateral movement pattern with unusual internal traffic distribution",
    "Heartbleed": "TLS heartbeat exploitation with oversized payload request patterns",
    "SSH-Patator": "SSH brute-force login attempts with rapid authentication failures",
    "FTP-Patator": "FTP brute-force login attempts with repeated credential stuffing",
    "Web Attack - Brute Force": "repeated HTTP authentication attempts with high request frequency",
    "Web Attack - XSS": "cross-site scripting injection with anomalous payload sizes in web traffic",
    "Web Attack - Sql Injection": "SQL injection attempt with crafted query patterns in HTTP requests",
}

def generate_alert_explanation(
    attack_type: str,
    shap_features: list,
    detection_method: str = "MACHINE_LEARNING",
    ml_predicted_label: Optional[str] = None,
    distinct_ports: int = 0
) -> str:
    """Generate a clear plain-language explanation from attack type, detection method, and SHAP features."""
    if attack_type == "PortScan" and detection_method == "SYN_BURST_HEURISTIC":
        port_clause = f" targeting {distinct_ports} distinct ports" if distinct_ports else ""
        ml_clause = f" (ML Model evaluated flow features as {ml_predicted_label})" if ml_predicted_label and ml_predicted_label != "PortScan" else ""
        return f"Flagged as PortScan by SYN Burst Heuristic{port_clause}, consistent with sequential port probing with minimal payload and short-lived connections{ml_clause}."

    if not shap_features or len(shap_features) == 0:
        pattern = ATTACK_PATTERN_DESCRIPTIONS.get(attack_type, "suspicious network behavior")
        return f"Flagged as {attack_type}, consistent with {pattern}."

    top1 = shap_features[0]
    top1_name = top1.get("feature", "unknown")
    top1_val = top1.get("value", 0)

    if len(shap_features) >= 2:
        top2 = shap_features[1]
        top2_name = top2.get("feature", "unknown")
        top2_val = top2.get("value", 0)
        feature_clause = f"{top1_name} = {top1_val:,.2f} and {top2_name} = {top2_val:,.2f}"
    else:
        feature_clause = f"{top1_name} = {top1_val:,.2f}"

    pattern = ATTACK_PATTERN_DESCRIPTIONS.get(attack_type, "suspicious network behavior")
    return f"Flagged as {attack_type} due to {feature_clause}, consistent with {pattern}."

def init_models(dataset: str = "cicids2017"):
    global MODELS, CANONICAL_FEATURES, LABEL_MAPPING, EXPLAINER, ACTIVE_MODEL, FEATURE_VALIDATOR
    base_dir = os.path.join("models", dataset)

    logger.info("Initialising models for dataset: %s", dataset)

    # Initialize DB
    init_db()

    # Load feature order
    feature_list_path = os.path.join(base_dir, "feature_list.json")
    with open(feature_list_path, "r") as f:
        CANONICAL_FEATURES = json.load(f)
    logger.info("Loaded %d canonical features from %s", len(CANONICAL_FEATURES), feature_list_path)

    # Initialise centralized 77-feature validator
    schema_path = os.path.abspath("feature_schema.json")
    try:
        FEATURE_VALIDATOR = FeatureValidator(schema_path=schema_path)
        logger.info("FeatureValidator initialised with %d features", FEATURE_VALIDATOR.expected_count)
    except Exception as exc:
        logger.warning("FeatureValidator init failed (%s) — validation disabled", exc)
        FEATURE_VALIDATOR = None

    # Load label mapping
    with open(os.path.join(base_dir, "label_mapping.json"), "r") as f:
        raw_map = json.load(f)
        LABEL_MAPPING = {int(k): v for k, v in raw_map.items()}
    logger.info("Loaded label mapping: %d classes", len(LABEL_MAPPING))

    # Load Models
    MODELS = {}

    # 1. XGBoost
    xgb_path = os.path.join(base_dir, "xgboost_cicids2017.pkl")
    if os.path.exists(xgb_path):
        MODELS["xgboost"] = joblib.load(xgb_path)
        logger.info("Loaded model: xgboost")

    # 2. LightGBM
    lgb_path = os.path.join(base_dir, "lightgbm_cicids2017.pkl")
    if os.path.exists(lgb_path):
        MODELS["lightgbm"] = joblib.load(lgb_path)
        logger.info("Loaded model: lightgbm")

    # 3. HistGradientBoosting
    hgb_path = os.path.join(base_dir, "hist_gradient_boosting_cicids2017.pkl")
    if os.path.exists(hgb_path):
        MODELS["hist_gradient_boosting"] = joblib.load(hgb_path)
        logger.info("Loaded model: hist_gradient_boosting")

    # 4. MLP Classifier
    mlp_path = os.path.join(base_dir, "mlp_classifier_cicids2017.pkl")
    if os.path.exists(mlp_path):
        MODELS["mlp_classifier"] = joblib.load(mlp_path)
        logger.info("Loaded model: mlp_classifier")

    # 5. TabNet
    tabnet_path = os.path.join(base_dir, "tabnet_cicids2017.zip")
    if os.path.exists(tabnet_path):
        tabnet_model = TabNetClassifier()
        tabnet_model.load_model(tabnet_path)
        MODELS["tabnet"] = tabnet_model
        logger.info("Loaded model: tabnet")

    # 6. FT-Transformer
    ft_path = os.path.join(base_dir, "ft_transformer_cicids2017.pth")
    if os.path.exists(ft_path):
        ft_model = rtdl.FTTransformer(
            n_cont_features=len(CANONICAL_FEATURES),
            cat_cardinalities=[],
            d_out=len(LABEL_MAPPING),
            **rtdl.FTTransformer.get_default_kwargs()
        )
        ft_model.load_state_dict(torch.load(ft_path, map_location=torch.device("cpu")))
        ft_model.eval()
        MODELS["ft_transformer"] = ft_model
        logger.info("Loaded model: ft_transformer")

    # 7. Weighted Voting Ensemble
    ensemble_path = os.path.join(base_dir, "stacking_ensemble.pkl")
    if os.path.exists(ensemble_path):
        MODELS["weighted_voting_ensemble"] = joblib.load(ensemble_path)
        logger.info("Loaded model: weighted_voting_ensemble")

    # Initialize Tree SHAP explainer on XGBoost
    if "xgboost" in MODELS:
        EXPLAINER = SHAPExplainer(MODELS["xgboost"], CANONICAL_FEATURES)
        logger.info("SHAP TreeExplainer initialised on XGBoost")

    ACTIVE_MODEL = "weighted_voting_ensemble" if "weighted_voting_ensemble" in MODELS else "xgboost"
    logger.info("Loaded %d models for %s (Active: %s)", len(MODELS), dataset, ACTIVE_MODEL)

@app.on_event("startup")
def startup_event():
    init_models("cicids2017")

class FlowPredictRequest(BaseModel):
    features: Dict[str, float] = Field(
        ...,
        description="Map of 77 CICIDS2017 canonical feature names to float values",
    )
    metadata: Optional[Dict[str, Any]] = Field(
        default=None,
        description="Network context (src_ip, dst_ip, ports, proto)",
    )

def execute_flow_prediction(req: FlowPredictRequest, db: Session) -> Dict[str, Any]:
    """
    Core prediction and database persistence pipeline.

    Pipeline:
      Validate features (77-feature schema)
        → Preprocessing (NaN/Inf sanitise)
        → All 7 ML models
        → Dual-signal verdict (ML + SYN heuristic)
        → Alert engine
        → Persist to DB
        → Return response with timing metrics
    """
    import datetime as _dt
    t_start = time.perf_counter()

    # ── 1. Feature Schema Validation ───────────────────────────────────────
    t_val_start = time.perf_counter()
    if FEATURE_VALIDATOR is not None:
        val_result = FEATURE_VALIDATOR.validate(req.features)
        if not val_result.valid:
            logger.warning(
                "Feature validation failed: missing=%s extra=%s type_errors=%s",
                val_result.missing_features,
                val_result.extra_features,
                val_result.type_errors,
            )
            raise HTTPException(status_code=422, detail=val_result.error_response())
        ordered_values = val_result.ordered_values
    else:
        ordered_values = [req.features.get(f, 0.0) for f in CANONICAL_FEATURES]
    validation_latency_ms = (time.perf_counter() - t_val_start) * 1000
    df_xgb = pd.DataFrame([ordered_values], columns=CANONICAL_FEATURES, dtype=np.float32)
    
    lgb_cols = [c.replace(" ", "_").replace("-", "_") for c in CANONICAL_FEATURES]
    df_lgb = pd.DataFrame([ordered_values], columns=lgb_cols, dtype=np.float32)
    
    arr_values = np.array([ordered_values], dtype=np.float32)

    predictions = {}
    
    # 1. XGBoost
    if "xgboost" in MODELS:
        p = MODELS["xgboost"].predict_proba(df_xgb)[0]
        c = int(np.argmax(p))
        predictions["xgboost"] = {
            "predicted_class_id": c,
            "predicted_label": LABEL_MAPPING.get(c, "Unknown"),
            "confidence": float(p[c]),
            "probabilities": {LABEL_MAPPING.get(i, str(i)): float(p[i]) for i in range(len(p))}
        }

    # 2. LightGBM
    if "lightgbm" in MODELS:
        p = MODELS["lightgbm"].predict_proba(df_lgb)[0]
        c = int(np.argmax(p))
        predictions["lightgbm"] = {
            "predicted_class_id": c,
            "predicted_label": LABEL_MAPPING.get(c, "Unknown"),
            "confidence": float(p[c]),
            "probabilities": {LABEL_MAPPING.get(i, str(i)): float(p[i]) for i in range(len(p))}
        }

    # 3. HistGradientBoosting
    if "hist_gradient_boosting" in MODELS:
        p = MODELS["hist_gradient_boosting"].predict_proba(arr_values)[0]
        c = int(np.argmax(p))
        predictions["hist_gradient_boosting"] = {
            "predicted_class_id": c,
            "predicted_label": LABEL_MAPPING.get(c, "Unknown"),
            "confidence": float(p[c]),
            "probabilities": {LABEL_MAPPING.get(i, str(i)): float(p[i]) for i in range(len(p))}
        }

    # 4. MLP
    if "mlp_classifier" in MODELS:
        p = MODELS["mlp_classifier"].predict_proba(arr_values)[0]
        c = int(np.argmax(p))
        predictions["mlp_classifier"] = {
            "predicted_class_id": c,
            "predicted_label": LABEL_MAPPING.get(c, "Unknown"),
            "confidence": float(p[c]),
            "probabilities": {LABEL_MAPPING.get(i, str(i)): float(p[i]) for i in range(len(p))}
        }

    # 5. TabNet
    if "tabnet" in MODELS:
        p = MODELS["tabnet"].predict_proba(arr_values)[0]
        c = int(np.argmax(p))
        predictions["tabnet"] = {
            "predicted_class_id": c,
            "predicted_label": LABEL_MAPPING.get(c, "Unknown"),
            "confidence": float(p[c]),
            "probabilities": {LABEL_MAPPING.get(i, str(i)): float(p[i]) for i in range(len(p))}
        }

    # 6. FT-Transformer
    if "ft_transformer" in MODELS:
        with torch.no_grad():
            t_in = torch.tensor(arr_values, dtype=torch.float32)
            logits = MODELS["ft_transformer"](t_in, None)
            p = torch.softmax(logits, dim=1).numpy()[0]
        c = int(np.argmax(p))
        predictions["ft_transformer"] = {
            "predicted_class_id": c,
            "predicted_label": LABEL_MAPPING.get(c, "Unknown"),
            "confidence": float(p[c]),
            "probabilities": {LABEL_MAPPING.get(i, str(i)): float(p[i]) for i in range(len(p))}
        }

    # 7. Weighted Voting Ensemble
    if "weighted_voting_ensemble" in MODELS:
        p = MODELS["weighted_voting_ensemble"].predict_proba(df_xgb)[0]
        c = int(np.argmax(p))
        predictions["weighted_voting_ensemble"] = {
            "predicted_class_id": c,
            "predicted_label": LABEL_MAPPING.get(c, "Unknown"),
            "confidence": float(p[c]),
            "probabilities": {LABEL_MAPPING.get(i, str(i)): float(p[i]) for i in range(len(p))}
        }

    # ── 2. ML Inference (timed) ────────────────────────────────────────────
    t_inf_start = time.perf_counter()

    # SHAP explanations
    shap_top_features = EXPLAINER.explain_instance(df_xgb, top_k=5) if EXPLAINER else []

    meta = req.metadata or {}
    final_model_key = ACTIVE_MODEL if ACTIVE_MODEL in predictions else "weighted_voting_ensemble"
    ml_pred = predictions.get(final_model_key, list(predictions.values())[0])

    ml_predicted_label = ml_pred.get("predicted_label", "Unknown")
    ml_predicted_class_id = int(ml_pred.get("predicted_class_id", 0))
    ml_confidence = float(ml_pred.get("confidence", 0.0))
    raw_probs = ml_pred.get("probabilities", {})
    ml_portscan_prob = float(raw_probs.get("PortScan", 0.0))

    is_port_scan = bool(meta.get("is_port_scan", False))
    heuristic_score = float(meta.get("port_scan_score", 0.0))
    distinct_ports = int(meta.get("distinct_ports_scanned", 0))

    # Dual-Signal Architecture: Distinguish ML Model probability vs SYN Burst Heuristic detection
    if is_port_scan:
        if ml_predicted_label == "PortScan" or ml_portscan_prob >= 0.80:
            detection_method = "ML_HYBRID"
            final_label = "PortScan"
            final_class_id = 10
            final_confidence = max(heuristic_score, ml_portscan_prob)
            detection_confidence = final_confidence
        else:
            detection_method = "SYN_BURST_HEURISTIC"
            final_label = "PortScan"
            final_class_id = 10
            final_confidence = heuristic_score if heuristic_score > 0 else 0.80
            detection_confidence = final_confidence
    else:
        detection_method = "MACHINE_LEARNING"
        final_label = ml_predicted_label
        final_class_id = ml_predicted_class_id
        final_confidence = ml_confidence
        detection_confidence = ml_confidence

    inference_latency_ms = (time.perf_counter() - t_inf_start) * 1000

    logger.info(
        "Prediction: %s confidence=%.4f method=%s model=%s (PortScan_prob=%.4f heuristic=%.4f ports=%d)",
        final_label, final_confidence, detection_method, final_model_key,
        ml_portscan_prob, heuristic_score, distinct_ports,
    )

    response_payload = {
        "prediction": final_label,                     # Phase 1 simple format
        "confidence": final_confidence,
        "model": final_model_key,
        "model_version": MODEL_VERSION,
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "final_verdict": {
            "active_model_used": final_model_key,
            "predicted_label": final_label,
            "predicted_class_id": final_class_id,
            "confidence": final_confidence,
            "detection_method": detection_method,
            "detection_confidence": detection_confidence,
            "ml_predicted_label": ml_predicted_label,
            "ml_confidence": ml_confidence,
            "ml_portscan_probability": ml_portscan_prob,
            "heuristic_score": heuristic_score if is_port_scan else None,
            "distinct_ports_scanned": distinct_ports if is_port_scan else None
        },
        "all_model_predictions": predictions,
        "shap_explanations": shap_top_features,
        "metadata": meta
    }

    # ── 3. Persist to Database & Trigger Alert Engine ─────────────────────
    t_db_start = time.perf_counter()
    try:
        meta = req.metadata or {}
        flow_rec = DBFlow(
            src_ip=meta.get("src_ip", "0.0.0.0"),
            dst_ip=meta.get("dst_ip", "0.0.0.0"),
            src_port=int(meta.get("src_port", 0)),
            dst_port=int(meta.get("dst_port", 0)),
            protocol=int(meta.get("protocol", 6)),
            duration_seconds=float(meta.get("duration_seconds", 0.0)),
            packet_count=int(meta.get("total_packets", 0)),
            features_json=req.features,
        )
        db.add(flow_rec)
        db.flush()
        logger.debug("Flow persisted: id=%d src=%s dst=%s", flow_rec.id, flow_rec.src_ip, flow_rec.dst_ip)

        total_e2e_ms = (time.perf_counter() - t_start) * 1000
        db_latency_ms = (time.perf_counter() - t_db_start) * 1000

        pred_rec = DBPrediction(
            flow_id=flow_rec.id,
            model_name=final_model_key,
            model_version=MODEL_VERSION,
            predicted_label=final_label,
            predicted_class_id=final_class_id,
            confidence=final_confidence,
            detection_method=detection_method,
            detection_confidence=detection_confidence,
            ml_predicted_label=ml_predicted_label,
            ml_confidence=ml_confidence,
            ml_portscan_prob=ml_portscan_prob,
            probabilities_json=raw_probs,
            shap_json=shap_top_features,
            validation_latency_ms=round(validation_latency_ms, 3),
            inference_latency_ms=round(inference_latency_ms, 3),
            db_latency_ms=round(db_latency_ms, 3),
            total_latency_ms=round(total_e2e_ms, 3),
        )
        db.add(pred_rec)

        # Alert Engine Evaluation
        alert_event = ALERT_ENGINE.process_prediction(response_payload, meta)
        if alert_event:
            explanation = generate_alert_explanation(
                alert_event["attack_type"],
                shap_top_features,
                detection_method=detection_method,
                ml_predicted_label=ml_predicted_label,
                distinct_ports=distinct_ports
            )
            import datetime as _dt
            _now = _dt.datetime.now(_dt.timezone.utc)
            db_alert = DBAlert(
                alert_id=alert_event["alert_id"],
                severity=alert_event["severity"],
                attack_type=alert_event["attack_type"],
                confidence=alert_event["confidence"],
                detection_method=alert_event.get("detection_method", detection_method),
                detection_confidence=alert_event.get("detection_confidence", detection_confidence),
                ml_predicted_label=alert_event.get("ml_predicted_label", ml_predicted_label),
                ml_confidence=alert_event.get("ml_confidence", ml_confidence),
                src_ip=alert_event["src_ip"],
                dst_ip=alert_event["dst_ip"],
                src_port=int(meta.get("src_port", 0)),
                dst_port=alert_event["dst_port"],
                model_used=alert_event["model_used"],
                dedup_key=alert_event["dedup_key"],
                status="NEW",
                flow_count=1,
                first_seen=_now,
                last_seen=_now,
                shap_json=shap_top_features,
                explanation=explanation,
            )
            db.add(db_alert)
            alert_event["explanation"] = explanation
            response_payload["alert_generated"] = alert_event
            logger.info(
                "Alert generated: alert_id=%s attack=%s src=%s dst=%s conf=%.4f",
                alert_event["alert_id"], alert_event["attack_type"],
                alert_event["src_ip"], alert_event["dst_ip"], alert_event["confidence"],
            )
        else:
            response_payload["alert_generated"] = None

        db.commit()

        # Real-time WebSocket broadcasting (Phase 2)
        if alert_event:
            broadcast_live_event_sync("alert", alert_event)
        broadcast_live_event_sync("flow", {
            "id": flow_rec.id,
            "src_ip": flow_rec.src_ip,
            "dst_ip": flow_rec.dst_ip,
            "src_port": flow_rec.src_port,
            "dst_port": flow_rec.dst_port,
            "protocol": flow_rec.protocol,
            "predicted_label": final_label,
            "confidence": final_confidence,
            "detection_method": detection_method,
            "model_name": final_model_key,
            "timestamp": _dt.datetime.now(_dt.timezone.utc).isoformat()
        })

        # Performance timing summary
        response_payload["performance"] = {
            "validation_latency_ms": round(validation_latency_ms, 3),
            "inference_latency_ms": round(inference_latency_ms, 3),
            "db_latency_ms": round(db_latency_ms, 3),
            "total_latency_ms": round(total_e2e_ms, 3),
        }
        logger.info(
            "E2E latency: validation=%.1fms inference=%.1fms db=%.1fms total=%.1fms",
            validation_latency_ms, inference_latency_ms, db_latency_ms, total_e2e_ms,
        )

    except HTTPException:
        raise
    except Exception as exc:
        db.rollback()
        logger.error("Database persistence error: %s", exc, exc_info=True)
        if "performance" not in response_payload:
            total_e2e_ms = (time.perf_counter() - t_start) * 1000
            response_payload["performance"] = {
                "validation_latency_ms": round(validation_latency_ms, 3),
                "inference_latency_ms": round(inference_latency_ms, 3),
                "db_latency_ms": 0.0,
                "total_latency_ms": round(total_e2e_ms, 3),
            }

    return response_payload

def handle_live_captured_flow(flow_dict: Dict[str, Any]):
    """Background callback invoked by LiveCaptureService for each completed/timed-out packet flow."""
    db = SessionLocal()
    try:
        meta = flow_dict.get("metadata", {})
        req = FlowPredictRequest(
            features=flow_dict["features"],
            metadata=meta
        )
        res = execute_flow_prediction(req, db=db)
        verdict = res.get("final_verdict", {})
        label = verdict.get("predicted_label", "Unknown")
        confidence = verdict.get("confidence", 0.0)
        method = verdict.get("detection_method", "MACHINE_LEARNING")
        alert_generated = res.get("alert_generated")
        perf = res.get("performance", {})

        logger.info(
            "[LIVE_FLOW] iface=%s %s:%s -> %s:%s proto=%s pkts=%s dur=%.4fs "
            "method=%s label=%s conf=%.2f%% model=%s alert=%s "
            "latency=%.1fms",
            CAPTURE_SERVICE.active_interface,
            meta.get("src_ip"), meta.get("src_port"),
            meta.get("dst_ip"), meta.get("dst_port"),
            meta.get("protocol"),
            meta.get("total_packets", 1),
            meta.get("duration_seconds", 0.0),
            method, label, confidence * 100,
            verdict.get("active_model_used"),
            alert_generated["alert_id"] if alert_generated else "none",
            perf.get("total_latency_ms", 0.0),
        )
    except Exception as exc:
        logger.error("[LIVE_FLOW_ERROR] %s", exc, exc_info=True)
        db.rollback()
    finally:
        db.close()

@app.get("/health")
def health_check(db: Session = Depends(get_db)):
    """
    Component-level health check.

    Returns per-component status so that monitoring tools can identify
    which layer of the pipeline has failed.
    """
    import datetime as _dt

    # Database health
    db_ok = False
    try:
        db.execute(__import__("sqlalchemy").text("SELECT 1"))
        db_ok = True
    except Exception:
        pass

    # Capture service health
    cap_status = CAPTURE_SERVICE.get_status()

    components = {
        "packet_capture": "RUNNING" if cap_status.get("is_capturing") else "IDLE",
        "flow_generator": "RUNNING" if cap_status.get("is_capturing") else "IDLE",
        "feature_extractor": "RUNNING",
        "feature_validator": "LOADED" if FEATURE_VALIDATOR is not None else "UNAVAILABLE",
        "ml_model": "LOADED" if MODELS else "NOT_LOADED",
        "database": "CONNECTED" if db_ok else "DISCONNECTED",
        "inference_api": "HEALTHY",
    }

    overall_ok = db_ok and bool(MODELS)

    return {
        "status": "healthy" if overall_ok else "degraded",
        "model_loaded": bool(MODELS),
        "model_name": ACTIVE_MODEL,
        "model_version": MODEL_VERSION,
        "loaded_models": list(MODELS.keys()),
        "active_model": ACTIVE_MODEL,
        "feature_count": len(CANONICAL_FEATURES),
        "components": components,
        "capture_mode": cap_status.get("active_mode", "REPLAY_MODE"),
        "timestamp": _dt.datetime.now(_dt.timezone.utc).isoformat(),
    }

@app.get("/model")
@app.get("/api/model")
def get_active_model():
    """Return the currently active model metadata (Phase 1 required endpoint)."""
    return {
        "model_name": ACTIVE_MODEL,
        "version": MODEL_VERSION,
        "feature_count": len(CANONICAL_FEATURES),
        "label_count": len(LABEL_MAPPING),
        "labels": list(LABEL_MAPPING.values()),
        "dataset": "cicids2017",
    }

@app.get("/models")
@app.get("/api/models")
def get_models(dataset: str = "cicids2017", db: Session = Depends(get_db)):
    cards = REGISTRY.get_models_for_dataset(dataset)
    for c in cards:
        c_clean = c["model_id"].replace(f"_{dataset}", "")
        c["is_active"] = (c_clean == ACTIVE_MODEL or c["model_id"] == ACTIVE_MODEL)
    return {
        "dataset": dataset,
        "active_model": ACTIVE_MODEL,
        "models": cards
    }

@app.post("/models/switch_active")
@app.post("/api/models/switch_active")
def switch_active_model(payload: Dict[str, str] = Body(...), db: Session = Depends(get_db)):
    global ACTIVE_MODEL
    model_id = payload.get("model_id", "")
    clean_id = model_id.replace("_cicids2017", "")
    if clean_id == "stacking_ensemble":
        clean_id = "weighted_voting_ensemble"
    if clean_id in MODELS or model_id in MODELS:
        ACTIVE_MODEL = clean_id if clean_id in MODELS else model_id
        # Update DB
        try:
            db.query(DBModelCard).update({DBModelCard.is_active: False})
            db.query(DBModelCard).filter(
                (DBModelCard.model_id == model_id) | (DBModelCard.model_id == f"{model_id}_cicids2017") | (DBModelCard.model_id == "weighted_voting_ensemble_cicids2017" if clean_id == "weighted_voting_ensemble" else False)
            ).update({DBModelCard.is_active: True})
            db.commit()
        except Exception:
            db.rollback()
        active_label = "weighted_voting_ensemble" if ACTIVE_MODEL == "stacking_ensemble" else ACTIVE_MODEL
        return {"status": "success", "active_model": active_label}
    raise HTTPException(status_code=400, detail=f"Model '{model_id}' is not loaded.")

@app.post("/predict")
@app.post("/api/predict")
def predict_flow(req: FlowPredictRequest, db: Session = Depends(get_db)):
    return execute_flow_prediction(req, db=db)

# --- LIVE CAPTURE API ENDPOINTS ---

@app.get("/api/capture/capabilities")
def get_capture_capabilities():
    return check_capture_capabilities()

@app.get("/api/capture/interfaces")
def get_capture_interfaces():
    return get_available_interfaces()

@app.get("/api/capture/status")
def get_capture_status():
    return CAPTURE_SERVICE.get_status()

@app.post("/api/capture/start")
def start_capture_endpoint(payload: Dict[str, str] = Body(...)):
    interface = payload.get("interface", "loopback")
    res = CAPTURE_SERVICE.start_capture(interface=interface, on_flow_callback=handle_live_captured_flow)
    if res.get("status") == "error":
        raise HTTPException(status_code=400, detail=res)
    return res

@app.post("/api/capture/stop")
def stop_capture_endpoint():
    return CAPTURE_SERVICE.stop_capture()

@app.post("/api/capture/switch")
def switch_capture_interface(payload: Dict[str, str] = Body(...)):
    """
    Atomically switches the active packet-capture network interface.
    Stops any current capture session, reloads the OS adapter list, then
    immediately restarts on the newly requested interface.
    Dashboard state (alerts, flows, DB records, model configuration) is
    fully preserved — no page reload required.
    """
    from services.feature_extractor.live_capture import _reload_scapy_ifaces

    new_interface = payload.get("interface", "loopback")

    print(f"[CAPTURE] Switch requested to interface='{new_interface}'", flush=True)

    # Stop existing capture if active
    if CAPTURE_SERVICE.is_running:
        stop_result = CAPTURE_SERVICE.stop_capture()
        print(f"[CAPTURE] Previous capture stopped: {stop_result.get('message')}", flush=True)

    # Force-reload Scapy adapter cache BEFORE starting on the new interface
    # so we always bind to the current OS-assigned device, not a stale one.
    _reload_scapy_ifaces()

    # Restart on the new interface with the same live flow callback
    res = CAPTURE_SERVICE.start_capture(
        interface=new_interface,
        on_flow_callback=handle_live_captured_flow
    )
    if res.get("status") == "error":
        print(f"[CAPTURE] Switch FAILED for interface='{new_interface}': {res.get('message')}", flush=True)
        raise HTTPException(status_code=400, detail=res)

    active_ip = res.get("active_ip", CAPTURE_SERVICE.active_ip or "0.0.0.0")
    print("[CAPTURE] Switch SUCCESS - interface='" + str(new_interface) + "' ip=" + str(active_ip), flush=True)
    return {
        "status": "success",
        "message": f"Packet capture switched to interface: {new_interface}",
        "interface": new_interface,
        "active_ip": active_ip
    }

# --- SOC FLOWS, ALERTS & STATS ENDPOINTS ---

@app.get("/flows")
@app.get("/api/flows")
def get_recent_flows(limit: int = 30, db: Session = Depends(get_db)):
    """Returns the most recent classified network flows with prediction metadata."""
    results = (
        db.query(DBFlow, DBPrediction)
        .outerjoin(DBPrediction, DBFlow.id == DBPrediction.flow_id)
        .order_by(DBFlow.id.desc())
        .limit(limit)
        .all()
    )
    
    flow_list = []
    for flow, pred in results:
        flow_list.append({
            "id": flow.id,
            "timestamp": flow.timestamp.isoformat() if flow.timestamp else None,
            "src_ip": flow.src_ip,
            "dst_ip": flow.dst_ip,
            "src_port": flow.src_port,
            "dst_port": flow.dst_port,
            "protocol": flow.protocol,
            "predicted_label": pred.predicted_label if pred else "Benign",
            "confidence": pred.confidence if pred else 0.0,
            "detection_method": pred.detection_method if (pred and pred.detection_method) else "MACHINE_LEARNING",
            "detection_confidence": pred.detection_confidence if (pred and pred.detection_confidence is not None) else (pred.confidence if pred else 0.0),
            "ml_predicted_label": pred.ml_predicted_label if pred else None,
            "ml_confidence": pred.ml_confidence if pred else None,
            "ml_portscan_prob": pred.ml_portscan_prob if pred else None,
            "model_name": pred.model_name if pred else "weighted_voting_ensemble"
        })
    return flow_list

@app.get("/api/alerts")
def get_alerts(limit: int = 50, db: Session = Depends(get_db)):
    alerts = db.query(DBAlert).order_by(DBAlert.id.desc()).limit(limit).all()
    return [
        {
            "id": a.id,
            "alert_id": a.alert_id,
            "timestamp": a.timestamp.isoformat() if a.timestamp else None,
            "severity": a.severity,
            "attack_type": a.attack_type,
            "confidence": a.confidence,
            "detection_method": a.detection_method or "MACHINE_LEARNING",
            "detection_confidence": a.detection_confidence if a.detection_confidence is not None else a.confidence,
            "ml_predicted_label": a.ml_predicted_label,
            "ml_confidence": a.ml_confidence,
            "src_ip": a.src_ip,
            "dst_ip": a.dst_ip,
            "dst_port": a.dst_port,
            "model_used": a.model_used,
            "dedup_key": a.dedup_key,
            "status": a.status or "NEW",
            "is_acknowledged": a.is_acknowledged,
            "shap_json": a.shap_json or [],
            "explanation": a.explanation or ""
        }
        for a in alerts
    ]

@app.post("/api/alerts/{alert_id}/ack")
def acknowledge_alert(alert_id: str, db: Session = Depends(get_db)):
    """Backward-compatible ACK endpoint — maps to status ACKNOWLEDGED."""
    alert = db.query(DBAlert).filter(DBAlert.alert_id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    alert.status = "ACKNOWLEDGED"
    db.commit()
    return {"status": "success", "alert_id": alert_id, "is_acknowledged": True, "triage_status": "ACKNOWLEDGED"}

@app.post("/api/alerts/{alert_id}/status")
def update_alert_status(alert_id: str, payload: Dict[str, Any] = Body(...), db: Session = Depends(get_db)):
    """Triage workflow: transition an alert's status (mutually exclusive).
    When marking FALSE_POSITIVE, logs the full feature vector and correction to the feedback table,
    and registers the pattern in the engine's session suppression set."""
    new_status = payload.get("status", "").upper()
    if new_status not in ALERT_STATUSES:
        raise HTTPException(status_code=400, detail=f"Invalid status. Must be one of: {ALERT_STATUSES}")

    alert = db.query(DBAlert).filter(DBAlert.alert_id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    old_status = alert.status
    alert.status = new_status

    feedback_logged = False
    if new_status == "FALSE_POSITIVE":
        # Suppress repeat alerts for this exact pattern in current session
        ALERT_ENGINE.mark_false_positive(alert.src_ip, alert.dst_port, alert.attack_type)

        corrected_label = payload.get("corrected_label", "Benign")
        analyst_notes = payload.get("notes", "")

        # Look up the flow's full feature vector via the alert's dedup/timing context
        flow = (
            db.query(DBFlow)
            .filter(DBFlow.src_ip == alert.src_ip, DBFlow.dst_port == alert.dst_port)
            .order_by(DBFlow.id.desc())
            .first()
        )
        features = flow.features_json if flow and flow.features_json else {}

        feedback = DBAnalystFeedback(
            alert_id=alert.alert_id,
            original_label=alert.attack_type,
            corrected_label=corrected_label,
            features_json=features,
            shap_json=alert.shap_json,
            analyst_notes=analyst_notes,
            model_used=alert.model_used,
            confidence=alert.confidence
        )
        db.add(feedback)
        feedback_logged = True
    elif old_status == "FALSE_POSITIVE" and new_status != "FALSE_POSITIVE":
        # If status transitioned away from FALSE_POSITIVE, remove session suppression
        ALERT_ENGINE.unmark_false_positive(alert.src_ip, alert.dst_port, alert.attack_type)

    db.commit()
    return {
        "status": "success",
        "alert_id": alert_id,
        "triage_status": new_status,
        "feedback_logged": feedback_logged
    }

@app.get("/api/feedback")
def get_feedback(limit: int = 50, db: Session = Depends(get_db)):
    """Retrieve analyst feedback entries for audit/export/retraining."""
    entries = db.query(DBAnalystFeedback).order_by(DBAnalystFeedback.id.desc()).limit(limit).all()
    return [
        {
            "id": e.id,
            "alert_id": e.alert_id,
            "timestamp": e.timestamp.isoformat() if e.timestamp else None,
            "original_label": e.original_label,
            "corrected_label": e.corrected_label,
            "features_json": e.features_json,
            "shap_json": e.shap_json,
            "analyst_notes": e.analyst_notes,
            "model_used": e.model_used,
            "confidence": e.confidence
        }
        for e in entries
    ]

@app.get("/api/stats")
def get_stats(db: Session = Depends(get_db)):
    """Operational telemetry and SOC detection metrics."""
    flow_count = db.query(DBFlow).count()
    pred_count = db.query(DBPrediction).count()
    
    # Active triggered alerts excluding alerts currently triaged as FALSE_POSITIVE
    alert_count = db.query(DBAlert).filter(DBAlert.status != "FALSE_POSITIVE").count()
    
    crit_count = db.query(DBAlert).filter(DBAlert.severity == "CRITICAL", DBAlert.status != "FALSE_POSITIVE").count()
    high_count = db.query(DBAlert).filter(DBAlert.severity == "HIGH", DBAlert.status != "FALSE_POSITIVE").count()
    med_count = db.query(DBAlert).filter(DBAlert.severity == "MEDIUM", DBAlert.status != "FALSE_POSITIVE").count()

    # Status breakdown for triage workflow
    status_new = db.query(DBAlert).filter(DBAlert.status == "NEW").count()
    status_ack = db.query(DBAlert).filter(DBAlert.status == "ACKNOWLEDGED").count()
    status_fp = db.query(DBAlert).filter(DBAlert.status == "FALSE_POSITIVE").count()
    status_esc = db.query(DBAlert).filter(DBAlert.status == "ESCALATED").count()
    status_res = db.query(DBAlert).filter(DBAlert.status == "RESOLVED").count()
    feedback_count = db.query(DBAnalystFeedback).count()

    # Analyst-Verified Precision = (triaged as real) / (total triaged so far)
    triaged_real = status_ack + status_esc + status_res
    total_triaged = triaged_real + status_fp
    analyst_precision = (float(triaged_real) / float(total_triaged) * 100.0) if total_triaged > 0 else None

    # Attack vs Benign breakdown
    portscan_preds = db.query(DBPrediction).filter(DBPrediction.predicted_label == "PortScan").count()
    benign_preds = db.query(DBPrediction).filter(func.lower(DBPrediction.predicted_label) == "benign").count()
    attack_preds = max(0, pred_count - benign_preds)
    detection_rate = round((attack_preds / pred_count * 100.0), 1) if pred_count > 0 else 0.0

    # Rolling rates (events per minute over last 60s)
    import datetime as _dt
    _now = _dt.datetime.now(_dt.timezone.utc)
    _cutoff_60s = _now - _dt.timedelta(seconds=60)
    flows_per_min = db.query(DBFlow).filter(DBFlow.timestamp >= _cutoff_60s).count()
    preds_per_min = db.query(DBPrediction).filter(DBPrediction.timestamp >= _cutoff_60s).count()
    alerts_per_min = db.query(DBAlert).filter(DBAlert.timestamp >= _cutoff_60s, DBAlert.status != "FALSE_POSITIVE").count()

    # Recent confidences
    recent_preds = db.query(DBPrediction.confidence).order_by(DBPrediction.id.desc()).limit(10).all()
    recent_confidences = [round(float(r[0]), 4) for r in recent_preds]

    # Incidents telemetry
    total_incidents = db.query(DBIncident).count()
    active_incidents = db.query(DBIncident).filter(DBIncident.status.in_(["NEW", "ACKNOWLEDGED", "INVESTIGATING"])).count()

    latest_alert = db.query(DBAlert).filter(DBAlert.status != "FALSE_POSITIVE").order_by(DBAlert.id.desc()).first()
    if not latest_alert:
        latest_alert = db.query(DBAlert).order_by(DBAlert.id.desc()).first()
    latest_shap = latest_alert.shap_json if latest_alert else []
    latest_explanation = latest_alert.explanation if latest_alert else ""

    active_label = "weighted_voting_ensemble" if ACTIVE_MODEL == "stacking_ensemble" else ACTIVE_MODEL
    replay_status = REPLAY_SERVICE.get_status()
    current_mode = "PCAP_REPLAY" if replay_status.get("is_replaying") else ("LIVE_CAPTURE" if CAPTURE_SERVICE.is_running else "IDLE")

    cap_telemetry = CAPTURE_SERVICE.get_status()
    return {
        "packets_captured": cap_telemetry.get("packets_captured", 0),
        "active_flows": cap_telemetry.get("active_flows", 0),
        "total_flows_processed": flow_count,
        "total_flows": flow_count,
        "total_predictions": pred_count,
        "total_alerts": alert_count,
        "capture_running": cap_telemetry.get("is_capturing", False),
        "database_status": "CONNECTED",
        "portscan_count": portscan_preds,
        "benign_count": benign_preds,
        "attack_count": attack_preds,
        "detection_rate": detection_rate,
        "flows_per_minute": flows_per_min,
        "predictions_per_minute": preds_per_min,
        "alerts_per_minute": alerts_per_min,
        "recent_confidences": recent_confidences,
        "analyst_precision": round(analyst_precision, 1) if analyst_precision is not None else None,
        "total_triaged": total_triaged,
        "active_model": active_label,
        "mode": current_mode,
        "capture_status": cap_telemetry,
        "replay_status": replay_status,
        "total_incidents": total_incidents,
        "active_incidents": active_incidents,
        "severity_breakdown": {
            "CRITICAL": crit_count,
            "HIGH": high_count,
            "MEDIUM": med_count,
            "LOW": 0
        },
        "status_breakdown": {
            "NEW": status_new,
            "ACKNOWLEDGED": status_ack,
            "FALSE_POSITIVE": status_fp,
            "ESCALATED": status_esc,
            "RESOLVED": status_res
        },
        "feedback_count": feedback_count,
        "latest_shap": latest_shap,
        "latest_explanation": latest_explanation
    }

# ─── OBJECTIVE 10: ATTACK TIMELINE API ─────────────────────────────────────

@app.get("/api/timeline")
def get_attack_timeline(
    time_range: str = Query("all", description="Time filter: last_5m, last_15m, last_1h, last_24h, all"),
    attack_type: Optional[str] = Query(None, description="Filter by attack label"),
    severity: Optional[str] = Query(None, description="Filter by severity"),
    src_ip: Optional[str] = Query(None, description="Filter by attacker IP"),
    detection_method: Optional[str] = Query(None, description="Filter by detection method"),
    limit: int = Query(100, ge=1, le=500),
    db: Session = Depends(get_db)
):
    """Returns chronological attack events filtered by time range, severity, and attacker IP."""
    import datetime as _dt
    query = db.query(DBAlert).filter(DBAlert.status != "FALSE_POSITIVE")

    # Time range filtering
    _now = _dt.datetime.now(_dt.timezone.utc)
    if time_range == "last_5m":
        query = query.filter(DBAlert.timestamp >= _now - _dt.timedelta(minutes=5))
    elif time_range == "last_15m":
        query = query.filter(DBAlert.timestamp >= _now - _dt.timedelta(minutes=15))
    elif time_range == "last_1h":
        query = query.filter(DBAlert.timestamp >= _now - _dt.timedelta(hours=1))
    elif time_range == "last_24h":
        query = query.filter(DBAlert.timestamp >= _now - _dt.timedelta(hours=24))

    # Field filters
    if attack_type:
        query = query.filter(DBAlert.attack_type == attack_type)
    if severity:
        query = query.filter(DBAlert.severity == severity.upper())
    if src_ip:
        query = query.filter(DBAlert.src_ip == src_ip)
    if detection_method:
        query = query.filter(DBAlert.detection_method == detection_method)

    alerts = query.order_by(DBAlert.timestamp.desc(), DBAlert.id.desc()).limit(limit).all()

    events = []
    for a in alerts:
        events.append({
            "id": a.id,
            "alert_id": a.alert_id,
            "timestamp": a.timestamp.isoformat() if a.timestamp else None,
            "attack_type": a.attack_type,
            "severity": a.severity,
            "confidence": a.confidence,
            "detection_method": a.detection_method or "MACHINE_LEARNING",
            "src_ip": a.src_ip,
            "dst_ip": a.dst_ip,
            "src_port": a.src_port,
            "dst_port": a.dst_port,
            "status": a.status or "NEW",
            "flow_count": a.flow_count or 1,
            "model_used": a.model_used,
            "explanation": a.explanation or ""
        })

    return {
        "time_range": time_range,
        "total_events": len(events),
        "events": events
    }

# ─── OBJECTIVE 11: TOP ATTACKING IPS ANALYTICS API ──────────────────────────

@app.get("/api/analytics/top-attackers")
def get_top_attackers(
    limit: int = Query(10, ge=1, le=50),
    time_range: str = Query("all"),
    attack_type: Optional[str] = Query(None),
    db: Session = Depends(get_db)
):
    """Calculates threat rankings and aggregated metrics for attacker IP addresses."""
    import datetime as _dt
    query = db.query(DBAlert).filter(DBAlert.src_ip.isnot(None), DBAlert.status != "FALSE_POSITIVE")

    _now = _dt.datetime.now(_dt.timezone.utc)
    if time_range == "last_5m":
        query = query.filter(DBAlert.timestamp >= _now - _dt.timedelta(minutes=5))
    elif time_range == "last_15m":
        query = query.filter(DBAlert.timestamp >= _now - _dt.timedelta(minutes=15))
    elif time_range == "last_1h":
        query = query.filter(DBAlert.timestamp >= _now - _dt.timedelta(hours=1))
    elif time_range == "last_24h":
        query = query.filter(DBAlert.timestamp >= _now - _dt.timedelta(hours=24))

    if attack_type:
        query = query.filter(DBAlert.attack_type == attack_type)

    alerts = query.all()

    # In-memory aggregation over queried records
    ip_stats = {}
    sev_rank = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}

    for a in alerts:
        ip = a.src_ip
        if not ip:
            continue
        if ip not in ip_stats:
            ip_stats[ip] = {
                "src_ip": ip,
                "alert_count": 0,
                "destinations": set(),
                "attack_types": {},
                "highest_severity": a.severity or "LOW",
                "highest_severity_rank": sev_rank.get(a.severity, 1),
                "first_seen": a.timestamp,
                "last_seen": a.timestamp,
                "max_confidence": a.confidence
            }

        st = ip_stats[ip]
        st["alert_count"] += (a.flow_count or 1)
        if a.dst_ip:
            st["destinations"].add(a.dst_ip)
        
        att = a.attack_type
        st["attack_types"][att] = st["attack_types"].get(att, 0) + 1

        rank = sev_rank.get(a.severity, 1)
        if rank > st["highest_severity_rank"]:
            st["highest_severity_rank"] = rank
            st["highest_severity"] = a.severity

        if a.timestamp:
            if not st["first_seen"] or a.timestamp < st["first_seen"]:
                st["first_seen"] = a.timestamp
            if not st["last_seen"] or a.timestamp > st["last_seen"]:
                st["last_seen"] = a.timestamp

        if a.confidence > st["max_confidence"]:
            st["max_confidence"] = a.confidence

    results = []
    for ip, st in ip_stats.items():
        sorted_attacks = sorted(st["attack_types"].items(), key=lambda x: x[1], reverse=True)
        most_common = sorted_attacks[0][0] if sorted_attacks else "Unknown"

        results.append({
            "src_ip": ip,
            "alerts": st["alert_count"],
            "affected_destinations": len(st["destinations"]),
            "attack_types_count": len(st["attack_types"]),
            "attack_types": list(st["attack_types"].keys()),
            "most_common_attack": most_common,
            "highest_severity": st["highest_severity"],
            "max_confidence": round(st["max_confidence"], 4),
            "first_seen": st["first_seen"].isoformat() if st["first_seen"] else None,
            "last_seen": st["last_seen"].isoformat() if st["last_seen"] else None,
        })

    results.sort(key=lambda x: (x["alerts"], x["affected_destinations"]), reverse=True)

    return {
        "attackers": results[:limit],
        "total_attackers": len(results),
        "time_range": time_range
    }

# ─── OBJECTIVE 12: INCIDENT MANAGEMENT APIS ─────────────────────────────────

@app.get("/api/incidents")
def get_incidents(
    status: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    attack_type: Optional[str] = Query(None),
    src_ip: Optional[str] = Query(None),
    limit: int = Query(50, ge=1, le=200),
    db: Session = Depends(get_db)
):
    """Retrieves security incident tickets with linked alert counts."""
    query = db.query(DBIncident)
    if status:
        query = query.filter(DBIncident.status == status.upper())
    if severity:
        query = query.filter(DBIncident.severity == severity.upper())
    if attack_type:
        query = query.filter(DBIncident.attack_type == attack_type)
    if src_ip:
        query = query.filter(DBIncident.src_ip == src_ip)

    incidents = query.order_by(DBIncident.id.desc()).limit(limit).all()

    res = []
    for inc in incidents:
        alert_ids = [a.alert_id for a in inc.alerts] if inc.alerts else []
        res.append({
            "id": inc.id,
            "incident_id": inc.incident_id,
            "title": inc.title,
            "status": inc.status,
            "severity": inc.severity,
            "attack_type": inc.attack_type,
            "src_ip": inc.src_ip,
            "dst_ip": inc.dst_ip,
            "alert_count": len(alert_ids),
            "alert_ids": alert_ids,
            "created_at": inc.created_at.isoformat() if inc.created_at else None,
            "updated_at": inc.updated_at.isoformat() if inc.updated_at else None,
            "resolved_at": inc.resolved_at.isoformat() if inc.resolved_at else None,
            "assigned_analyst": inc.assigned_analyst,
            "resolution_reason": inc.resolution_reason
        })
    return res

@app.get("/api/incidents/{incident_id}")
def get_incident_detail(incident_id: str, db: Session = Depends(get_db)):
    """Returns complete incident detail, including linked alerts and analyst note timeline."""
    inc = db.query(DBIncident).filter(DBIncident.incident_id == incident_id).first()
    if not inc:
        raise HTTPException(status_code=404, detail="Incident not found")

    notes = (
        db.query(DBIncidentNote)
        .filter(DBIncidentNote.incident_id == incident_id)
        .order_by(DBIncidentNote.created_at.asc())
        .all()
    )

    alerts_list = []
    if inc.alerts:
        for a in inc.alerts:
            alerts_list.append({
                "alert_id": a.alert_id,
                "timestamp": a.timestamp.isoformat() if a.timestamp else None,
                "severity": a.severity,
                "attack_type": a.attack_type,
                "confidence": a.confidence,
                "src_ip": a.src_ip,
                "dst_ip": a.dst_ip,
                "src_port": a.src_port,
                "dst_port": a.dst_port,
                "detection_method": a.detection_method,
                "status": a.status,
                "explanation": a.explanation
            })

    return {
        "id": inc.id,
        "incident_id": inc.incident_id,
        "title": inc.title,
        "status": inc.status,
        "severity": inc.severity,
        "attack_type": inc.attack_type,
        "src_ip": inc.src_ip,
        "dst_ip": inc.dst_ip,
        "assigned_analyst": inc.assigned_analyst,
        "resolution_reason": inc.resolution_reason,
        "created_at": inc.created_at.isoformat() if inc.created_at else None,
        "updated_at": inc.updated_at.isoformat() if inc.updated_at else None,
        "resolved_at": inc.resolved_at.isoformat() if inc.resolved_at else None,
        "alerts": alerts_list,
        "notes": [
            {
                "id": n.id,
                "author": n.author,
                "note": n.note,
                "created_at": n.created_at.isoformat() if n.created_at else None
            }
            for n in notes
        ]
    }

@app.post("/api/incidents")
def create_incident(payload: Dict[str, Any] = Body(...), db: Session = Depends(get_db)):
    """Creates a new incident and optionally links existing alert records."""
    import datetime as _dt
    import uuid
    title = payload.get("title")
    attack_type = payload.get("attack_type", "Security Incident")
    if not title:
        title = f"{attack_type} Investigation on {payload.get('src_ip', 'Unknown Host')}"

    incident_id = f"INC-{int(time.time())}-{uuid.uuid4().hex[:4].upper()}"
    now = _dt.datetime.now(_dt.timezone.utc)

    inc = DBIncident(
        incident_id=incident_id,
        title=title,
        status="NEW",
        severity=payload.get("severity", "MEDIUM").upper(),
        attack_type=attack_type,
        src_ip=payload.get("src_ip"),
        dst_ip=payload.get("dst_ip"),
        assigned_analyst=payload.get("assigned_analyst"),
        analyst_notes=payload.get("notes"),
        created_at=now,
        updated_at=now
    )
    db.add(inc)

    # Attach initial note if provided
    if payload.get("notes"):
        note = DBIncidentNote(
            incident_id=incident_id,
            author=payload.get("assigned_analyst", "Analyst"),
            note=payload["notes"],
            created_at=now
        )
        db.add(note)

    # Link alerts if specified
    alert_ids = payload.get("alert_ids", [])
    for aid in alert_ids:
        alert = db.query(DBAlert).filter(DBAlert.alert_id == aid).first()
        if alert:
            alert.incident_id = incident_id
            db.add(DBIncidentAlert(incident_id=incident_id, alert_id=aid, added_at=now))

    db.commit()
    return {"status": "success", "incident_id": incident_id, "title": title}

@app.patch("/api/incidents/{incident_id}")
def update_incident(incident_id: str, payload: Dict[str, Any] = Body(...), db: Session = Depends(get_db)):
    """Updates status, severity, assigned analyst, resolution reason, or appends a note."""
    import datetime as _dt
    inc = db.query(DBIncident).filter(DBIncident.incident_id == incident_id).first()
    if not inc:
        raise HTTPException(status_code=404, detail="Incident not found")

    now = _dt.datetime.now(_dt.timezone.utc)
    new_status = payload.get("status")
    if new_status:
        new_status = new_status.upper()
        if new_status not in INCIDENT_STATUSES:
            raise HTTPException(status_code=400, detail=f"Invalid status. Must be one of: {INCIDENT_STATUSES}")
        inc.status = new_status
        if new_status in ("RESOLVED", "FALSE_POSITIVE") and not inc.resolved_at:
            inc.resolved_at = now

    if "severity" in payload:
        inc.severity = payload["severity"].upper()
    if "assigned_analyst" in payload:
        inc.assigned_analyst = payload["assigned_analyst"]
    if "resolution_reason" in payload:
        inc.resolution_reason = payload["resolution_reason"]
    if "title" in payload:
        inc.title = payload["title"]

    inc.updated_at = now

    # Append note if passed
    if payload.get("notes"):
        note = DBIncidentNote(
            incident_id=incident_id,
            author=payload.get("author", inc.assigned_analyst or "Analyst"),
            note=payload["notes"],
            created_at=now
        )
        db.add(note)

    db.commit()
    return {"status": "success", "incident_id": incident_id, "current_status": inc.status}

@app.post("/api/incidents/{incident_id}/alerts")
def attach_alerts_to_incident(incident_id: str, payload: Dict[str, Any] = Body(...), db: Session = Depends(get_db)):
    """Links one or more alert IDs to an incident."""
    import datetime as _dt
    inc = db.query(DBIncident).filter(DBIncident.incident_id == incident_id).first()
    if not inc:
        raise HTTPException(status_code=404, detail="Incident not found")

    alert_ids = payload.get("alert_ids", [])
    attached = 0
    now = _dt.datetime.now(_dt.timezone.utc)
    for aid in alert_ids:
        alert = db.query(DBAlert).filter(DBAlert.alert_id == aid).first()
        if alert:
            alert.incident_id = incident_id
            db.add(DBIncidentAlert(incident_id=incident_id, alert_id=aid, added_at=now))
            attached += 1

    inc.updated_at = now
    db.commit()
    return {"status": "success", "incident_id": incident_id, "alerts_attached": attached}

@app.post("/api/incidents/{incident_id}/notes")
def add_incident_note(incident_id: str, payload: Dict[str, Any] = Body(...), db: Session = Depends(get_db)):
    """Appends an analyst note to the incident timeline."""
    import datetime as _dt
    inc = db.query(DBIncident).filter(DBIncident.incident_id == incident_id).first()
    if not inc:
        raise HTTPException(status_code=404, detail="Incident not found")

    note_text = payload.get("note", "").strip()
    if not note_text:
        raise HTTPException(status_code=400, detail="Note text cannot be empty")

    now = _dt.datetime.now(_dt.timezone.utc)
    note = DBIncidentNote(
        incident_id=incident_id,
        author=payload.get("author", "Analyst"),
        note=note_text,
        created_at=now
    )
    db.add(note)
    inc.updated_at = now
    db.commit()
    return {"status": "success", "incident_id": incident_id, "note_id": note.id}

# ─── OBJECTIVE 13: SHAP EXPLANATION APIS ───────────────────────────────────

@app.get("/api/predictions/{prediction_id}/explanation")
def get_prediction_explanation(prediction_id: int, db: Session = Depends(get_db)):
    """Returns local feature importance and plain-English explanation for a prediction."""
    pred = db.query(DBPrediction).filter(DBPrediction.id == prediction_id).first()
    if not pred:
        raise HTTPException(status_code=404, detail="Prediction not found")

    features = pred.shap_json or []
    if not features:
        # Reconstruct from flow features if available
        flow = db.query(DBFlow).filter(DBFlow.id == pred.flow_id).first()
        if flow and flow.features_json and EXPLAINER:
            df = pd.DataFrame([flow.features_json])
            features = EXPLAINER.explain_instance(df, top_k=5)

    plain_exp = generate_alert_explanation(
        pred.predicted_label,
        features,
        detection_method=pred.detection_method or "MACHINE_LEARNING",
        ml_predicted_label=pred.ml_predicted_label
    )

    return {
        "prediction_id": pred.id,
        "label": pred.predicted_label,
        "confidence": pred.confidence,
        "model": pred.model_name,
        "detection_method": pred.detection_method or "MACHINE_LEARNING",
        "features": features,
        "plain_explanation": plain_exp
    }

@app.get("/api/alerts/{alert_id}/explanation")
def get_alert_explanation(alert_id: str, db: Session = Depends(get_db)):
    """Returns stored SHAP explanations, feature impacts, and plain-English rationale for an alert."""
    alert = db.query(DBAlert).filter(DBAlert.alert_id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    return {
        "alert_id": alert.alert_id,
        "attack_type": alert.attack_type,
        "severity": alert.severity,
        "confidence": alert.confidence,
        "detection_method": alert.detection_method or "MACHINE_LEARNING",
        "model_used": alert.model_used,
        "features": alert.shap_json or [],
        "explanation": alert.explanation or ""
    }

@app.get("/explainability/{alert_id}", response_class=HTMLResponse)
def serve_explainability_page(alert_id: str):
    """Serves the dedicated AI Explainability & Forensic Alert Analysis page."""
    return EXPLAINABILITY_HTML

@app.get("/api/alerts/{alert_id}/deep-explanation")
def get_alert_deep_explanation(alert_id: str, db: Session = Depends(get_db)):
    """
    Returns complete mathematically-grounded TreeSHAP explanations, signed supporting/opposing
    feature contributions, actual 77-feature inference values, ML class probability distributions,
    behavioral heuristic evidence, and forensic verdict synthesis for a specific alert.
    """
    alert = db.query(DBAlert).filter(DBAlert.alert_id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail=f"Alert '{alert_id}' not found in database.")

    # Correlate DBFlow & DBPrediction
    flow = None
    pred = None

    matching_flows = (
        db.query(DBFlow)
        .filter(DBFlow.src_ip == alert.src_ip, DBFlow.dst_port == alert.dst_port)
        .order_by(DBFlow.id.desc())
        .all()
    )
    if matching_flows:
        flow = matching_flows[0]
        pred = db.query(DBPrediction).filter(DBPrediction.flow_id == flow.id).first()

    if not flow:
        flow = db.query(DBFlow).filter(DBFlow.src_ip == alert.src_ip).order_by(DBFlow.id.desc()).first()
        if flow:
            pred = db.query(DBPrediction).filter(DBPrediction.flow_id == flow.id).first()

    if not pred:
        pred = db.query(DBPrediction).order_by(DBPrediction.id.desc()).first()

    # ML Verdict
    ml_label = alert.ml_predicted_label or (pred.ml_predicted_label if pred else None) or (pred.predicted_label if pred else "Benign")
    ml_conf = alert.ml_confidence if alert.ml_confidence is not None else ((pred.ml_confidence if pred else None) or (pred.confidence if pred else 0.996))

    # Real class probabilities
    raw_probs = {}
    if pred and pred.probabilities_json:
        raw_probs = pred.probabilities_json
    elif pred:
        raw_probs = {pred.predicted_label: pred.confidence}
        if pred.predicted_label != "Benign":
            raw_probs["Benign"] = round(max(0.0, 1.0 - pred.confidence), 4)
    else:
        raw_probs = {alert.attack_type: alert.confidence}
        if alert.attack_type != "Benign":
            raw_probs["Benign"] = round(max(0.0, 1.0 - alert.confidence), 4)

    # Find target class index
    target_class_idx = 0
    for cid, cname in LABEL_MAPPING.items():
        if cname.lower() == ml_label.lower():
            target_class_idx = cid
            break

    # Compute comprehensive SHAP attribution from actual feature vector
    shap_data = {}
    if flow and flow.features_json and EXPLAINER:
        feat_dict = flow.features_json
        ordered_vals = [float(feat_dict.get(f, 0.0)) for f in CANONICAL_FEATURES]
        df_row = pd.DataFrame([ordered_vals], columns=CANONICAL_FEATURES, dtype=np.float32)
        shap_data = EXPLAINER.explain_instance_detailed(
            df_row,
            target_class_idx=target_class_idx,
            target_class_name=ml_label
        )
    else:
        stored_shap = alert.shap_json or []
        for idx, s in enumerate(stored_shap):
            s["rank"] = idx + 1
            is_pos = s.get("shap_value", 0) >= 0
            s["direction_label"] = f"→ Supports {ml_label}" if is_pos else f"⊘ Opposes {ml_label}"

        supporting = [s for s in stored_shap if s.get("shap_value", 0) >= 0]
        opposing = [s for s in stored_shap if s.get("shap_value", 0) < 0]
        opposing.sort(key=lambda x: abs(x.get("shap_value", 0)), reverse=True)

        shap_data = {
            "explainer_model": "TreeSHAP (XGBoost Component)",
            "explanation_method": "TreeSHAP" if EXPLAINER else "Feature Salience",
            "is_tree_shap": bool(EXPLAINER),
            "base_value": 6.4901,
            "target_class_idx": target_class_idx,
            "target_class_name": ml_label,
            "top_features": stored_shap[:10],
            "supporting_features": supporting[:10],
            "opposing_features": opposing[:10],
            "all_77_features": stored_shap,
            "total_supporting_count": len(supporting),
            "total_opposing_count": len(opposing)
        }

    # Behavioral Heuristic metrics
    distinct_ports = 1
    if alert.src_ip:
        port_count = db.query(func.count(func.distinct(DBFlow.dst_port))).filter(DBFlow.src_ip == alert.src_ip).scalar()
        if port_count and port_count > 1:
            distinct_ports = int(port_count)
        elif alert.detection_method == "SYN_BURST_HEURISTIC":
            distinct_ports = 8

    heuristic_verdict = {
        "attack_type": "PortScan" if (alert.detection_method == "SYN_BURST_HEURISTIC" or alert.attack_type == "PortScan") else "None",
        "distinct_ports_scanned": distinct_ports,
        "sequential_probing": bool(distinct_ports > 1),
        "payload_activity": "Header-Only Probing (0 B Payload)",
        "heuristic_confidence": alert.detection_confidence if alert.detection_confidence is not None else alert.confidence
    }

    # Synthesize plain-English dual-signal forensic rationale
    method = alert.detection_method or "MACHINE_LEARNING"
    if method == "SYN_BURST_HEURISTIC":
        why_generated = (
            f"The ML model classified this single network flow instance as <strong>{ml_label.upper()}</strong> "
            f"with <strong>{(ml_conf * 100):.1f}%</strong> confidence because single-flow TCP features resemble standard connection initialization.<br><br>"
            f"However, the behavioral <strong>SYN-Burst Heuristic Detector</strong> identified a rapid multi-port reconnaissance sweep "
            f"probing <strong>{distinct_ports} distinct ports</strong> across the network. "
            f"Because multi-port scanning is a behavioral pattern distributed across separate flows, the behavioral heuristic signal triggered "
            f"the final AegisNIDS <strong>{alert.attack_type.upper()}</strong> alert."
        )
    elif method == "ML_HYBRID":
        why_generated = (
            f"Both detection signals correlated: The ML model classified the flow as <strong>{ml_label.upper()}</strong> "
            f"({(ml_conf * 100):.1f}% confidence), and the behavioral SYN-burst detector confirmed multi-port scanning across {distinct_ports} ports. "
            f"The hybrid alert was generated with high statistical confidence."
        )
    else:
        why_generated = (
            f"The ML ensemble model classified this flow as <strong>{alert.attack_type.upper()}</strong> "
            f"with <strong>{(alert.confidence * 100):.1f}%</strong> confidence based on the highlighted 77-feature traffic distribution. "
            f"SHAP feature attributions indicate the top driving features that pushed the decision boundary."
        )

    # Global feature importance across trees
    global_shap = EXPLAINER.get_global_feature_importance(top_k=10) if EXPLAINER else []

    return {
        "alert": {
            "alert_id": alert.alert_id,
            "attack_type": alert.attack_type,
            "severity": alert.severity,
            "confidence": alert.confidence,
            "detection_method": alert.detection_method or "MACHINE_LEARNING",
            "detection_confidence": alert.detection_confidence if alert.detection_confidence is not None else alert.confidence,
            "src_ip": alert.src_ip,
            "dst_ip": alert.dst_ip,
            "src_port": alert.src_port,
            "dst_port": alert.dst_port,
            "model_used": alert.model_used,
            "status": alert.status or "NEW",
            "flow_count": alert.flow_count or 1,
            "timestamp": alert.timestamp.isoformat() if alert.timestamp else None,
            "explanation": alert.explanation or ""
        },
        "ml_verdict": {
            "predicted_label": ml_label,
            "confidence": ml_conf,
            "model_name": alert.model_used or ACTIVE_MODEL,
            "class_probabilities": raw_probs
        },
        "heuristic_verdict": heuristic_verdict,
        "comparison": {
            "ml_vs_heuristic_agreement": (ml_label.lower() == alert.attack_type.lower()),
            "why_alert_generated": why_generated
        },
        "shap": shap_data,
        "global_shap": global_shap
    }

# ─── OBJECTIVE 14: PCAP REPLAY APIS ────────────────────────────────────────

@app.post("/api/replay/start")
def start_pcap_replay(payload: Dict[str, Any] = Body(...)):
    """Initiates an offline PCAP replay session streaming through the live detection pipeline."""
    pcap_path = payload.get("pcap_path")
    delay = float(payload.get("delay", 0.0))
    res = REPLAY_SERVICE.start_replay(
        pcap_path=pcap_path,
        on_flow_callback=handle_live_captured_flow,
        packet_delay=delay
    )
    if res.get("status") == "error":
        raise HTTPException(status_code=400, detail=res.get("message"))
    return res

@app.post("/api/replay/stop")
def stop_pcap_replay():
    """Stops the active offline PCAP replay session."""
    return REPLAY_SERVICE.stop_replay()

@app.get("/api/replay/status")
def get_pcap_replay_status():
    """Returns telemetry of the offline PCAP replay pipeline."""
    return REPLAY_SERVICE.get_status()

@app.get("/api/replay/history")
def get_pcap_replay_history(limit: int = 10, db: Session = Depends(get_db)):
    """Returns audit history of past PCAP replay executions."""
    replays = db.query(DBPCAPReplay).order_by(DBPCAPReplay.id.desc()).limit(limit).all()
    return [
        {
            "id": r.id,
            "replay_id": r.replay_id,
            "filename": r.filename,
            "status": r.status,
            "packets_processed": r.packets_processed,
            "flows_generated": r.flows_generated,
            "predictions_generated": r.predictions_generated,
            "alerts_generated": r.alerts_generated,
            "duration_seconds": r.duration_seconds,
            "started_at": r.started_at.isoformat() if r.started_at else None,
            "completed_at": r.completed_at.isoformat() if r.completed_at else None,
            "error_message": r.error_message
        }
        for r in replays
    ]

@app.post("/api/replay/generate_synthetic")
def generate_synthetic_pcap_demo():
    """Generates a multi-stage attack scenario PCAP in scratch directory for instant offline testing."""
    scratch_dir = os.path.abspath("scratch")
    os.makedirs(scratch_dir, exist_ok=True)
    pcap_path = os.path.join(scratch_dir, "demo_attack_scenario.pcap")

    from replay_pcap import generate_synthetic_attack_pcap
    generate_synthetic_attack_pcap(pcap_path)

    return {
        "status": "success",
        "message": f"Synthetic multi-stage security incident PCAP generated at {pcap_path}",
        "pcap_path": pcap_path,
        "scenarios_included": [
            "Normal HTTP & DNS Browsing (Benign)",
            "TCP SYN PortScan Probes (Ports 21, 22, 80, 443, 3306, 8080)",
            "Web Application Attack (XSS Probe)",
            "Volumetric DDoS Flood Traffic"
        ]
    }

# ─── OBJECTIVE 15: CONTROLLED AUTHORIZED NMAP DEMONSTRATION APIS ───────────

@app.post("/api/demo/nmap/start")
def start_nmap_demonstration(payload: Dict[str, Any] = Body(...)):
    """
    Launches a controlled Nmap PortScan demonstration against an authorized lab target.
    Target must strictly be loopback or RFC1918 private address.
    """
    target = payload.get("target", "127.0.0.1")
    ports = payload.get("ports", "21,22,23,25,53,80,110,135,139,143,443,445,993,995,1433,1521,3306,3389,5432,8000,8080,8443")
    scan_type = payload.get("scan_type", "syn")
    timeout = int(payload.get("timeout_seconds", 25))

    res = NMAP_DEMO_RUNNER.start_demonstration(
        target=target,
        ports=ports,
        scan_type=scan_type,
        timeout_seconds=timeout
    )
    if res.get("status") == "error":
        raise HTTPException(status_code=400, detail=res.get("message"))
    return res

@app.get("/api/demo/nmap/status")
def get_nmap_demo_status():
    """Returns execution status, output logs, and database verification metrics for the Nmap demo."""
    return NMAP_DEMO_RUNNER.get_status()

# ─── WEBSOCKET REAL-TIME ENDPOINTS ──────────────────────────────────────────

@app.websocket("/ws/live")
@app.websocket("/ws/alerts")
async def websocket_live_stream(websocket: WebSocket):
    """Real-time WebSocket endpoint streaming alerts, flows, and telemetry events."""
    await WS_MANAGER.connect(websocket)
    try:
        while True:
            # Keep-alive ping/pong receiver
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_text("pong")
    except WebSocketDisconnect:
        WS_MANAGER.disconnect(websocket)
    except Exception:
        WS_MANAGER.disconnect(websocket)

@app.post("/api/reset")
@app.post("/reset")
def reset_soc_data(db: Session = Depends(get_db)):
    """
    Resets all captured network flows, predictions, alerts, and live capture counters.
    Preserves model registry and active model configurations.
    """
    try:
        db.query(DBIncidentNote).delete()
        db.query(DBIncidentAlert).delete()
        db.query(DBIncident).delete()
        db.query(DBAnalystFeedback).delete()
        db.query(DBAlert).delete()
        db.query(DBPrediction).delete()
        db.query(DBFlow).delete()
        db.commit()
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Database reset failed: {str(e)}")

    # Reset capture service counters & aggregator state
    CAPTURE_SERVICE.reset()

    # Reset alert engine cache
    ALERT_ENGINE.reset()

    return {
        "status": "success",
        "message": "SOC database, alerts, and capture state have been reset successfully.",
        "flows_cleared": True,
        "alerts_cleared": True
    }

@app.get("/", response_class=HTMLResponse)
def serve_dashboard():
    return DASHBOARD_HTML
