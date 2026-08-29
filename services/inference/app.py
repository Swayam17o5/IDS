import os
import sys
import json
import joblib
import torch
import numpy as np
import pandas as pd
from fastapi import FastAPI, HTTPException, Body, Depends
from fastapi.responses import HTMLResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from typing import Dict, List, Any, Optional
from sqlalchemy.orm import Session

# Ensure project root is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))

from pytorch_tabnet.tab_model import TabNetClassifier
import rtdl_revisiting_models as rtdl

from services.registry.registry import ModelRegistry
from services.inference.explainer import SHAPExplainer
from services.inference.ensemble import IDSStackingEnsemble
from services.alert_engine.engine import AlertEngine
from services.feature_extractor.live_capture import (
    CAPTURE_SERVICE,
    check_capture_capabilities,
    get_available_interfaces
)
from database.db import init_db, SessionLocal, get_db
from database.models import DBFlow, DBPrediction, DBAlert, DBModelCard, DBAnalystFeedback, ALERT_STATUSES

app = FastAPI(title="AegisNIDS Real-Time SOC Intelligence Engine", version="1.0.0")

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
ALERT_ENGINE = AlertEngine(min_confidence_threshold=0.80, dedup_window_seconds=120)

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
    global MODELS, CANONICAL_FEATURES, LABEL_MAPPING, EXPLAINER, ACTIVE_MODEL
    base_dir = os.path.join("models", dataset)
    
    # Initialize DB
    init_db()
    
    # Load feature order
    with open(os.path.join(base_dir, "feature_list.json"), "r") as f:
        CANONICAL_FEATURES = json.load(f)
        
    # Load label mapping
    with open(os.path.join(base_dir, "label_mapping.json"), "r") as f:
        raw_map = json.load(f)
        LABEL_MAPPING = {int(k): v for k, v in raw_map.items()}
        
    # Load Models
    MODELS = {}
    
    # 1. XGBoost
    xgb_path = os.path.join(base_dir, "xgboost_cicids2017.pkl")
    if os.path.exists(xgb_path):
        MODELS["xgboost"] = joblib.load(xgb_path)
        
    # 2. LightGBM
    lgb_path = os.path.join(base_dir, "lightgbm_cicids2017.pkl")
    if os.path.exists(lgb_path):
        MODELS["lightgbm"] = joblib.load(lgb_path)
        
    # 3. HistGradientBoosting
    hgb_path = os.path.join(base_dir, "hist_gradient_boosting_cicids2017.pkl")
    if os.path.exists(hgb_path):
        MODELS["hist_gradient_boosting"] = joblib.load(hgb_path)
        
    # 4. MLP Classifier
    mlp_path = os.path.join(base_dir, "mlp_classifier_cicids2017.pkl")
    if os.path.exists(mlp_path):
        MODELS["mlp_classifier"] = joblib.load(mlp_path)
        
    # 5. TabNet
    tabnet_path = os.path.join(base_dir, "tabnet_cicids2017.zip")
    if os.path.exists(tabnet_path):
        tabnet_model = TabNetClassifier()
        tabnet_model.load_model(tabnet_path)
        MODELS["tabnet"] = tabnet_model
        
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
        
    # 7. Weighted Voting Ensemble
    ensemble_path = os.path.join(base_dir, "stacking_ensemble.pkl")
    if os.path.exists(ensemble_path):
        MODELS["weighted_voting_ensemble"] = joblib.load(ensemble_path)
        
    # Initialize Tree SHAP explainer on XGBoost
    if "xgboost" in MODELS:
        EXPLAINER = SHAPExplainer(MODELS["xgboost"], CANONICAL_FEATURES)
        
    ACTIVE_MODEL = "weighted_voting_ensemble" if "weighted_voting_ensemble" in MODELS else "xgboost"
    print(f"Loaded {len(MODELS)} models for {dataset} (Active: {ACTIVE_MODEL})!")

@app.on_event("startup")
def startup_event():
    init_models("cicids2017")

class FlowPredictRequest(BaseModel):
    features: Dict[str, float] = Field(..., description="Map of 77 CICIDS2017 canonical feature names to float values")
    metadata: Optional[Dict[str, Any]] = Field(default=None, description="Network context (src_ip, dst_ip, ports, proto)")

def execute_flow_prediction(req: FlowPredictRequest, db: Session) -> Dict[str, Any]:
    """Core prediction and database persistence pipeline."""
    ordered_values = [req.features.get(f, 0.0) for f in CANONICAL_FEATURES]
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
            # Normalized scan evidence score (0.80 - 0.99 depending on ports probed)
            final_confidence = heuristic_score if heuristic_score > 0 else 0.80
            detection_confidence = final_confidence
    else:
        detection_method = "MACHINE_LEARNING"
        final_label = ml_predicted_label
        final_class_id = ml_predicted_class_id
        final_confidence = ml_confidence
        detection_confidence = ml_confidence

    print(
        f"[INFERENCE_VERDICT] Method: {detection_method} | Verdict: {final_label} (Conf: {final_confidence:.4f}) | "
        f"ML Model: {final_model_key} (Pred: {ml_predicted_label} @ {ml_confidence:.4f}, PortScan Prob: {ml_portscan_prob:.6f}) | "
        f"Heuristic Score: {heuristic_score:.4f} (Ports: {distinct_ports})",
        flush=True
    )

    response_payload = {
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

    # Persist to Database & Trigger Alert Engine
    try:
        meta = req.metadata or {}
        # Store full 77-feature vector for retraining feedback loop
        flow_rec = DBFlow(
            src_ip=meta.get("src_ip", "0.0.0.0"),
            dst_ip=meta.get("dst_ip", "0.0.0.0"),
            src_port=int(meta.get("src_port", 0)),
            dst_port=int(meta.get("dst_port", 0)),
            protocol=int(meta.get("protocol", 6)),
            features_json=req.features
        )
        db.add(flow_rec)
        db.flush()

        pred_rec = DBPrediction(
            flow_id=flow_rec.id,
            model_name=final_model_key,
            predicted_label=final_label,
            predicted_class_id=final_class_id,
            confidence=final_confidence,
            detection_method=detection_method,
            detection_confidence=detection_confidence,
            ml_predicted_label=ml_predicted_label,
            ml_confidence=ml_confidence,
            ml_portscan_prob=ml_portscan_prob,
            probabilities_json=raw_probs,
            shap_json=shap_top_features
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
                dst_port=alert_event["dst_port"],
                model_used=alert_event["model_used"],
                dedup_key=alert_event["dedup_key"],
                status="NEW",
                shap_json=shap_top_features,
                explanation=explanation
            )
            db.add(db_alert)
            alert_event["explanation"] = explanation
            response_payload["alert_generated"] = alert_event
        else:
            response_payload["alert_generated"] = None

        db.commit()
    except Exception as e:
        db.rollback()

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
        label = verdict.get('predicted_label', 'Unknown')
        confidence = verdict.get('confidence', 0.0)
        method = verdict.get('detection_method', 'MACHINE_LEARNING')
        is_scan = meta.get('is_port_scan', False)
        alert_generated = res.get('alert_generated')

        print(
            "[LIVE_FLOW] iface='" + str(CAPTURE_SERVICE.active_interface) + "' ip=" + str(CAPTURE_SERVICE.active_ip) + " "
            + str(meta.get('src_ip')) + ":" + str(meta.get('src_port')) + " -> "
            + str(meta.get('dst_ip')) + ":" + str(meta.get('dst_port')) + " "
            "proto=" + str(meta.get('protocol')) + " pkts=" + str(meta.get('total_packets', 1)) + " "
            "dur=" + str(round(meta.get('duration_seconds', 0.0), 4)) + "s "
            "method=" + str(method) + " label=" + str(label) + " conf=" + str(round(confidence * 100, 2)) + "% "
            "model=" + str(verdict.get('active_model_used')) + " "
            "alert=" + ("YES - " + alert_generated['alert_id'] if alert_generated else "none"),
            flush=True
        )
    except Exception as e:
        print(f"[LIVE_FLOW_ERROR] {str(e)}", flush=True)
        db.rollback()
    finally:
        db.close()

@app.get("/health")
def health_check():
    return {
        "status": "ok",
        "loaded_models": list(MODELS.keys()),
        "active_model": ACTIVE_MODEL
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
    # Triaged as real = ACKNOWLEDGED + ESCALATED + RESOLVED
    # Total triaged = Triaged as real + FALSE_POSITIVE
    triaged_real = status_ack + status_esc + status_res
    total_triaged = triaged_real + status_fp
    analyst_precision = (float(triaged_real) / float(total_triaged) * 100.0) if total_triaged > 0 else None

    latest_alert = db.query(DBAlert).filter(DBAlert.status != "FALSE_POSITIVE").order_by(DBAlert.id.desc()).first()
    if not latest_alert:
        latest_alert = db.query(DBAlert).order_by(DBAlert.id.desc()).first()
    latest_shap = latest_alert.shap_json if latest_alert else []
    latest_explanation = latest_alert.explanation if latest_alert else ""

    active_label = "weighted_voting_ensemble" if ACTIVE_MODEL == "stacking_ensemble" else ACTIVE_MODEL

    return {
        "total_flows": flow_count,
        "total_predictions": pred_count,
        "total_alerts": alert_count,
        "analyst_precision": round(analyst_precision, 1) if analyst_precision is not None else None,
        "total_triaged": total_triaged,
        "active_model": active_label,
        "capture_status": CAPTURE_SERVICE.get_status(),
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

@app.post("/api/reset")
@app.post("/reset")
def reset_soc_data(db: Session = Depends(get_db)):
    """
    Resets all captured network flows, predictions, alerts, and live capture counters.
    Preserves model registry and active model configurations.
    """
    try:
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

DASHBOARD_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>AegisNIDS // Security Operations Center</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;700&family=Plus+Jakarta+Sans:wght@400;600;700;800&display=swap" rel="stylesheet">
  <style>
    :root {
      --bg: #07090e;
      --card-bg: rgba(16, 22, 34, 0.75);
      --card-border: rgba(45, 55, 72, 0.5);
      --accent-cyan: #00f0ff;
      --accent-blue: #3b82f6;
      --accent-purple: #8b5cf6;
      --critical: #ef4444;
      --high: #f97316;
      --medium: #eab308;
      --text: #f1f5f9;
      --text-muted: #94a3b8;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      background: radial-gradient(circle at 10% 20%, #0d1322 0%, #07090e 90%);
      color: var(--text);
      font-family: 'Plus Jakarta Sans', sans-serif;
      min-height: 100vh;
      display: flex;
      flex-direction: column;
    }
    header {
      padding: 16px 32px;
      display: flex;
      justify-content: space-between;
      align-items: center;
      border-bottom: 1px solid var(--card-border);
      backdrop-filter: blur(12px);
      background: rgba(7, 9, 14, 0.85);
      position: sticky;
      top: 0;
      z-index: 100;
    }
    .brand { display: flex; align-items: center; gap: 12px; }
    .brand-icon {
      width: 36px; height: 36px; border-radius: 8px;
      background: linear-gradient(135deg, var(--accent-cyan), var(--accent-blue));
      display: flex; align-items: center; justify-content: center;
      font-weight: 800; color: #000; font-size: 18px;
    }
    .brand h1 { font-size: 19px; font-weight: 800; letter-spacing: 0.5px; }
    .brand span { color: var(--accent-cyan); font-weight: 500; font-size: 13px; margin-left: 8px; }
    
    .header-actions { display: flex; align-items: center; gap: 14px; }
    .mode-indicator {
      display: flex; align-items: center; gap: 8px;
      padding: 6px 14px; border-radius: 20px; font-size: 12px; font-weight: 700;
      letter-spacing: 0.5px; text-transform: uppercase; font-family: 'JetBrains Mono', monospace;
    }
    .mode-indicator.replay {
      background: rgba(59, 130, 246, 0.12); border: 1px solid rgba(59, 130, 246, 0.3); color: #60a5fa;
    }
    .mode-indicator.live {
      background: rgba(239, 68, 68, 0.15); border: 1px solid rgba(239, 68, 68, 0.4); color: #f87171;
    }
    .mode-dot { width: 8px; height: 8px; border-radius: 50%; }
    .mode-dot.blue { background: #3b82f6; box-shadow: 0 0 8px #3b82f6; }
    .mode-dot.red { background: #ef4444; box-shadow: 0 0 10px #ef4444; animation: pulse 1.5s infinite; }
    @keyframes pulse { 0%, 100% { opacity: 1; } 50% { opacity: 0.3; } }

    main { padding: 24px 32px; flex: 1; display: flex; flex-direction: column; gap: 20px; max-width: 1600px; margin: 0 auto; width: 100%; }

    /* Live Capture Control Bar */
    .capture-panel {
      background: rgba(13, 20, 36, 0.85); border: 1px solid var(--card-border);
      border-radius: 12px; padding: 16px 20px; display: flex; flex-direction: column; gap: 12px;
      backdrop-filter: blur(16px);
    }
    .capture-top-row { display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 12px; }
    .capture-controls { display: flex; align-items: center; gap: 10px; flex-wrap: wrap; }
    .select-input {
      background: rgba(7, 9, 14, 0.9); border: 1px solid var(--card-border);
      color: #fff; padding: 8px 14px; border-radius: 6px; font-size: 13px; outline: none;
      font-family: 'Plus Jakarta Sans', sans-serif;
    }
    .btn {
      padding: 8px 16px; border-radius: 6px; font-weight: 700; font-size: 13px; cursor: pointer;
      border: none; display: flex; align-items: center; gap: 6px; transition: all 0.2s ease;
    }
    .btn-live-start { background: linear-gradient(135deg, #10b981, #059669); color: #fff; }
    .btn-live-start:hover { opacity: 0.9; box-shadow: 0 0 12px rgba(16, 185, 129, 0.4); }
    .btn-live-stop { background: linear-gradient(135deg, #ef4444, #dc2626); color: #fff; }
    .btn-live-stop:hover { opacity: 0.9; box-shadow: 0 0 12px rgba(239, 68, 68, 0.4); }
    .btn:disabled { opacity: 0.4; cursor: not-allowed; }
    
    .driver-banner {
      background: rgba(234, 179, 8, 0.1); border: 1px solid rgba(234, 179, 8, 0.3);
      padding: 10px 14px; border-radius: 6px; font-size: 12px; color: #facc15;
      display: flex; align-items: center; justify-content: space-between; gap: 10px;
    }
    .driver-banner a { color: #00f0ff; text-decoration: underline; font-weight: 700; }
    .guardrail-note { font-size: 11px; color: var(--text-muted); font-style: italic; }

    /* Metrics Grid */
    .metrics-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 16px; }
    .card {
      background: var(--card-bg); border: 1px solid var(--card-border);
      border-radius: 12px; padding: 18px 20px; backdrop-filter: blur(16px);
      box-shadow: 0 8px 32px rgba(0,0,0,0.3); position: relative; overflow: hidden;
    }
    .card::before {
      content: ''; position: absolute; top: 0; left: 0; width: 100%; height: 2px;
      background: linear-gradient(90deg, transparent, var(--accent-cyan), transparent);
    }
    .card-title { font-size: 12px; text-transform: uppercase; color: var(--text-muted); font-weight: 700; letter-spacing: 0.5px; }
    .card-val { font-size: 28px; font-weight: 800; margin-top: 6px; font-family: 'JetBrains Mono', monospace; }
    .card-val.crit { color: var(--critical); text-shadow: 0 0 16px rgba(239, 68, 68, 0.4); }
    .card-val.high { color: var(--high); }
    .card-val.cyan { color: var(--accent-cyan); text-shadow: 0 0 16px rgba(0, 240, 255, 0.4); }
    
    /* Two Column Layout */
    .content-grid { display: grid; grid-template-columns: 2fr 1fr; gap: 20px; }
    @media (max-width: 1100px) { .content-grid { grid-template-columns: 1fr; } }
    
    /* Flow Stream & Alert Feed Table */
    .table-container { overflow-x: auto; max-height: 380px; }
    table { width: 100%; border-collapse: collapse; text-align: left; font-size: 13px; }
    th { padding: 12px 14px; color: var(--text-muted); font-weight: 600; border-bottom: 1px solid var(--card-border); background: rgba(0,0,0,0.2); }
    td { padding: 10px 14px; border-bottom: 1px solid rgba(255,255,255,0.05); font-family: 'JetBrains Mono', monospace; font-size: 12px; }
    tr:hover { background: rgba(255,255,255,0.02); }
    .badge {
      display: inline-block; padding: 3px 8px; border-radius: 6px; font-size: 11px; font-weight: 700; text-transform: uppercase;
    }
    .badge.CRITICAL { background: rgba(239, 68, 68, 0.15); color: #f87171; border: 1px solid rgba(239, 68, 68, 0.4); }
    .badge.HIGH { background: rgba(249, 115, 22, 0.15); color: #fb923c; border: 1px solid rgba(249, 115, 22, 0.4); }
    .badge.MEDIUM { background: rgba(234, 179, 8, 0.15); color: #facc15; border: 1px solid rgba(234, 179, 8, 0.4); }
    .badge.BENIGN, .badge.Benign { background: rgba(16, 185, 129, 0.15); color: #34d399; border: 1px solid rgba(16, 185, 129, 0.4); }
    .badge.ATTACK, .badge.Attack { background: rgba(239, 68, 68, 0.15); color: #f87171; border: 1px solid rgba(239, 68, 68, 0.4); }
    .badge.proto { background: rgba(99, 102, 241, 0.15); color: #818cf8; border: 1px solid rgba(99, 102, 241, 0.3); font-size: 10px; }
    
    /* SHAP Bars */
    .shap-bar-item { margin-bottom: 12px; }
    .shap-bar-label { display: flex; justify-content: space-between; font-size: 12px; margin-bottom: 4px; font-family: 'JetBrains Mono', monospace; }
    .shap-bar-track { width: 100%; height: 7px; background: rgba(255,255,255,0.05); border-radius: 4px; overflow: hidden; }
    .shap-bar-fill { height: 100%; background: linear-gradient(90deg, var(--accent-cyan), var(--accent-blue)); border-radius: 4px; }
    
    /* Models Grid */
    .models-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 14px; }
    .model-card {
      background: rgba(255,255,255,0.02); border: 1px solid var(--card-border);
      border-radius: 8px; padding: 14px; display: flex; flex-direction: column; justify-content: space-between; gap: 12px;
    }
    .model-card.active { border-color: var(--accent-cyan); background: rgba(0, 240, 255, 0.03); }
    .model-header { display: flex; justify-content: space-between; align-items: center; }
    .model-name { font-weight: 700; font-size: 14px; }
    .model-metrics { display: grid; grid-template-columns: 1fr 1fr; gap: 6px; font-size: 12px; color: var(--text-muted); font-family: 'JetBrains Mono', monospace; margin-top: 6px; }
    .model-metrics span { color: #fff; font-weight: 600; }
    .switch-btn {
      padding: 6px 12px; border-radius: 4px; font-size: 12px; font-weight: 700; cursor: pointer;
      background: rgba(255,255,255,0.05); border: 1px solid var(--card-border); color: #fff;
    }
    .switch-btn:hover { background: rgba(255,255,255,0.1); }
    .switch-btn.current { background: rgba(0, 240, 255, 0.15); border-color: var(--accent-cyan); color: var(--accent-cyan); }

    /* Reset Button */
    .btn-reset {
      background: rgba(239, 68, 68, 0.12);
      border: 1px solid rgba(239, 68, 68, 0.35);
      color: #f87171;
      padding: 6px 14px;
      border-radius: 20px;
      font-size: 12px;
      font-weight: 700;
      letter-spacing: 0.5px;
      display: inline-flex;
      align-items: center;
      gap: 7px;
      cursor: pointer;
      font-family: 'JetBrains Mono', monospace;
      transition: all 0.2s cubic-bezier(0.4, 0, 0.2, 1);
    }
    .btn-reset:hover {
      background: rgba(239, 68, 68, 0.25);
      border-color: #ef4444;
      color: #fff;
      box-shadow: 0 0 16px rgba(239, 68, 68, 0.35);
      transform: translateY(-1px);
    }
    .btn-reset:active {
      transform: translateY(0);
    }

    /* Reset Confirmation Modal */
    .modal-backdrop {
      position: fixed;
      top: 0; left: 0; width: 100vw; height: 100vh;
      background: rgba(4, 7, 14, 0.82);
      backdrop-filter: blur(10px);
      z-index: 1000;
      display: flex;
      align-items: center;
      justify-content: center;
      animation: fadeIn 0.15s ease-out;
    }
    .modal-dialog {
      background: #0d1424;
      border: 1px solid rgba(239, 68, 68, 0.35);
      box-shadow: 0 25px 60px rgba(0,0,0,0.8), 0 0 40px rgba(239, 68, 68, 0.15);
      border-radius: 14px;
      width: 90%;
      max-width: 480px;
      padding: 24px;
      animation: scaleIn 0.2s cubic-bezier(0.16, 1, 0.3, 1);
    }
    .modal-header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 14px;
    }
    .modal-close-btn {
      background: none; border: none; color: var(--text-muted);
      font-size: 16px; cursor: pointer; padding: 4px 8px; border-radius: 6px;
    }
    .modal-close-btn:hover { color: #fff; background: rgba(255,255,255,0.08); }
    .modal-body { font-size: 13px; color: #cbd5e1; line-height: 1.6; }
    .modal-footer {
      display: flex; justify-content: flex-end; gap: 10px; margin-top: 20px;
    }
    .btn-modal-cancel {
      background: rgba(255,255,255,0.06); border: 1px solid var(--card-border); color: #cbd5e1;
    }
    .btn-modal-cancel:hover { background: rgba(255,255,255,0.12); color: #fff; }
    .btn-modal-confirm {
      background: linear-gradient(135deg, #ef4444, #dc2626); color: #fff;
    }
    .btn-modal-confirm:hover { box-shadow: 0 0 18px rgba(239, 68, 68, 0.5); opacity: 0.95; }
    @keyframes fadeIn { from { opacity: 0; } to { opacity: 1; } }
    @keyframes scaleIn { from { opacity: 0; transform: scale(0.94); } to { opacity: 1; transform: scale(1); } }

    /* Triage Action Buttons */
    .triage-actions { display: flex; gap: 4px; align-items: center; }
    .triage-btn {
      padding: 3px 7px; border-radius: 4px; font-size: 10px; font-weight: 700; cursor: pointer;
      border: 1px solid; transition: all 0.15s ease; font-family: 'JetBrains Mono', monospace;
      letter-spacing: 0.3px; text-transform: uppercase;
    }
    .triage-btn.ack { background: rgba(59, 130, 246, 0.12); border-color: rgba(59, 130, 246, 0.4); color: #60a5fa; }
    .triage-btn.ack:hover { background: rgba(59, 130, 246, 0.25); box-shadow: 0 0 8px rgba(59, 130, 246, 0.3); }
    .triage-btn.fp { background: rgba(234, 179, 8, 0.12); border-color: rgba(234, 179, 8, 0.4); color: #facc15; }
    .triage-btn.fp:hover { background: rgba(234, 179, 8, 0.25); box-shadow: 0 0 8px rgba(234, 179, 8, 0.3); }
    .triage-btn.esc { background: rgba(168, 85, 247, 0.12); border-color: rgba(168, 85, 247, 0.4); color: #c084fc; }
    .triage-btn.esc:hover { background: rgba(168, 85, 247, 0.25); box-shadow: 0 0 8px rgba(168, 85, 247, 0.3); }
    .triage-btn.res { background: rgba(16, 185, 129, 0.12); border-color: rgba(16, 185, 129, 0.4); color: #34d399; }
    .triage-btn.res:hover { background: rgba(16, 185, 129, 0.25); box-shadow: 0 0 8px rgba(16, 185, 129, 0.3); }

    /* Status Badges */
    .badge.NEW { background: rgba(59, 130, 246, 0.15); color: #60a5fa; border: 1px solid rgba(59, 130, 246, 0.4); }
    .badge.ACKNOWLEDGED { background: rgba(99, 102, 241, 0.15); color: #818cf8; border: 1px solid rgba(99, 102, 241, 0.4); }
    .badge.FALSE_POSITIVE { background: rgba(234, 179, 8, 0.15); color: #facc15; border: 1px solid rgba(234, 179, 8, 0.4); }
    .badge.ESCALATED { background: rgba(168, 85, 247, 0.15); color: #c084fc; border: 1px solid rgba(168, 85, 247, 0.4); }
    .badge.RESOLVED { background: rgba(16, 185, 129, 0.15); color: #34d399; border: 1px solid rgba(16, 185, 129, 0.4); }
    tr.alert-resolved { opacity: 0.5; }
    tr.alert-fp { opacity: 0.55; }

    /* Alert Explanation */
    .explanation-box {
      background: rgba(0, 240, 255, 0.04); border: 1px solid rgba(0, 240, 255, 0.15);
      border-radius: 8px; padding: 12px 16px; margin-bottom: 16px;
      font-size: 13px; color: #e2e8f0; line-height: 1.6;
    }
    .explanation-box .label { font-size: 10px; text-transform: uppercase; font-weight: 700; color: var(--accent-cyan); letter-spacing: 0.5px; margin-bottom: 6px; }
    .explanation-inline { font-size: 10px; color: #94a3b8; font-style: italic; margin-top: 2px; max-width: 200px; line-height: 1.3; }

    /* FP Correction Modal */
    .fp-modal-dialog {
      background: #0d1424;
      border: 1px solid rgba(234, 179, 8, 0.35);
      box-shadow: 0 25px 60px rgba(0,0,0,0.8), 0 0 40px rgba(234, 179, 8, 0.15);
      border-radius: 14px; width: 90%; max-width: 520px; padding: 24px;
      animation: scaleIn 0.2s cubic-bezier(0.16, 1, 0.3, 1);
    }
    .fp-form-group { margin-bottom: 14px; }
    .fp-form-group label { display: block; font-size: 12px; font-weight: 700; color: var(--text-muted); margin-bottom: 6px; text-transform: uppercase; letter-spacing: 0.5px; }
    .fp-form-group select, .fp-form-group textarea {
      width: 100%; background: rgba(7, 9, 14, 0.9); border: 1px solid var(--card-border);
      color: #fff; padding: 10px 14px; border-radius: 6px; font-size: 13px; outline: none;
      font-family: 'Plus Jakarta Sans', sans-serif;
    }
    .fp-form-group textarea { resize: vertical; min-height: 60px; }
    .btn-fp-submit { background: linear-gradient(135deg, #eab308, #ca8a04); color: #000; font-weight: 700; }
    .btn-fp-submit:hover { box-shadow: 0 0 18px rgba(234, 179, 8, 0.5); opacity: 0.95; }

    /* Toast Notification */
    .toast {
      position: fixed;
      bottom: 24px;
      right: 24px;
      background: #0f172a;
      border: 1px solid var(--accent-cyan);
      box-shadow: 0 10px 30px rgba(0,0,0,0.5), 0 0 20px rgba(0, 240, 255, 0.25);
      color: #fff;
      padding: 12px 20px;
      border-radius: 8px;
      font-size: 13px;
      font-weight: 600;
      z-index: 2000;
      display: flex;
      align-items: center;
      gap: 10px;
      animation: toastSlideIn 0.25s ease-out;
    }
    @keyframes toastSlideIn {
      from { transform: translateY(20px); opacity: 0; }
      to { transform: translateY(0); opacity: 1; }
    }

    /* ── Change Network Button ── */
    .btn-change-network {
      background: rgba(0, 240, 255, 0.08);
      border: 1px solid rgba(0, 240, 255, 0.28);
      color: var(--accent-cyan);
      padding: 6px 14px;
      border-radius: 20px;
      font-size: 12px;
      font-weight: 700;
      letter-spacing: 0.5px;
      display: inline-flex;
      align-items: center;
      gap: 7px;
      cursor: pointer;
      font-family: 'JetBrains Mono', monospace;
      transition: all 0.2s cubic-bezier(0.4, 0, 0.2, 1);
    }
    .btn-change-network:hover {
      background: rgba(0, 240, 255, 0.18);
      border-color: var(--accent-cyan);
      box-shadow: 0 0 16px rgba(0, 240, 255, 0.22);
      transform: translateY(-1px);
    }
    .btn-change-network:active { transform: translateY(0); }

    /* ── Active Network Label ── */
    .active-network-label {
      font-size: 11px;
      font-family: 'JetBrains Mono', monospace;
      color: var(--text-muted);
      display: flex;
      align-items: center;
      gap: 5px;
      padding: 4px 10px;
      background: rgba(255,255,255,0.03);
      border: 1px solid rgba(255,255,255,0.07);
      border-radius: 12px;
      white-space: nowrap;
    }
    .active-network-label .net-name {
      color: #e2e8f0;
      font-weight: 700;
    }

    /* ── Capture Status Indicator (header) ── */
    .capture-status-indicator {
      display: inline-flex;
      align-items: center;
      gap: 7px;
      padding: 5px 12px;
      border-radius: 20px;
      font-size: 11px;
      font-family: 'JetBrains Mono', monospace;
      font-weight: 600;
      letter-spacing: 0.3px;
      border: 1px solid rgba(255,255,255,0.07);
      background: rgba(255,255,255,0.03);
      color: var(--text-muted);
      transition: all 0.3s ease;
      white-space: nowrap;
    }
    .capture-status-indicator.active {
      background: rgba(16, 185, 129, 0.08);
      border-color: rgba(16, 185, 129, 0.35);
      color: #34d399;
    }
    .capture-status-indicator.active .cap-dot {
      background: #10b981;
      box-shadow: 0 0 7px #10b981;
      animation: pulse 1.5s infinite;
    }
    .capture-status-indicator.inactive .cap-dot {
      background: var(--text-muted);
    }
    .cap-dot {
      width: 7px; height: 7px; border-radius: 50%;
      flex-shrink: 0;
    }
    .cap-iface { color: #fff; font-weight: 700; max-width: 140px; overflow: hidden; text-overflow: ellipsis; }
    .cap-ip { color: var(--accent-cyan); opacity: 0.85; }

    /* ── Change Network Modal ── */
    .network-modal-dialog {
      background: #0c1528;
      border: 1px solid rgba(0, 240, 255, 0.22);
      box-shadow: 0 25px 60px rgba(0,0,0,0.8), 0 0 40px rgba(0, 240, 255, 0.1);
      border-radius: 14px;
      width: 90%;
      max-width: 520px;
      padding: 24px;
      animation: scaleIn 0.2s cubic-bezier(0.16, 1, 0.3, 1);
    }
    .network-iface-list {
      display: flex;
      flex-direction: column;
      gap: 8px;
      max-height: 260px;
      overflow-y: auto;
      margin: 14px 0;
      padding-right: 4px;
    }
    .network-iface-list::-webkit-scrollbar { width: 4px; }
    .network-iface-list::-webkit-scrollbar-track { background: rgba(255,255,255,0.03); border-radius: 2px; }
    .network-iface-list::-webkit-scrollbar-thumb { background: rgba(0,240,255,0.25); border-radius: 2px; }
    .iface-option-btn {
      background: rgba(255,255,255,0.03);
      border: 1px solid rgba(255,255,255,0.07);
      border-radius: 8px;
      padding: 12px 14px;
      cursor: pointer;
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 12px;
      transition: all 0.15s ease;
      text-align: left;
      width: 100%;
      color: var(--text);
    }
    .iface-option-btn:hover {
      background: rgba(0, 240, 255, 0.06);
      border-color: rgba(0, 240, 255, 0.2);
    }
    .iface-option-btn.selected {
      background: rgba(0, 240, 255, 0.1);
      border-color: var(--accent-cyan);
      box-shadow: 0 0 10px rgba(0, 240, 255, 0.12);
    }
    .iface-name { font-weight: 700; font-size: 13px; }
    .iface-ip {
      font-size: 11px; font-family: 'JetBrains Mono', monospace;
      color: var(--text-muted); margin-top: 2px;
    }
    .iface-active-tag {
      font-size: 10px; font-weight: 700; font-family: 'JetBrains Mono', monospace;
      padding: 2px 7px; border-radius: 4px; text-transform: uppercase; white-space: nowrap;
      background: rgba(0, 240, 255, 0.12); color: var(--accent-cyan);
      border: 1px solid rgba(0, 240, 255, 0.3);
    }
    .btn-detect-networks {
      background: rgba(255,255,255,0.05);
      border: 1px solid rgba(255,255,255,0.1);
      color: #cbd5e1; padding: 6px 12px; border-radius: 6px;
      font-size: 12px; font-weight: 600; cursor: pointer;
      display: inline-flex; align-items: center; gap: 6px;
      transition: all 0.15s ease; font-family: 'Plus Jakarta Sans', sans-serif;
    }
    .btn-detect-networks:hover { background: rgba(255,255,255,0.1); border-color: rgba(255,255,255,0.22); }
    .btn-detect-networks:disabled { opacity: 0.5; cursor: not-allowed; }
    .btn-network-apply {
      background: linear-gradient(135deg, #00b4cc, #0077aa); color: #fff;
    }
    .btn-network-apply:hover { box-shadow: 0 0 18px rgba(0, 240, 255, 0.35); opacity: 0.95; }
    .btn-network-apply:disabled { opacity: 0.35; cursor: not-allowed; }
    .network-current-row {
      background: rgba(0,0,0,0.22);
      border: 1px solid rgba(255,255,255,0.06);
      border-radius: 8px; padding: 10px 14px;
      font-size: 12px; font-family: 'JetBrains Mono', monospace;
      color: var(--text-muted); display: flex; align-items: center; gap: 8px;
    }
    .network-current-row strong { color: var(--accent-cyan); }
  </style>
</head>
<body>
  <header>
    <div class="brand">
      <div class="brand-icon">🛡️</div>
      <div>
        <h1>AegisNIDS <span>SOC Intelligence</span></h1>
      </div>
    </div>
    <div class="header-actions">
      <div id="mode-badge" class="mode-indicator replay">
        <span id="mode-dot" class="mode-dot blue"></span>
        <span id="mode-text">REPLAY MODE</span>
      </div>

      <!-- Capture Status Indicator: shows active interface + IP in real time -->
      <div id="capture-status-indicator" class="capture-status-indicator inactive"
           title="Packet capture status — interface and local IP address">
        <span class="cap-dot" id="cap-status-dot"></span>
        <span id="cap-status-text">Packet Capture: Inactive</span>
      </div>

      <div id="active-network-label" class="active-network-label" title="Currently monitored network interface">
        <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="2" y="2" width="20" height="8" rx="2"/><rect x="2" y="14" width="20" height="8" rx="2"/><line x1="6" y1="6" x2="6.01" y2="6"/><line x1="6" y1="18" x2="6.01" y2="18"/></svg>
        Active Network: <span id="active-net-name" class="net-name">—</span>
      </div>
      <button id="btn-change-network" class="btn-change-network" onclick="openNetworkModal()" title="Switch the active packet-capture network interface without reloading">
        <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M5 12h14"/><path d="m12 5 7 7-7 7"/></svg>
        CHANGE NETWORK
      </button>
      <button id="btn-reset-soc" class="btn-reset" onclick="openResetModal()" title="Reset all flows, alerts, and telemetry counters">
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
          <path d="M3 12a9 9 0 1 0 9-9 9.75 9.75 0 0 0-6.74 2.74L3 8"/>
          <path d="M3 3v5h5"/>
        </svg>
        RESET SOC DATA
      </button>
    </div>
  </header>

  <main>
    <!-- Live Capture Control Bar -->
    <div class="capture-panel">
      <div class="capture-top-row">
        <div class="capture-controls">
          <label style="font-size: 12px; font-weight: 700; color: var(--text-muted);">ADAPTER:</label>
          <select id="interface-select" class="select-input">
            <option value="loopback">Software Loopback (127.0.0.1)</option>
          </select>
          <button id="btn-start-cap" class="btn btn-live-start" onclick="startLiveCapture()">▶ START LIVE CAPTURE</button>
          <button id="btn-stop-cap" class="btn btn-live-stop" onclick="stopLiveCapture()" style="display: none;">⏹ STOP CAPTURE</button>
        </div>
        <div id="capture-stats-badge" style="font-size: 12px; font-family: 'JetBrains Mono', monospace; color: var(--text-muted);">
          Packets: <span id="cap-pkts" style="color: #fff; font-weight: 700;">0</span> | Flows: <span id="cap-flows" style="color: #fff; font-weight: 700;">0</span>
        </div>
      </div>

      <!-- Missing Driver Diagnostic Warning Banner -->
      <div id="driver-warning" class="driver-banner" style="display: none;">
        <div>⚠️ <strong>Npcap Packet Driver Notice:</strong> Layer-2 packet sniffing on Windows requires Npcap.</div>
        <a href="https://npcap.com/#download" target="_blank">Download Npcap (WinPcap-Compatible Mode) →</a>
      </div>

      <div class="guardrail-note">
        🔒 Safety Guardrail: Traffic capture defaults to local loopback (127.0.0.1). Flows are projected into 77 canonical features and evaluated through the active ML model in real time.
      </div>
    </div>

    <!-- Metrics Cards -->
    <div class="metrics-grid">
      <div class="card">
        <div class="card-title">Total Network Flows</div>
        <div class="card-val cyan" id="stat-flows">0</div>
      </div>
      <div class="card">
        <div class="card-title">Active Security Alerts</div>
        <div class="card-val" id="stat-alerts">0</div>
      </div>
      <div class="card">
        <div class="card-title">Critical Threats</div>
        <div class="card-val crit" id="stat-crit">0</div>
      </div>
      <div class="card">
        <div class="card-title">Analyst-Verified Precision</div>
        <div class="card-val" id="stat-precision" style="color: var(--text-muted); font-size: 24px;">—</div>
      </div>
      <div class="card">
        <div class="card-title">Active ML Model</div>
        <div class="card-val" style="font-size: 15px; color: #fff; font-family: 'Plus Jakarta Sans'; word-break: break-word;" id="stat-active">weighted_voting_ensemble</div>
      </div>
    </div>

    <!-- Live Flow Stream Panel (Shows every classified flow: Benign & Attack) -->
    <div class="card">
      <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 14px;">
        <div>
          <h2 style="font-size: 16px; font-weight: 700;">Live Network Flow Classification Stream</h2>
          <div style="font-size: 12px; color: var(--text-muted); margin-top: 2px;">Real-time ML flow ingestion & predictions (Last 30 Flows)</div>
        </div>
        <div style="display: flex; align-items: center; gap: 8px; font-size: 11px; font-family: 'JetBrains Mono', monospace; color: var(--accent-cyan);">
          <span style="display: inline-block; width: 8px; height: 8px; border-radius: 50%; background: #10b981; box-shadow: 0 0 8px #10b981;"></span>
          INGESTION ACTIVE
        </div>
      </div>
      <div class="table-container" style="max-height: 280px;">
        <table>
          <thead>
            <tr>
              <th>Flow ID</th>
              <th>Time</th>
              <th>Protocol</th>
              <th>Source (IP:Port)</th>
              <th>Destination (IP:Port)</th>
              <th>Predicted Class</th>
              <th>Confidence</th>
              <th>Model</th>
            </tr>
          </thead>
          <tbody id="flows-body">
            <tr><td colspan="8" style="text-align: center; color: var(--text-muted);">Awaiting live network traffic...</td></tr>
          </tbody>
        </table>
      </div>
    </div>

    <!-- Alert Feed & SHAP Panel -->
    <div class="content-grid">
      <div class="card">
        <h2 style="font-size: 16px; font-weight: 700; margin-bottom: 16px;">Live Security Incident & Alert Stream</h2>
        <div class="table-container">
          <table>
            <thead>
              <tr>
                <th>Alert ID</th>
                <th>Severity</th>
                <th>Attack Type</th>
                <th>Confidence</th>
                <th>Source IP</th>
                <th>Target</th>
                <th>Status</th>
                <th>Triage</th>
              </tr>
            </thead>
            <tbody id="alerts-body">
              <tr><td colspan="8" style="text-align: center; color: var(--text-muted);">Loading live alerts...</td></tr>
            </tbody>
          </table>
        </div>
      </div>

      <div class="card">
        <h2 style="font-size: 16px; font-weight: 700; margin-bottom: 16px;">Real-Time Tree SHAP Attributions</h2>
        <div id="explanation-container">
          <div style="color: var(--text-muted); font-size: 12px;">Awaiting alert explanations...</div>
        </div>
        <div id="shap-container" style="margin-top: 14px;">
          <div style="color: var(--text-muted); font-size: 13px;">Computing live explainability attributions...</div>
        </div>
      </div>
    </div>

    <!-- Model Comparison Matrix -->
    <div class="card">
      <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 16px; flex-wrap: wrap; gap: 10px;">
        <div>
          <h2 style="font-size: 16px; font-weight: 700;">Registered Models Benchmark & Dynamic Switcher</h2>
          <div style="font-size: 12px; color: var(--text-muted); margin-top: 2px;">Real-time inference hot-switching across registered benchmark models</div>
        </div>
        <div style="display: flex; gap: 8px; font-size: 11px; font-family: 'JetBrains Mono', monospace; flex-wrap: wrap;">
          <span style="padding: 4px 10px; border-radius: 6px; background: rgba(0, 240, 255, 0.12); border: 1px solid var(--accent-cyan); color: var(--accent-cyan); font-weight: 700;">● CICIDS2017 (Active — 7 Models)</span>
          <span style="padding: 4px 10px; border-radius: 6px; background: rgba(255, 255, 255, 0.03); border: 1px solid var(--card-border); color: var(--text-muted);" title="Dataset ingestion planned in future expansion phase">○ NSL-KDD (Not yet implemented)</span>
          <span style="padding: 4px 10px; border-radius: 6px; background: rgba(255, 255, 255, 0.03); border: 1px solid var(--card-border); color: var(--text-muted);" title="Dataset ingestion planned in future expansion phase">○ UNSW-NB15 (Not yet implemented)</span>
        </div>
      </div>
      <div class="models-grid" id="models-container">
        <!-- Rendered via JS -->
      </div>
    </div>
  </main>

  <!-- Reset Confirmation Modal -->
  <div id="reset-modal" class="modal-backdrop" style="display: none;" onclick="handleModalBackdropClick(event)">
    <div class="modal-dialog">
      <div class="modal-header">
        <div style="display: flex; align-items: center; gap: 10px;">
          <div style="width: 32px; height: 32px; border-radius: 8px; background: rgba(239,68,68,0.15); border: 1px solid rgba(239,68,68,0.4); display: flex; align-items: center; justify-content: center; color: #ef4444; font-size: 16px;">⚠️</div>
          <h3 style="font-size: 16px; font-weight: 800; color: #fff;">Reset SOC Telemetry & Database</h3>
        </div>
        <button class="modal-close-btn" onclick="closeResetModal()">✕</button>
      </div>
      <div class="modal-body">
        <p>This action will permanently purge:</p>
        <ul style="margin: 8px 0 8px 20px; color: var(--text); font-size: 12px; font-family: 'JetBrains Mono', monospace; line-height: 1.8;">
          <li>All stored network flows and classifications</li>
          <li>All security incidents and alerts</li>
          <li>Live packet and flow telemetry counters</li>
          <li>Active alert deduplication caches</li>
        </ul>
        <p style="font-size: 12px; color: var(--text-muted); margin-top: 8px;">Active ML models and registered benchmark configurations will remain intact.</p>
      </div>
      <div class="modal-footer">
        <button class="btn btn-modal-cancel" onclick="closeResetModal()">Cancel</button>
        <button class="btn btn-modal-confirm" id="btn-confirm-reset-action" onclick="executeReset()">
          <span>Confirm & Purge Telemetry</span>
        </button>
      </div>
    </div>
  </div>

  <!-- False Positive Correction Modal -->
  <div id="fp-modal" class="modal-backdrop" style="display: none;" onclick="if(event.target.id==='fp-modal')closeFPModal()">
    <div class="fp-modal-dialog">
      <div class="modal-header">
        <div style="display: flex; align-items: center; gap: 10px;">
          <div style="width: 32px; height: 32px; border-radius: 8px; background: rgba(234,179,8,0.15); border: 1px solid rgba(234,179,8,0.4); display: flex; align-items: center; justify-content: center; color: #eab308; font-size: 16px;">🏷️</div>
          <h3 style="font-size: 16px; font-weight: 800; color: #fff;">Mark as False Positive</h3>
        </div>
        <button class="modal-close-btn" onclick="closeFPModal()">✕</button>
      </div>
      <div class="modal-body">
        <p style="margin-bottom: 12px;">Alert <strong id="fp-alert-id-display" style="color: var(--accent-cyan);"></strong> will be marked as a false positive. This correction is logged for future model retraining.</p>
        <div class="fp-form-group">
          <label>Original Detection</label>
          <input type="text" id="fp-original-label" readonly style="background: rgba(7,9,14,0.9); border: 1px solid var(--card-border); color: #f87171; padding: 10px 14px; border-radius: 6px; font-size: 13px; width: 100%; font-family: 'JetBrains Mono', monospace;">
        </div>
        <div class="fp-form-group">
          <label>Corrected Classification</label>
          <select id="fp-corrected-label">
            <option value="Benign">Benign (Normal Traffic)</option>
            <option value="Bot">Bot</option>
            <option value="DDoS">DDoS</option>
            <option value="DoS GoldenEye">DoS GoldenEye</option>
            <option value="DoS Hulk">DoS Hulk</option>
            <option value="DoS Slowhttptest">DoS Slowhttptest</option>
            <option value="DoS slowloris">DoS slowloris</option>
            <option value="FTP-Patator">FTP-Patator</option>
            <option value="Heartbleed">Heartbleed</option>
            <option value="Infiltration">Infiltration</option>
            <option value="PortScan">PortScan</option>
            <option value="SSH-Patator">SSH-Patator</option>
            <option value="Web Attack - Brute Force">Web Attack - Brute Force</option>
            <option value="Web Attack - Sql Injection">Web Attack - Sql Injection</option>
            <option value="Web Attack - XSS">Web Attack - XSS</option>
          </select>
        </div>
        <div class="fp-form-group">
          <label>Analyst Notes (Optional)</label>
          <textarea id="fp-notes" placeholder="Reason for marking as false positive..."></textarea>
        </div>
      </div>
      <div class="modal-footer">
        <button class="btn btn-modal-cancel" onclick="closeFPModal()">Cancel</button>
        <button class="btn btn-fp-submit" id="btn-fp-submit" onclick="submitFalsePositive()">Confirm False Positive & Log Feedback</button>
      </div>
    </div>
  </div>

  <!-- Change Network Interface Modal -->
  <div id="network-modal" class="modal-backdrop" style="display: none;" onclick="if(event.target.id==='network-modal')closeNetworkModal()">
    <div class="network-modal-dialog">
      <div class="modal-header">
        <div style="display: flex; align-items: center; gap: 10px;">
          <div style="width: 32px; height: 32px; border-radius: 8px; background: rgba(0,240,255,0.12); border: 1px solid rgba(0,240,255,0.28); display: flex; align-items: center; justify-content: center; color: var(--accent-cyan); font-size: 16px;">🌐</div>
          <h3 style="font-size: 16px; font-weight: 800; color: #fff;">Change Network Interface</h3>
        </div>
        <button class="modal-close-btn" onclick="closeNetworkModal()">✕</button>
      </div>
      <div class="modal-body">
        <div class="network-current-row">
          <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="2" y="2" width="20" height="8" rx="2"/><rect x="2" y="14" width="20" height="8" rx="2"/><line x1="6" y1="6" x2="6.01" y2="6"/><line x1="6" y1="18" x2="6.01" y2="18"/></svg>
          Currently active: <strong id="network-current-active">—</strong>
        </div>
        <div style="display: flex; justify-content: space-between; align-items: center; margin: 14px 0 4px;">
          <span style="font-size: 12px; font-weight: 700; color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.5px;">Available Interfaces</span>
          <button class="btn-detect-networks" id="btn-detect-ifaces" onclick="detectNetworkInterfaces()">
            <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M3 12a9 9 0 1 0 9-9 9.75 9.75 0 0 0-6.74 2.74L3 8"/><path d="M3 3v5h5"/></svg>
            Detect Networks
          </button>
        </div>
        <div class="network-iface-list" id="network-iface-list">
          <div style="color: var(--text-muted); font-size: 12px; text-align: center; padding: 16px;">Detecting interfaces...</div>
        </div>
        <p style="font-size: 11px; color: var(--text-muted); line-height: 1.5; margin-top: 6px;">
          🔒 Selecting a new interface restarts packet capture only. All existing alerts, flows, and model state remain intact — no page reload required.
        </p>
      </div>
      <div class="modal-footer">
        <button class="btn btn-modal-cancel" onclick="closeNetworkModal()">Cancel</button>
        <button class="btn btn-network-apply" id="btn-apply-network" onclick="applyNetworkChange()" disabled>Apply Interface</button>
      </div>
    </div>
  </div>

  <!-- Toast Notification -->
  <div id="toast" class="toast" style="display: none;"></div>

  <script>
    let isCapturing = false;
    let currentFPAlertId = null;
    let selectedNetworkInterface = null; // Holds pending interface selection in the Change Network modal

    function openResetModal() {
      document.getElementById('reset-modal').style.display = 'flex';
    }

    function closeResetModal() {
      document.getElementById('reset-modal').style.display = 'none';
    }

    function handleModalBackdropClick(e) {
      if (e.target.id === 'reset-modal') {
        closeResetModal();
      }
    }

    document.addEventListener('keydown', (e) => {
      if (e.key === 'Escape') {
        closeResetModal();
        closeNetworkModal();
      }
    });

    function showToast(msg, duration = 3000) {
      const toast = document.getElementById('toast');
      toast.innerHTML = `<span>🛡️</span> <span>${msg}</span>`;
      toast.style.display = 'flex';
      setTimeout(() => {
        toast.style.display = 'none';
      }, duration);
    }

    async function executeReset() {
      const btn = document.getElementById('btn-confirm-reset-action');
      const origText = btn.innerHTML;
      btn.disabled = true;
      btn.innerHTML = '<span>Purging Telemetry...</span>';

      try {
        const res = await fetch('/api/reset', { method: 'POST' });
        const data = await res.json();
        if (res.ok) {
          closeResetModal();
          showToast('SOC database & telemetry counters reset to zero.');
          await fetchStats();
          await fetchFlows();
          await fetchAlerts();
          document.getElementById('shap-container').innerHTML = '<div style="color: var(--text-muted); font-size: 13px;">Awaiting network flows to compute live SHAP attributions...</div>';
        } else {
          alert('Failed to reset: ' + (data.detail || data.message || 'Unknown error'));
        }
      } catch (e) {
        console.error('Reset failed', e);
        alert('Reset request encountered an error.');
      } finally {
        btn.disabled = false;
        btn.innerHTML = origText;
      }
    }

    async function checkCapabilities() {
      try {
        const res = await fetch('/api/capture/capabilities');
        const cap = await res.json();
        if (!cap.has_pcap_driver) {
          document.getElementById('driver-warning').style.display = 'flex';
        }
      } catch (e) {
        console.error("Failed to check capabilities", e);
      }
    }

    async function fetchInterfaces(selectId) {
      try {
        const res = await fetch('/api/capture/interfaces');
        const list = await res.json();
        const select = document.getElementById('interface-select');
        select.innerHTML = '';
        list.forEach(i => {
          const opt = document.createElement('option');
          opt.value = i.id;
          opt.innerText = `${i.name} (${i.ip})`;
          if (i.is_default) opt.selected = true;
          select.appendChild(opt);
        });
        // If a specific interface was requested, select it in the dropdown
        if (selectId) {
          select.value = selectId;
          // If exact match not found, try matching by name substring
          if (!select.value || select.value !== selectId) {
            const fallback = Array.from(select.options).find(o =>
              o.value.includes(selectId) || selectId.includes(o.value)
            );
            if (fallback) select.value = fallback.value;
          }
        }
      } catch (e) {
        console.error("Failed to fetch interfaces", e);
      }
    }

    async function startLiveCapture() {
      const iface = document.getElementById('interface-select').value;
      try {
        const res = await fetch('/api/capture/start', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ interface: iface })
        });
        const data = await res.json();
        if (res.ok) {
          updateCaptureUI(true, iface, data.active_ip || null);
          showToast(`Live capture started on ${iface}`);
        } else {
          const errorMsg = data.detail ? (typeof data.detail === 'object' ? JSON.stringify(data.detail) : data.detail) : (data.message || 'Capture initialization failed');
          showToast(`⚠️ Live Capture Notice: ${errorMsg}`, 6000);
          updateCaptureUI(false, null, null);
        }
      } catch (e) {
        console.error("Error starting live capture", e);
        showToast("⚠️ Capture driver unavailable. Falling back to Replay Mode.", 5000);
        updateCaptureUI(false, null, null);
      }
    }

    async function stopLiveCapture() {
      try {
        const res = await fetch('/api/capture/stop', { method: 'POST' });
        if (res.ok) {
          updateCaptureUI(false, null);
          showToast("Live capture stopped. Switched to Replay Mode.");
        }
      } catch (e) {
        console.error("Error stopping live capture", e);
      }
    }

    function updateCaptureUI(active, iface, ip) {
      isCapturing = active;
      const modeBadge = document.getElementById('mode-badge');
      const modeDot = document.getElementById('mode-dot');
      const modeText = document.getElementById('mode-text');
      const btnStart = document.getElementById('btn-start-cap');
      const btnStop = document.getElementById('btn-stop-cap');

      if (active) {
        modeBadge.className = 'mode-indicator live';
        modeDot.className = 'mode-dot red';
        modeText.innerText = `LIVE CAPTURE — ${iface || 'interface'}`;
        btnStart.style.display = 'none';
        btnStop.style.display = 'inline-flex';
        updateActiveNetworkLabel(iface, ip);
      } else {
        modeBadge.className = 'mode-indicator replay';
        modeDot.className = 'mode-dot blue';
        modeText.innerText = 'REPLAY MODE';
        btnStart.style.display = 'inline-flex';
        btnStop.style.display = 'none';
        updateCaptureStatusIndicator(false, null, null);
      }
    }

    function updateActiveNetworkLabel(iface, ip) {
      const el = document.getElementById('active-net-name');
      if (el && iface) el.innerText = iface;
      updateCaptureStatusIndicator(true, iface, ip);
    }

    /**
     * Updates the "Packet Capture: Active — [iface] — [IP]" indicator in the header.
     * active: bool — whether capture is running
     * iface: string|null — interface name
     * ip: string|null — local IPv4 on that interface
     */
    function updateCaptureStatusIndicator(active, iface, ip) {
      const indicator = document.getElementById('capture-status-indicator');
      const textEl = document.getElementById('cap-status-text');
      if (!indicator || !textEl) return;

      if (active && iface) {
        indicator.className = 'capture-status-indicator active';
        const ipPart = (ip && ip !== '0.0.0.0') ? ` — <span class="cap-ip">${ip}</span>` : '';
        textEl.innerHTML = `Packet Capture: Active — <span class="cap-iface">${iface}</span>${ipPart}`;
      } else {
        indicator.className = 'capture-status-indicator inactive';
        textEl.innerHTML = 'Packet Capture: Inactive';
      }
    }

    // ── Change Network Modal ──────────────────────────────────────────────────

    function openNetworkModal() {
      selectedNetworkInterface = null;
      const applyBtn = document.getElementById('btn-apply-network');
      if (applyBtn) applyBtn.disabled = true;
      const curIface = document.getElementById('active-net-name').innerText;
      const curEl = document.getElementById('network-current-active');
      if (curEl) curEl.innerText = (curIface && curIface !== '—') ? curIface : (isCapturing ? 'Active capture' : 'Not capturing');
      document.getElementById('network-modal').style.display = 'flex';
      detectNetworkInterfaces();
    }

    function closeNetworkModal() {
      const modal = document.getElementById('network-modal');
      if (modal) modal.style.display = 'none';
      selectedNetworkInterface = null;
    }

    async function detectNetworkInterfaces() {
      const listEl = document.getElementById('network-iface-list');
      const detectBtn = document.getElementById('btn-detect-ifaces');
      if (!listEl || !detectBtn) return;
      detectBtn.disabled = true;
      detectBtn.innerHTML = `<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M3 12a9 9 0 1 0 9-9 9.75 9.75 0 0 0-6.74 2.74L3 8"/><path d="M3 3v5h5"/></svg> Detecting...`;
      listEl.innerHTML = '<div style="color: var(--text-muted); font-size: 12px; text-align: center; padding: 16px 0;">Scanning network adapters...</div>';
      try {
        const res = await fetch('/api/capture/interfaces');
        const interfaces = await res.json();
        if (!interfaces || interfaces.length === 0) {
          listEl.innerHTML = '<div style="color: var(--text-muted); font-size: 12px; text-align: center; padding: 16px 0;">No network interfaces detected.</div>';
          return;
        }
        const currentActive = document.getElementById('active-net-name').innerText;
        let html = '';
        interfaces.forEach(iface => {
          const ifaceId = iface.id || '';
          const ifaceName = iface.name || ifaceId;
          const ifaceIp = iface.ip || '';
          const ifaceDesc = iface.description || '';
          const isCurrentlyActive = (ifaceId === currentActive || ifaceName === currentActive);
          const safeBtnId = 'iface-btn-' + ifaceId.replace(/[^a-zA-Z0-9]/g, '-');
          html += `
            <button class="iface-option-btn" onclick="selectInterface('${ifaceId}', '${ifaceName.replace(/'/g, "\\'")}'" id="${safeBtnId}">
              <div style="flex: 1; min-width: 0;">
                <div class="iface-name">${ifaceName}</div>
                <div class="iface-ip">${ifaceDesc ? ifaceDesc + ' &nbsp;·&nbsp; ' : ''}${ifaceIp}</div>
              </div>
              ${isCurrentlyActive ? '<span class="iface-active-tag">● ACTIVE</span>' : ''}
            </button>
          `;
        });
        listEl.innerHTML = html;
      } catch (e) {
        listEl.innerHTML = '<div style="color: #f87171; font-size: 12px; text-align: center; padding: 16px 0;">⚠️ Failed to retrieve interfaces. Is the server reachable?</div>';
        console.error('Interface detection failed', e);
      } finally {
        detectBtn.disabled = false;
        detectBtn.innerHTML = `<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M3 12a9 9 0 1 0 9-9 9.75 9.75 0 0 0-6.74 2.74L3 8"/><path d="M3 3v5h5"/></svg> Detect Networks`;
      }
    }

    function selectInterface(id, name) {
      selectedNetworkInterface = { id, name };
      // Highlight selected button, deselect all others
      document.querySelectorAll('.iface-option-btn').forEach(btn => btn.classList.remove('selected'));
      const safeBtnId = 'iface-btn-' + id.replace(/[^a-zA-Z0-9]/g, '-');
      const target = document.getElementById(safeBtnId);
      if (target) target.classList.add('selected');
      const applyBtn = document.getElementById('btn-apply-network');
      if (applyBtn) applyBtn.disabled = false;
    }

    async function applyNetworkChange() {
      if (!selectedNetworkInterface) return;
      const btn = document.getElementById('btn-apply-network');
      const origText = btn ? btn.innerHTML : 'Apply Interface';
      if (btn) { btn.disabled = true; btn.innerHTML = 'Switching...'; }
      try {
        const res = await fetch('/api/capture/switch', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ interface: selectedNetworkInterface.id })
        });
        const data = await res.json();
        if (res.ok) {
          const displayName = selectedNetworkInterface.name || selectedNetworkInterface.id;
          // Save the interface ID before closeNetworkModal() clears selectedNetworkInterface
          const switchedId = selectedNetworkInterface.id;
          // active_ip comes from the backend _resolve_interface() - real hotspot IP
          const activeIp = data.active_ip || null;
          closeNetworkModal();
          updateActiveNetworkLabel(displayName, activeIp);
          updateCaptureUI(true, displayName, activeIp);
          const ipInfo = (activeIp && activeIp !== '0.0.0.0') ? ` (${activeIp})` : '';
          showToast(`Network changed successfully. Packet capture is now using ${displayName}${ipInfo}.`, 5500);
          await fetchStats();
          // Sync the ADAPTER dropdown to the newly active interface
          await fetchInterfaces(switchedId);
        } else {
          const errMsg = data.detail
            ? (typeof data.detail === 'object' ? JSON.stringify(data.detail) : data.detail)
            : (data.message || 'Failed to switch interface.');
          showToast(`Network switch failed: ${errMsg}`, 6000);
          if (btn) { btn.disabled = false; btn.innerHTML = origText; }
        }
      } catch (e) {
        console.error('Network switch request failed', e);
        showToast('Network switch request failed. Check server connectivity.', 5000);
        if (btn) { btn.disabled = false; btn.innerHTML = origText; }
      }
    }

    async function fetchStats() {
      try {
        const res = await fetch('/api/stats');
        const data = await res.json();
        document.getElementById('stat-flows').innerText = data.total_flows;
        document.getElementById('stat-alerts').innerText = data.total_alerts;
        document.getElementById('stat-crit').innerText = data.severity_breakdown.CRITICAL;
        document.getElementById('stat-active').innerText = data.active_model;

        // Update Analyst-Verified Precision card
        const precEl = document.getElementById('stat-precision');
        if (data.analyst_precision === null || data.analyst_precision === undefined) {
          precEl.innerText = '—';
          precEl.style.color = 'var(--text-muted)';
          precEl.style.fontSize = '24px';
          precEl.title = 'No alerts triaged yet';
        } else {
          precEl.innerText = `${data.analyst_precision.toFixed(1)}%`;
          precEl.style.color = '#10b981';
          precEl.style.fontSize = '26px';
          precEl.title = `${data.total_triaged || 0} alert(s) triaged (${data.status_breakdown ? data.status_breakdown.FALSE_POSITIVE : 0} FP)`;
        }

        // Update Capture Stats & Mode Badge
        if (data.capture_status) {
          document.getElementById('cap-pkts').innerText = data.capture_status.packet_count || 0;
          document.getElementById('cap-flows').innerText = data.capture_status.flow_count || 0;
          // Pass active_ip so the header status indicator shows the real IP
          updateCaptureUI(
            data.capture_status.is_capturing,
            data.capture_status.active_interface,
            data.capture_status.active_ip
          );
        }

        // Render Explanation
        if (data.latest_explanation) {
          document.getElementById('explanation-container').innerHTML = `
            <div class="explanation-box">
              <div class="label">🧠 AI Alert Explanation</div>
              <div>${data.latest_explanation}</div>
            </div>
          `;
        }

        // Render SHAP
        if (data.latest_shap && data.latest_shap.length > 0) {
          const maxImp = Math.max(...data.latest_shap.map(s => s.importance), 0.0001);
          let shapHtml = '';
          data.latest_shap.forEach(s => {
            const pct = Math.min(100, Math.round((s.importance / maxImp) * 100));
            shapHtml += `
              <div class="shap-bar-item">
                <div class="shap-bar-label">
                  <span>${s.feature}</span>
                  <span style="color: var(--accent-cyan);">${s.importance.toFixed(4)}</span>
                </div>
                <div class="shap-bar-track">
                  <div class="shap-bar-fill" style="width: ${pct}%;"></div>
                </div>
              </div>
            `;
          });
          document.getElementById('shap-container').innerHTML = shapHtml;
        }
      } catch (e) {
        console.error("Failed to fetch stats", e);
      }
    }

    async function fetchFlows() {
      try {
        const res = await fetch('/api/flows?limit=30');
        if (!res.ok) return;
        const flows = await res.json();
        const tbody = document.getElementById('flows-body');
        if (!flows || flows.length === 0) {
          tbody.innerHTML = '<tr><td colspan="8" style="text-align: center; color: var(--text-muted);">No network flows captured yet. Start capture to inspect real-time traffic.</td></tr>';
          return;
        }
        let html = '';
        const protoMap = { 6: 'TCP', 17: 'UDP', 1: 'ICMP', 2: 'IGMP' };
        flows.forEach(f => {
          const isBenign = (!f.predicted_label || f.predicted_label.toLowerCase() === 'benign');
          const badgeClass = isBenign ? 'BENIGN' : 'ATTACK';
          const protoName = protoMap[f.protocol] || `Proto ${f.protocol}`;
          const timeStr = f.timestamp ? f.timestamp.split('T')[1].split('.')[0] : '--:--:--';
          let methodBadge = '';
          if (f.detection_method === 'SYN_BURST_HEURISTIC') {
            methodBadge = `<div style="font-size: 10px; color: var(--accent-cyan); margin-top: 2px;">⚡ SYN Heuristic</div>`;
          } else if (f.detection_method === 'ML_HYBRID') {
            methodBadge = `<div style="font-size: 10px; color: #a78bfa; margin-top: 2px;">⚡ ML + Heuristic</div>`;
          }
          html += `
            <tr>
              <td>#${f.id}</td>
              <td style="color: var(--text-muted);">${timeStr}</td>
              <td><span class="badge proto">${protoName}</span></td>
              <td>${f.src_ip}:${f.src_port}</td>
              <td>${f.dst_ip}:${f.dst_port}</td>
              <td>
                <span class="badge ${badgeClass}">${f.predicted_label}</span>
                ${methodBadge}
              </td>
              <td>
                <div style="font-weight: 600;">${(f.confidence * 100).toFixed(1)}%</div>
                ${f.ml_predicted_label && f.ml_predicted_label !== f.predicted_label ? `<div style="font-size: 10px; color: var(--text-muted);">ML: ${f.ml_predicted_label} (${(f.ml_confidence * 100).toFixed(1)}%)</div>` : ''}
              </td>
              <td style="color: var(--text-muted); font-size: 11px;">${f.model_name || 'weighted_voting_ensemble'}</td>
            </tr>
          `;
        });
        tbody.innerHTML = html;
      } catch (e) {
        console.error("Failed to fetch flows", e);
      }
    }

    async function fetchAlerts() {
      try {
        const res = await fetch('/api/alerts?limit=25');
        const alerts = await res.json();
        const tbody = document.getElementById('alerts-body');
        if (alerts.length === 0) {
          tbody.innerHTML = '<tr><td colspan="8" style="text-align: center; color: var(--text-muted);">No alerts recorded. Network clean.</td></tr>';
          return;
        }
        let html = '';
        const statusLabels = { NEW: 'NEW', ACKNOWLEDGED: 'ACK', FALSE_POSITIVE: 'FP', ESCALATED: 'ESC', RESOLVED: 'RES' };
        alerts.forEach(a => {
          const st = a.status || 'NEW';
          const rowClass = st === 'RESOLVED' ? 'alert-resolved' : st === 'FALSE_POSITIVE' ? 'alert-fp' : '';
          const isTerminal = (st === 'RESOLVED' || st === 'FALSE_POSITIVE');
          let triageHtml = '';
          if (isTerminal) {
            triageHtml = `<span style="font-size: 11px; color: var(--text-muted); font-family: 'JetBrains Mono', monospace;">—</span>`;
          } else {
            triageHtml = `<div class="triage-actions">`;
            if (st !== 'ACKNOWLEDGED') triageHtml += `<button class="triage-btn ack" onclick="triageAlert('${a.alert_id}','ACKNOWLEDGED')" title="Acknowledge">ACK</button>`;
            triageHtml += `<button class="triage-btn fp" onclick="openFPModal('${a.alert_id}','${a.attack_type}')" title="False Positive">FP</button>`;
            if (st !== 'ESCALATED') triageHtml += `<button class="triage-btn esc" onclick="triageAlert('${a.alert_id}','ESCALATED')" title="Escalate">ESC</button>`;
            triageHtml += `<button class="triage-btn res" onclick="triageAlert('${a.alert_id}','RESOLVED')" title="Resolve">RES</button>`;
            triageHtml += `</div>`;
          }
          let methodTag = '';
          if (a.detection_method === 'SYN_BURST_HEURISTIC') {
            methodTag = `<span style="font-size: 10px; padding: 2px 6px; border-radius: 4px; background: rgba(0, 240, 255, 0.15); color: var(--accent-cyan); margin-left: 6px;">SYN Heuristic</span>`;
          } else if (a.detection_method === 'ML_HYBRID') {
            methodTag = `<span style="font-size: 10px; padding: 2px 6px; border-radius: 4px; background: rgba(167, 139, 250, 0.15); color: #a78bfa; margin-left: 6px;">ML + Heuristic</span>`;
          }
          html += `
            <tr class="${rowClass}">
              <td>${a.alert_id}</td>
              <td><span class="badge ${a.severity}">${a.severity}</span></td>
              <td>
                <div style="display: flex; align-items: center; gap: 6px;">
                  <span style="font-weight: 700; color: #fff;">${a.attack_type}</span>
                  ${methodTag}
                </div>
                ${a.explanation ? `<div class="explanation-inline">${a.explanation}</div>` : ''}
              </td>
              <td>
                <div style="font-weight: 700; color: var(--accent-cyan);">${(a.confidence * 100).toFixed(1)}%</div>
                ${a.ml_predicted_label && a.ml_predicted_label !== a.attack_type ? `<div style="font-size: 10px; color: var(--text-muted);">ML: ${a.ml_predicted_label} (${((a.ml_confidence || 0) * 100).toFixed(1)}%)</div>` : ''}
              </td>
              <td>${a.src_ip}</td>
              <td>${a.dst_ip}:${a.dst_port}</td>
              <td><span class="badge ${st}">${statusLabels[st] || st}</span></td>
              <td>${triageHtml}</td>
            </tr>
          `;
        });
        tbody.innerHTML = html;
      } catch (e) {
        console.error("Failed to fetch alerts", e);
      }
    }

    async function triageAlert(alertId, newStatus) {
      try {
        const res = await fetch(`/api/alerts/${alertId}/status`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ status: newStatus })
        });
        if (res.ok) {
          showToast(`Alert ${alertId} → ${newStatus}`);
          fetchAlerts();
          fetchStats();
        }
      } catch (e) {
        console.error('Triage failed', e);
      }
    }

    function openFPModal(alertId, attackType) {
      currentFPAlertId = alertId;
      document.getElementById('fp-alert-id-display').innerText = alertId;
      document.getElementById('fp-original-label').value = attackType;
      document.getElementById('fp-corrected-label').value = 'Benign';
      document.getElementById('fp-notes').value = '';
      document.getElementById('fp-modal').style.display = 'flex';
    }

    function closeFPModal() {
      document.getElementById('fp-modal').style.display = 'none';
      currentFPAlertId = null;
    }

    async function submitFalsePositive() {
      if (!currentFPAlertId) return;
      const btn = document.getElementById('btn-fp-submit');
      btn.disabled = true;
      btn.innerText = 'Logging Feedback...';
      try {
        const res = await fetch(`/api/alerts/${currentFPAlertId}/status`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            status: 'FALSE_POSITIVE',
            corrected_label: document.getElementById('fp-corrected-label').value,
            notes: document.getElementById('fp-notes').value
          })
        });
        if (res.ok) {
          const data = await res.json();
          closeFPModal();
          showToast(`Alert ${currentFPAlertId} → FALSE POSITIVE (feedback logged: ${data.feedback_logged})`);
          fetchAlerts();
          fetchStats();
        }
      } catch (e) {
        console.error('FP submission failed', e);
      } finally {
        btn.disabled = false;
        btn.innerText = 'Confirm False Positive & Log Feedback';
      }
    }

    async function fetchModels() {
      try {
        const res = await fetch('/api/models');
        const data = await res.json();
        const container = document.getElementById('models-container');
        let html = '';
        data.models.forEach(m => {
          const mClean = m.model_id.replace('_cicids2017', '');
          const isActive = (mClean === data.active_model || m.model_id === data.active_model || (data.active_model === 'weighted_voting_ensemble' && (m.model_id === 'weighted_voting_ensemble_cicids2017' || mClean === 'weighted_voting_ensemble')));
          html += `
            <div class="model-card ${isActive ? 'active' : ''}">
              <div>
                <div class="model-header">
                  <span class="model-name">${m.name}</span>
                  <span style="font-size: 11px; padding: 2px 6px; border-radius: 4px; background: rgba(255,255,255,0.1);">${m.framework}</span>
                </div>
                <div class="model-metrics">
                  <div class="metric-row">Accuracy: <span>${(m.metrics.accuracy * 100).toFixed(2)}%</span></div>
                  <div class="metric-row">F1 Score: <span>${(m.metrics.f1_score * 100).toFixed(2)}%</span></div>
                  <div class="metric-row">Precision: <span>${(m.metrics.precision * 100).toFixed(2)}%</span></div>
                  <div class="metric-row">Recall: <span>${(m.metrics.recall * 100).toFixed(2)}%</span></div>
                </div>
              </div>
              <button class="switch-btn ${isActive ? 'current' : ''}" onclick="switchModel('${m.model_id}')">
                ${isActive ? 'ACTIVE MODEL' : 'ACTIVATE MODEL'}
              </button>
            </div>
          `;
        });
        container.innerHTML = html;
      } catch (e) {
        console.error("Failed to fetch models", e);
      }
    }

    async function switchModel(modelId) {
      await fetch('/api/models/switch_active', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ model_id: modelId })
      });
      fetchStats();
      fetchModels();
    }

    // Initialize
    checkCapabilities();
    fetchInterfaces();
    fetchStats();
    fetchFlows();
    fetchAlerts();
    fetchModels();
    setInterval(fetchStats, 1500);
    setInterval(fetchFlows, 1500);
    setInterval(fetchAlerts, 2000);
  </script>
</body>
</html>
"""
