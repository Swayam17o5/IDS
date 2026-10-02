# SHAP Model Explainability & Dedicated Forensic Analysis Architecture

## 1. Overview
In mission-critical intrusion detection systems, machine learning models cannot operate as opaque black boxes. AegisNIDS integrates **TreeSHAP (SHapley Additive exPlanations)** directly into the inference and alert analysis pipelines, calculating exact mathematical feature importance for every detected threat, separating machine learning signals from behavioral heuristics, and providing a dedicated deep forensic explainability workspace.

---

## 2. Dedicated AI Explainability Page (`/explainability/{alert_id}`)

Every alert in the AegisNIDS SOC dashboard features a `🔍 Deep Explain` button linking directly to a dedicated full-page forensic analysis interface:
`GET /explainability/{alert_id}`

### Key Features of the Explainability Page:
1. **Alert Identification & Telemetry:** Displays Alert ID, Final Decision, Severity, Detection Method, Detection Confidence, Source IP, Destination IP, Destination Port, Timestamp, and Correlated Flow Count.
2. **Dual-Signal Separation Grid:** Visually and conceptually distinguishes:
   - **Final AegisNIDS Decision:** The composite verdict (e.g. `PORTSCAN` with `85.4%` confidence).
   - **ML Model Prediction:** The single-flow ML classification (e.g. `BENIGN` with `99.6%` confidence).
   - **Behavioral Detection:** The multi-flow heuristic verdict (e.g. `PORTSCAN` across 8 probed ports).
3. **Architectural Separation Notice & Flow Pipeline:** Clarifies that SHAP explains the ML model prediction, while the behavioral SYN-burst heuristic explains multi-port reconnaissance patterns.
4. **15-Class Probability Distribution:** Shows real model output probabilities across all classes.
5. **Signed SHAP Feature Contributions:**
   - **Features Supporting ML Prediction (+):** Positive additive shifts pushing the model toward the prediction.
   - **Features Opposing ML Prediction (-):** Negative additive shifts pushing the model away from the prediction.
   - **Horizontal SHAP Contribution Chart:** Visual bars with feature values, signed values, and direction labels.
   - **TreeSHAP Base Value $E[X]$:** Expected value baseline for the active TreeExplainer.
6. **Behavioral Heuristic Evidence Panel:** Distinct destination ports scanned, probing pattern, payload activity, and heuristic confidence.
7. **Forensic Verdict Synthesis & Plain-English Rationale:** Dynamic synthesis answering *"Why Did the ML Model Make This Prediction?"* and *"Why Was This Alert Generated?"*.
8. **Canonical 77-Feature Inspector:** Searchable and sortable table of all 77 CICIDS2017 features used for inference, sortable by SHAP Impact, Feature Name, or Feature Value with Show All / Collapse toggle.
9. **Global Model Explainability:** Dataset-level feature importances across all trees in the active model.
10. **Export Capabilities:** Download Complete JSON report and Print Report.

---

## 3. Deep Explanation API Specification

### Endpoint:
`GET /api/alerts/{alert_id}/deep-explanation`

### Response Schema:
```json
{
  "alert": {
    "alert_id": "ALT-1790961006373",
    "attack_type": "PortScan",
    "severity": "MEDIUM",
    "confidence": 0.95,
    "detection_method": "SYN_BURST_HEURISTIC",
    "detection_confidence": 0.95,
    "src_ip": "192.168.1.40",
    "dst_ip": "192.168.1.1",
    "src_port": 54321,
    "dst_port": 80,
    "model_used": "weighted_voting_ensemble",
    "status": "NEW",
    "flow_count": 1,
    "timestamp": "2026-10-02T16:58:44.319807+00:00",
    "explanation": "SYN-Burst heuristic triggered PortScan alert."
  },
  "ml_verdict": {
    "predicted_label": "Benign",
    "confidence": 0.9958,
    "model_name": "weighted_voting_ensemble",
    "class_probabilities": {
      "Benign": 0.9958,
      "PortScan": 0.0039,
      "DoS Hulk": 0.0001
    }
  },
  "heuristic_verdict": {
    "attack_type": "PortScan",
    "distinct_ports_scanned": 8,
    "sequential_probing": true,
    "payload_activity": "Header-Only Probing (0 B Payload)",
    "heuristic_confidence": 0.95
  },
  "comparison": {
    "ml_vs_heuristic_agreement": false,
    "why_alert_generated": "The ML model classified this single network flow instance as BENIGN with 99.6% confidence because single-flow TCP features resemble standard connection initialization. However, the behavioral SYN-Burst Heuristic Detector identified a rapid multi-port reconnaissance sweep probing 8 distinct ports across the network. Because multi-port scanning is a behavioral pattern distributed across separate flows, the behavioral heuristic signal triggered the final AegisNIDS PORTSCAN alert."
  },
  "shap": {
    "explainer_model": "xgboost (component of weighted_voting_ensemble)",
    "explanation_method": "TreeSHAP (Exact Additive Feature Attribution)",
    "is_tree_shap": true,
    "base_value": 6.782,
    "target_class_idx": 0,
    "target_class_name": "Benign",
    "top_features": [
      {
        "rank": 1,
        "feature": "Init Bwd Win Bytes",
        "value": 0.0,
        "shap_value": 0.54145,
        "importance": 0.54145,
        "contribution": "positive",
        "direction_label": "→ Supports Benign"
      }
    ],
    "supporting_features": [...],
    "opposing_features": [...],
    "all_77_features": [...],
    "total_supporting_count": 10,
    "total_opposing_count": 10
  },
  "global_shap": [
    {
      "rank": 1,
      "feature": "SYN Flag Count",
      "importance_score": 0.09001,
      "importance_pct": 9.0
    }
  ]
}
```

---

## 4. Dual-Signal Rationale Synthesis
AegisNIDS maintains an explicit separation between:
1. **Single-Flow ML Inference:** Evaluates statistical distribution across 77 features extracted from a single flow instance. TreeSHAP explains why the model evaluated those 77 features.
2. **Behavioral SYN-Burst Detection:** Evaluates cross-flow temporal patterns (e.g. 1 attacker IP hitting 20+ distinct ports within seconds with 0 payload).

When single-flow ML predicts `Benign` while the behavioral engine detects a multi-port scan, the explainability interface clearly presents both perspectives and explains why the behavioral heuristic signal produced the final alert.
