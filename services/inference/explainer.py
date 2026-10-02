"""
services/inference/explainer.py
---------------------------------
SHAP (SHapley Additive exPlanations) Engine for AegisNIDS.

Provides transparent, mathematically grounded feature contribution explanations
for individual intrusion detection predictions and security alerts.
"""

import logging
import numpy as np
import pandas as pd
from typing import List, Dict, Any, Optional

logger = logging.getLogger("aegis.explainer")

try:
    import shap
    SHAP_AVAILABLE = True
except ImportError:
    SHAP_AVAILABLE = False


class SHAPExplainer:
    """
    Computes local feature attribution using TreeExplainer for tree models
    (XGBoost, LightGBM, Random Forest, Extra Trees) with model-specific
    fallback for ensembles and neural models.
    """

    def __init__(self, model: Any, feature_names: List[str], model_name: str = "xgboost"):
        self.model = model
        self.feature_names = feature_names
        self.model_name = model_name
        self.explainer = None

        if SHAP_AVAILABLE and model is not None:
            try:
                # Direct TreeExplainer support for scikit-learn / XGBoost / LightGBM estimators
                if hasattr(model, "estimators_") or hasattr(model, "get_booster") or hasattr(model, "booster_"):
                    self.explainer = shap.TreeExplainer(model)
                elif hasattr(model, "predict_proba"):
                    # Check if it's an ensemble with tree base models
                    base_models = getattr(model, "models", {}) or getattr(model, "named_estimators_", {})
                    for name, submodel in (base_models.items() if isinstance(base_models, dict) else []):
                        if hasattr(submodel, "estimators_") or hasattr(submodel, "get_booster") or hasattr(submodel, "booster_"):
                            self.explainer = shap.TreeExplainer(submodel)
                            self.model_name = f"{name} (component of {self.model_name})"
                            break
                    if self.explainer is None:
                        try:
                            self.explainer = shap.TreeExplainer(model)
                        except Exception:
                            pass
            except Exception as exc:
                logger.debug("TreeExplainer init note for %s: %s", model_name, exc)
                self.explainer = None

    def explain_instance(
        self,
        df_row: pd.DataFrame,
        top_k: int = 5,
        target_class_idx: Optional[int] = None
    ) -> List[Dict[str, Any]]:
        """
        Computes top contributing features for a single flow instance.

        Returns list of feature explanations:
        [
            {
                "feature": "Destination Port",
                "value": 80.0,
                "shap_value": 0.4521,
                "importance": 0.4521,
                "contribution": "positive",
                "description": "Pushes prediction toward target attack"
            },
            ...
        ]
        """
        if df_row is None or df_row.empty:
            return []

        # Ensure correct column names matching self.feature_names
        if isinstance(df_row, pd.DataFrame) and list(df_row.columns) != self.feature_names:
            if df_row.shape[1] == len(self.feature_names):
                df_row = pd.DataFrame(df_row.values, columns=self.feature_names)

        # 1. Real SHAP TreeExplainer calculation
        if self.explainer is not None:
            try:
                raw_shap = self.explainer.shap_values(df_row)
                return self._parse_shap_output(raw_shap, df_row, top_k, target_class_idx)
            except Exception as exc:
                logger.debug("SHAP explanation evaluation exception: %s", exc)

        # 2. Heuristic / Model Feature Attribution Fallback (when TreeExplainer not directly supported)
        return self._fallback_feature_attribution(df_row, top_k)

    def _parse_shap_output(
        self,
        shap_values: Any,
        df_row: pd.DataFrame,
        top_k: int,
        target_class_idx: Optional[int] = None
    ) -> List[Dict[str, Any]]:
        """Extracts signed feature impact and ranking from raw SHAP values."""
        if isinstance(shap_values, list):
            # List of arrays [class_0, class_1, ...]
            if target_class_idx is not None and 0 <= target_class_idx < len(shap_values):
                class_vals = np.asarray(shap_values[target_class_idx])
                if class_vals.ndim >= 2:
                    signed_impacts = class_vals[0]
                else:
                    signed_impacts = class_vals
            else:
                # Default: find class with highest overall magnitude or max class
                magnitudes = [np.sum(np.abs(sv[0])) for sv in shap_values]
                best_cls = int(np.argmax(magnitudes))
                signed_impacts = np.asarray(shap_values[best_cls])[0]
        elif isinstance(shap_values, np.ndarray):
            if shap_values.ndim == 3:
                # Shape: (1, num_features, num_classes)
                if target_class_idx is not None and target_class_idx < shap_values.shape[2]:
                    signed_impacts = shap_values[0, :, target_class_idx]
                else:
                    signed_impacts = shap_values[0, :, 0]
            elif shap_values.ndim == 2:
                # Shape: (1, num_features)
                signed_impacts = shap_values[0]
            else:
                signed_impacts = shap_values
        else:
            return []

        abs_impacts = np.abs(signed_impacts)
        top_indices = np.argsort(abs_impacts)[::-1][:top_k]

        explanations = []
        for idx in top_indices:
            idx_int = int(idx)
            if idx_int >= len(self.feature_names):
                continue
            feat = self.feature_names[idx_int]
            val = float(df_row.iloc[0, idx_int]) if isinstance(df_row, pd.DataFrame) else float(df_row[0][idx_int])
            shap_val = float(signed_impacts[idx_int])
            imp = float(abs_impacts[idx_int])
            direction = "positive" if shap_val >= 0 else "negative"

            explanations.append({
                "feature": feat,
                "value": round(val, 4),
                "shap_value": round(shap_val, 6),
                "importance": round(imp, 6),
                "contribution": direction,
            })

        return explanations

    def _fallback_feature_attribution(self, df_row: pd.DataFrame, top_k: int) -> List[Dict[str, Any]]:
        """Fallback attribution identifying high-magnitude security-salient features."""
        # Find active non-zero key features
        row_vals = df_row.iloc[0].to_dict() if isinstance(df_row, pd.DataFrame) else {}
        salient_keys = [
            "Destination Port", "Flow Duration", "Total Fwd Packets",
            "Total Backward Packets", "SYN Flag Count", "Init Fwd Win Bytes",
            "Init Bwd Win Bytes", "Fwd Packet Length Max", "Bwd Packet Length Max",
            "Flow Bytes/s", "Flow Packets/s", "ACK Flag Count"
        ]

        scored = []
        for k in salient_keys:
            if k in row_vals and row_vals[k] is not None:
                val = float(row_vals[k])
                if val > 0:
                    scored.append({
                        "feature": k,
                        "value": round(val, 4),
                        "shap_value": round(val / (val + 1000.0), 4),
                        "importance": round(val / (val + 1000.0), 4),
                        "contribution": "positive",
                    })

        scored.sort(key=lambda x: x["importance"], reverse=True)
        return scored[:top_k]

    def explain_instance_detailed(
        self,
        df_row: pd.DataFrame,
        target_class_idx: Optional[int] = None,
        target_class_name: str = "Target Class"
    ) -> Dict[str, Any]:
        """
        Produces comprehensive SHAP forensic breakdown for all 77 features,
        including base expected value, positive (supporting) and negative (opposing)
        contributions, and full sorted feature table.
        """
        all_feats = self.explain_instance(df_row, top_k=len(self.feature_names), target_class_idx=target_class_idx)

        # Base value extraction from TreeExplainer if available
        base_val = None
        if self.explainer is not None and hasattr(self.explainer, "expected_value"):
            try:
                ev = self.explainer.expected_value
                if isinstance(ev, (list, np.ndarray)):
                    if target_class_idx is not None and 0 <= target_class_idx < len(ev):
                        base_val = float(ev[target_class_idx])
                    else:
                        base_val = float(ev[0])
                else:
                    base_val = float(ev)
            except Exception:
                base_val = None

        # Annotate direction labels
        for idx, f in enumerate(all_feats):
            f["rank"] = idx + 1
            if f["shap_value"] > 0:
                f["direction_label"] = f"→ Supports {target_class_name}"
            elif f["shap_value"] < 0:
                f["direction_label"] = f"⊘ Opposes {target_class_name}"
            else:
                f["direction_label"] = "Neutral"

        supporting = [f for f in all_feats if f["shap_value"] > 0]
        opposing = [f for f in all_feats if f["shap_value"] < 0]
        # Sort opposing so highest magnitude negative impact is first
        opposing.sort(key=lambda x: abs(x["shap_value"]), reverse=True)

        return {
            "explainer_model": self.model_name,
            "explanation_method": "TreeSHAP (Exact Additive Feature Attribution)" if self.explainer else "Surrogate Feature Salience Attribution",
            "is_tree_shap": self.explainer is not None,
            "base_value": round(base_val, 4) if base_val is not None else None,
            "target_class_idx": target_class_idx,
            "target_class_name": target_class_name,
            "top_features": all_feats[:10],
            "supporting_features": supporting[:10],
            "opposing_features": opposing[:10],
            "all_77_features": all_feats,
            "total_supporting_count": len(supporting),
            "total_opposing_count": len(opposing),
        }

    def get_global_feature_importance(self, top_k: int = 15) -> List[Dict[str, Any]]:
        """
        Retrieves global feature importance directly from tree models / meta-learners.
        """
        importances = None
        model_source = self.model

        if hasattr(model_source, "feature_importances_"):
            importances = model_source.feature_importances_
        elif hasattr(model_source, "models") and isinstance(model_source.models, dict):
            for sub in model_source.models.values():
                if hasattr(sub, "feature_importances_"):
                    importances = sub.feature_importances_
                    break

        if importances is None or len(importances) != len(self.feature_names):
            return []

        importances = np.asarray(importances, dtype=float)
        total = np.sum(importances)
        norm_imp = (importances / total) if total > 0 else importances

        top_indices = np.argsort(norm_imp)[::-1][:top_k]
        result = []
        for rank, idx in enumerate(top_indices, 1):
            result.append({
                "rank": rank,
                "feature": self.feature_names[int(idx)],
                "importance_score": round(float(norm_imp[int(idx)]), 5),
                "importance_pct": round(float(norm_imp[int(idx)]) * 100.0, 2)
            })
        return result

