import json
import numpy as np
import pandas as pd
from sklearn.base import BaseEstimator, ClassifierMixin

class IDSStackingEnsemble(BaseEstimator, ClassifierMixin):
    """
    Stacking / Blending Ensemble for Network Intrusion Detection.
    Combines calibrated probability outputs from XGBoost, LightGBM, and HistGradientBoosting.
    
    Note: XGBoost expects space-based feature names (matching CICIDS2017 training schema),
    while LightGBM was trained with underscore-based names. This class handles both.
    """
    def __init__(self, xgb_model=None, lgb_model=None, hgb_model=None, weights=None):
        self.xgb_model = xgb_model
        self.lgb_model = lgb_model
        self.hgb_model = hgb_model
        self.weights = weights or [0.45, 0.35, 0.20]
        self.classes_ = np.arange(15)

    def predict_proba(self, X):
        # X should arrive with space-based feature names (original CICIDS2017 schema)
        # matching the columns XGBoost was trained on.
        if isinstance(X, pd.DataFrame):
            df_xgb = X  # Use as-is for XGBoost (expects space-based names)
            arr = X.values
            
            # Create underscore-based version for LightGBM
            normalized_cols = [c.replace(" ", "_").replace("-", "_") for c in X.columns]
            df_lgb = pd.DataFrame(arr, columns=normalized_cols)
        else:
            # Fallback for raw numpy array (shouldn't happen in normal flow)
            arr = np.asarray(X, dtype=np.float32)
            with open("models/cicids2017/feature_list.json") as f:
                cols = json.load(f)
            # XGBoost uses space-based names
            df_xgb = pd.DataFrame(arr, columns=cols)
            # LightGBM uses underscore-based names
            normalized_cols = [c.replace(" ", "_").replace("-", "_") for c in cols]
            df_lgb = pd.DataFrame(arr, columns=normalized_cols)

        p_xgb = self.xgb_model.predict_proba(df_xgb) if self.xgb_model else np.zeros((len(X), 15))
        p_lgb = self.lgb_model.predict_proba(df_lgb) if self.lgb_model else np.zeros((len(X), 15))
        p_hgb = self.hgb_model.predict_proba(arr) if self.hgb_model else np.zeros((len(X), 15))

        w = np.array(self.weights) / np.sum(self.weights)
        blended = w[0] * p_xgb + w[1] * p_lgb + w[2] * p_hgb
        return blended

    def predict(self, X):
        proba = self.predict_proba(X)
        return np.argmax(proba, axis=1)
