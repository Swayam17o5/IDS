import json
import numpy as np
import pandas as pd
from sklearn.base import BaseEstimator, ClassifierMixin

class IDSStackingEnsemble(BaseEstimator, ClassifierMixin):
    """
    Stacking / Blending Ensemble for Network Intrusion Detection.
    Combines calibrated probability outputs from XGBoost, LightGBM, and HistGradientBoosting.
    """
    def __init__(self, xgb_model=None, lgb_model=None, hgb_model=None, weights=None):
        self.xgb_model = xgb_model
        self.lgb_model = lgb_model
        self.hgb_model = hgb_model
        self.weights = weights or [0.45, 0.35, 0.20]
        self.classes_ = np.arange(15)

    def predict_proba(self, X):
        # Handle DataFrame vs numpy array
        if isinstance(X, pd.DataFrame):
            df_xgb = X
            # LightGBM requires columns with underscores if trained with them
            df_lgb = X.copy()
            df_lgb.columns = [c.replace(" ", "_").replace("-", "_") for c in df_lgb.columns]
            arr = X.values
        else:
            arr = np.asarray(X, dtype=np.float32)
            with open("models/cicids2017/feature_list.json") as f:
                cols = json.load(f)
            df_xgb = pd.DataFrame(arr, columns=cols)
            df_lgb = pd.DataFrame(arr, columns=[c.replace(" ", "_").replace("-", "_") for c in cols])

        p_xgb = self.xgb_model.predict_proba(df_xgb) if self.xgb_model else np.zeros((len(X), 15))
        p_lgb = self.lgb_model.predict_proba(df_lgb) if self.lgb_model else np.zeros((len(X), 15))
        p_hgb = self.hgb_model.predict_proba(arr) if self.hgb_model else np.zeros((len(X), 15))

        w = np.array(self.weights) / np.sum(self.weights)
        blended = w[0] * p_xgb + w[1] * p_lgb + w[2] * p_hgb
        return blended

    def predict(self, X):
        proba = self.predict_proba(X)
        return np.argmax(proba, axis=1)
