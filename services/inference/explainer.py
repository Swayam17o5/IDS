import shap
import numpy as np
import pandas as pd
from typing import List, Dict, Any, Optional

class SHAPExplainer:
    def __init__(self, model, feature_names: List[str]):
        self.model = model
        self.feature_names = feature_names
        try:
            self.explainer = shap.TreeExplainer(model)
        except Exception as e:
            self.explainer = None

    def explain_instance(self, df_row: pd.DataFrame, top_k: int = 5) -> List[Dict[str, Any]]:
        if self.explainer is None:
            return []
        try:
            shap_values = self.explainer.shap_values(df_row)
            # For multiclass, shap_values is a list of arrays (one per class) or (1, features, classes)
            if isinstance(shap_values, list):
                # Aggregate absolute impact across classes or for predicted class
                impacts = np.mean([np.abs(sv[0]) for sv in shap_values], axis=0)
            elif len(shap_values.shape) == 3:
                impacts = np.mean(np.abs(shap_values[0]), axis=1)
            else:
                impacts = np.abs(shap_values[0])
            
            top_indices = np.argsort(impacts)[::-1][:top_k]
            explanations = []
            for idx in top_indices:
                feat = self.feature_names[idx]
                val = float(df_row.iloc[0, idx])
                imp = float(impacts[idx])
                explanations.append({
                    "feature": feat,
                    "value": val,
                    "importance": imp
                })
            return explanations
        except Exception as e:
            return []
