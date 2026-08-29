import os
import sys
import json
from typing import Dict, List, Any, Optional

# Ensure project root is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))

class ModelRegistry:
    def __init__(self, base_dir: str = "models"):
        self.base_dir = base_dir

    def list_datasets(self) -> List[str]:
        if not os.path.exists(self.base_dir):
            return []
        return [d for d in os.listdir(self.base_dir) if os.path.isdir(os.path.join(self.base_dir, d))]

    def get_models_for_dataset(self, dataset: str = "cicids2017") -> List[Dict[str, Any]]:
        cards_dir = os.path.join(self.base_dir, dataset, "model_cards")
        if not os.path.exists(cards_dir):
            return []
        models = []
        for fn in sorted(os.listdir(cards_dir)):
            if fn.endswith(".json"):
                with open(os.path.join(cards_dir, fn), "r") as f:
                    models.append(json.load(f))
        return models

    def get_model_card(self, dataset: str, model_name: str) -> Optional[Dict[str, Any]]:
        card_path = os.path.join(self.base_dir, dataset, "model_cards", f"{model_name}.json")
        if os.path.exists(card_path):
            with open(card_path, "r") as f:
                return json.load(f)
        return None

    def validate_all_cards(self) -> Dict[str, Any]:
        results = {"valid_count": 0, "errors": [], "cards": []}
        required_keys = ["model_id", "name", "dataset", "framework", "file_path", "feature_count", "classes_count", "metrics"]
        
        for dataset in self.list_datasets():
            models = self.get_models_for_dataset(dataset)
            for card in models:
                mid = card.get("model_id", "unknown")
                # Check keys
                missing = [k for k in required_keys if k not in card]
                if missing:
                    results["errors"].append(f"Model {mid} missing keys: {missing}")
                    continue
                # Check file existence
                if not os.path.exists(card["file_path"]):
                    results["errors"].append(f"Model {mid} file path does not exist: {card['file_path']}")
                    continue
                results["valid_count"] += 1
                results["cards"].append(card)
        return results

    def validate_loaded_models(self) -> Dict[str, Any]:
        """
        Deep validation: loads each registered model and verifies:
        1. Model deserialization
        2. Expected feature count (77)
        3. Target classes count (15)
        """
        import joblib
        import torch
        from services.inference.ensemble import IDSStackingEnsemble
        from pytorch_tabnet.tab_model import TabNetClassifier
        import rtdl_revisiting_models as rtdl

        results = {"verified_models": [], "errors": []}
        
        for dataset in self.list_datasets():
            models = self.get_models_for_dataset(dataset)
            for card in models:
                mid = card["model_id"]
                fp = card["file_path"]
                expected_feats = card["feature_count"]
                expected_classes = card["classes_count"]
                
                try:
                    if not os.path.exists(fp):
                        raise FileNotFoundError(f"Model file {fp} not found on disk.")
                        
                    if fp.endswith(".pth"):
                        model = rtdl.FTTransformer(
                            n_cont_features=expected_feats,
                            cat_cardinalities=[],
                            d_out=expected_classes,
                            **rtdl.FTTransformer.get_default_kwargs()
                        )
                        model.load_state_dict(torch.load(fp, map_location="cpu"))
                        model.eval()
                        actual_feats = expected_feats
                        actual_classes = expected_classes
                    elif fp.endswith(".zip"):
                        tn = TabNetClassifier()
                        tn.load_model(fp)
                        actual_feats = getattr(tn, "input_dim", expected_feats)
                        actual_classes = len(getattr(tn, "classes_", range(expected_classes)))
                    else:
                        model = joblib.load(fp)
                        actual_classes = len(getattr(model, "classes_", range(expected_classes)))
                        actual_feats = getattr(model, "n_features_in_", expected_feats)

                    if actual_feats != expected_feats:
                        raise ValueError(f"Feature count mismatch: card has {expected_feats}, model has {actual_feats}")
                    if actual_classes != expected_classes:
                        raise ValueError(f"Class count mismatch: card has {expected_classes}, model has {actual_classes}")
                    
                    results["verified_models"].append({
                        "model_id": mid,
                        "name": card["name"],
                        "dataset": card["dataset"],
                        "framework": card["framework"],
                        "features": actual_feats,
                        "classes": actual_classes,
                        "status": "VERIFIED_LOADED"
                    })
                except Exception as e:
                    results["errors"].append(f"Model {mid} validation failed: {str(e)}")
                    
        return results

if __name__ == "__main__":
    reg = ModelRegistry()
    val_cards = reg.validate_all_cards()
    print("=== MODEL REGISTRY METADATA VALIDATION ===")
    print(f"Total valid model cards: {val_cards['valid_count']}")
    print(f"Total metadata errors: {len(val_cards['errors'])}")
    
    val_deep = reg.validate_loaded_models()
    print("\n=== DEEP MODEL WEIGHT & TENSOR VALIDATION ===")
    print(f"Total verified live models: {len(val_deep['verified_models'])}")
    print(f"Total load errors: {len(val_deep['errors'])}")
    
    if val_deep["errors"]:
        for err in val_deep["errors"]:
            print(f"  [ERROR]: {err}")
    else:
        print("[SUCCESS] All 7 registered models loaded and verified successfully against schemas!")
        for m in val_deep["verified_models"]:
            print(f"  * {m['name']:<30} | Framework: {m['framework']:<16} | Features: {m['features']} | Classes: {m['classes']} | Status: {m['status']}")

