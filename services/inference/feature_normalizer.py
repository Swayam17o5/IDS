"""
Feature name normalization for inference boundary.

Handles both:
1. Space-based → underscore-based normalization (for LightGBM)
2. CICIDS2017 CSV → canonical feature schema mapping (for XGBoost)

The CSV→canonical mapping is critical to fix the feature_names_in_ mismatch
that caused 0% DoS Hulk detection in production.
"""

import json
import logging
from typing import Dict, List, Any

logger = logging.getLogger(__name__)

# Import schema mapper for CICIDS2017 CSV → canonical mapping
try:
    from .feature_schema_mapper import (
        normalize_cicids2017_features,
        validate_schema,
        CSV_TO_CANONICAL_MAPPING,
    )
    SCHEMA_MAPPER_AVAILABLE = True
except ImportError:
    logger.warning("feature_schema_mapper not available, will use legacy normalization")
    SCHEMA_MAPPER_AVAILABLE = False


def normalize_feature_names(features_dict: Dict[str, float], canonical_features: List[str]) -> Dict[str, float]:
    """
    Normalize feature names from space-separated to underscore-separated format.
    
    Args:
        features_dict: Input features with potentially space-based names
        canonical_features: List of canonical feature names (with spaces)
    
    Returns:
        Dictionary with normalized (underscore) feature names
    """
    # Create mapping from space-based to underscore-based names
    normalized = {}
    
    for space_name in canonical_features:
        # Convert spaces and dashes to underscores
        underscore_name = space_name.replace(" ", "_").replace("-", "_")
        
        # Get value from input dict using space name, default to 0.0
        value = features_dict.get(space_name, 0.0)
        
        # Store with underscore name
        normalized[underscore_name] = value
    
    return normalized


def get_canonical_feature_names(features_json_path: str = "models/cicids2017/feature_list.json") -> List[str]:
    """
    Load canonical feature names from JSON file.
    
    Args:
        features_json_path: Path to feature list JSON
    
    Returns:
        List of feature names with spaces
    """
    with open(features_json_path) as f:
        return json.load(f)


def get_normalized_feature_names(canonical_features: List[str]) -> List[str]:
    """
    Convert canonical (space-based) feature names to normalized (underscore-based).
    
    Args:
        canonical_features: List of canonical feature names with spaces
    
    Returns:
        List of normalized feature names with underscores
    """
    return [name.replace(" ", "_").replace("-", "_") for name in canonical_features]


def normalize_for_xgboost(features_input, model_feature_names):
    """
    Normalize features for XGBoost using schema mapper.
    
    Handles CICIDS2017 CSV feature names and maps them to canonical schema
    expected by the trained XGBoost model.
    
    Args:
        features_input: dict or pd.DataFrame with CSV feature names
        model_feature_names: list of feature names from model.feature_names_in_
    
    Returns:
        pd.DataFrame with exact canonical feature names and order
        
    Raises:
        ValueError: If schema mismatch or mapping fails
    """
    if not SCHEMA_MAPPER_AVAILABLE:
        logger.warning("Schema mapper not available, skipping CSV→canonical mapping")
        return features_input
    
    try:
        # Normalize CSV features to canonical order
        df = normalize_cicids2017_features(
            features_input,
            model_feature_names,
            strict=True
        )
        
        # Validate schema
        validation = validate_schema(df, model_feature_names)
        logger.debug(f"Schema validation: {validation}")
        
        return df
    
    except Exception as e:
        logger.error(f"Feature normalization failed: {e}")
        raise
