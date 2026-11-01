"""
Feature Schema Mapper: CICIDS2017 CSV → XGBoost Canonical

Maps CICIDS2017 CSV column names and order to the canonical feature schema
that the XGBoost model expects. This resolves the feature_names_in_ mismatch.

Author: Kiro
Date: 2026-10-05
Purpose: Fix 0% DoS Hulk detection by ensuring exact feature schema alignment
"""

import numpy as np
import pandas as pd
import logging

logger = logging.getLogger(__name__)

# Explicit mapping from CICIDS2017 CSV column names to canonical feature names
# Used to normalize feature data before passing to model
#
# KEY INSIGHT: CICIDS2017 CSV has 79 columns (78 features + Label)
# - CSV index 0: " Destination Port" (NOT used; Protocol comes from fallback)
# - CSV indices 1-77: map to canonical indices 0-76 (with Protocol=6 fallback at canonical[0])
# - CSV index 78: " Label"
#
# The CSV " Destination Port" is dropped entirely because:
# - It is a flow attribute, not a learned model feature
# - The model expects "Protocol" at canonical index 0, which is derived from flow metadata
# - Using Protocol=6 (TCP) as fallback is reasonable for netflow data
#
CSV_TO_CANONICAL_MAPPING = {
    # DROPPED: " Destination Port" at CSV index 0 is not mapped to any canonical feature
    # Instead, canonical index 0 ("Protocol") is filled from fallback/metadata
    
    # CSV indices 1-77 → canonical indices 0-76 (with Protocol at canonical[0])
    "Protocol": "Protocol",  # Canonical index 0: filled from fallback (6=TCP)
    
    # Positions 1-3: Direct match
    "Flow Duration": "Flow Duration",
    "Total Fwd Packets": "Total Fwd Packets",
    "Total Backward Packets": "Total Backward Packets",
    
    # Positions 4-5: Different naming convention
    "Total Length of Fwd Packets": "Fwd Packets Length Total",
    "Total Length of Bwd Packets": "Bwd Packets Length Total",
    
    # Positions 6-9: Direct match
    "Fwd Packet Length Max": "Fwd Packet Length Max",
    "Fwd Packet Length Min": "Fwd Packet Length Min",
    "Fwd Packet Length Mean": "Fwd Packet Length Mean",
    "Fwd Packet Length Std": "Fwd Packet Length Std",
    
    # Positions 10-13: Direct match
    "Bwd Packet Length Max": "Bwd Packet Length Max",
    "Bwd Packet Length Min": "Bwd Packet Length Min",
    "Bwd Packet Length Mean": "Bwd Packet Length Mean",
    "Bwd Packet Length Std": "Bwd Packet Length Std",
    
    # Positions 14-37: Mostly direct matches
    "Flow Bytes/s": "Flow Bytes/s",
    "Flow Packets/s": "Flow Packets/s",
    "Flow IAT Mean": "Flow IAT Mean",
    "Flow IAT Std": "Flow IAT Std",
    "Flow IAT Max": "Flow IAT Max",
    "Flow IAT Min": "Flow IAT Min",
    "Fwd IAT Total": "Fwd IAT Total",
    "Fwd IAT Mean": "Fwd IAT Mean",
    "Fwd IAT Std": "Fwd IAT Std",
    "Fwd IAT Max": "Fwd IAT Max",
    "Fwd IAT Min": "Fwd IAT Min",
    "Bwd IAT Total": "Bwd IAT Total",
    "Bwd IAT Mean": "Bwd IAT Mean",
    "Bwd IAT Std": "Bwd IAT Std",
    "Bwd IAT Max": "Bwd IAT Max",
    "Bwd IAT Min": "Bwd IAT Min",
    "Fwd PSH Flags": "Fwd PSH Flags",
    "Bwd PSH Flags": "Bwd PSH Flags",
    "Fwd URG Flags": "Fwd URG Flags",
    "Bwd URG Flags": "Bwd URG Flags",
    "Fwd Header Length": "Fwd Header Length",
    "Bwd Header Length": "Bwd Header Length",
    "Fwd Packets/s": "Fwd Packets/s",
    "Bwd Packets/s": "Bwd Packets/s",
    
    # Positions 38-39: Naming order swapped
    "Min Packet Length": "Packet Length Min",
    "Max Packet Length": "Packet Length Max",
    
    # Positions 40-42: Direct match
    "Packet Length Mean": "Packet Length Mean",
    "Packet Length Std": "Packet Length Std",
    "Packet Length Variance": "Packet Length Variance",
    
    # Positions 43-50: Direct match
    "FIN Flag Count": "FIN Flag Count",
    "SYN Flag Count": "SYN Flag Count",
    "RST Flag Count": "RST Flag Count",
    "PSH Flag Count": "PSH Flag Count",
    "ACK Flag Count": "ACK Flag Count",
    "URG Flag Count": "URG Flag Count",
    "CWE Flag Count": "CWE Flag Count",
    "ECE Flag Count": "ECE Flag Count",
    
    # Positions 51-52: "Down/Up Ratio" direct, "Average Packet Size" → "Avg Packet Size"
    "Down/Up Ratio": "Down/Up Ratio",
    "Average Packet Size": "Avg Packet Size",
    
    # Positions 53-61: Mostly direct (54 has "Fwd Header Length.1" in CSV)
    "Avg Fwd Segment Size": "Avg Fwd Segment Size",
    "Avg Bwd Segment Size": "Avg Bwd Segment Size",
    "Fwd Header Length.1": "Fwd Header Length",  # Duplicate column, mapped to canonical
    "Fwd Avg Bytes/Bulk": "Fwd Avg Bytes/Bulk",
    "Fwd Avg Packets/Bulk": "Fwd Avg Packets/Bulk",
    "Fwd Avg Bulk Rate": "Fwd Avg Bulk Rate",
    "Bwd Avg Bytes/Bulk": "Bwd Avg Bytes/Bulk",
    "Bwd Avg Packets/Bulk": "Bwd Avg Packets/Bulk",
    "Bwd Avg Bulk Rate": "Bwd Avg Bulk Rate",
    
    # Positions 62-65: Direct match
    "Subflow Fwd Packets": "Subflow Fwd Packets",
    "Subflow Fwd Bytes": "Subflow Fwd Bytes",
    "Subflow Bwd Packets": "Subflow Bwd Packets",
    "Subflow Bwd Bytes": "Subflow Bwd Bytes",
    
    # Positions 66-69: Naming convention differs (underscores vs spaces)
    "Init_Win_bytes_forward": "Init Fwd Win Bytes",
    "Init_Win_bytes_backward": "Init Bwd Win Bytes",
    "act_data_pkt_fwd": "Fwd Act Data Packets",
    "min_seg_size_forward": "Fwd Seg Size Min",
    
    # Positions 70-77: Active/Idle metrics - direct match
    "Active Mean": "Active Mean",
    "Active Std": "Active Std",
    "Active Max": "Active Max",
    "Active Min": "Active Min",
    "Idle Mean": "Idle Mean",
    "Idle Std": "Idle Std",
    "Idle Max": "Idle Max",
    "Idle Min": "Idle Min",
}

# Inverse mapping (canonical → CSV) for reference
CANONICAL_TO_CSV_MAPPING = {v: k for k, v in CSV_TO_CANONICAL_MAPPING.items() if v is not None}


def normalize_cicids2017_features(df_or_dict, expected_canonical_features, strict=True, protocol_fallback=6):
    """
    Normalize CICIDS2017 CSV features to canonical feature schema.
    
    Handles the key structural mismatch:
    - CICIDS2017 CSV has 78 features (indices 0-77) + Label
    - CSV index 0 is " Destination Port" (flow metadata, not a model feature)
    - Canonical features start with "Protocol" (not in CSV, use fallback)
    - CSV indices 1-77 map to canonical indices 0-76 (with Protocol at canonical[0])
    
    Args:
        df_or_dict: pd.DataFrame with CSV column names OR dict with CSV keys
        expected_canonical_features: List of canonical feature names (from model.feature_names_in_)
        strict: If True, raise on missing features; if False, fill with 0.0
        protocol_fallback: Default Protocol value if not in input (default 6=TCP)
    
    Returns:
        pd.DataFrame with exactly len(expected_canonical_features) columns in canonical order
        
    Raises:
        ValueError: If required features missing (when strict=True)
        KeyError: If mapping incomplete
    """
    
    # Convert dict to DataFrame if needed
    if isinstance(df_or_dict, dict):
        df = pd.DataFrame([df_or_dict])
    else:
        df = df_or_dict.copy()
    
    # Strip column names
    df.columns = [col.strip() for col in df.columns]
    
    logger.debug(f"Input shape: {df.shape}, columns: {list(df.columns[:5])}...{list(df.columns[-5:])}")

    # If input is already in the canonical model schema, do not
    # apply CSV -> canonical mapping again. Just reorder columns.
    canonical_set = set(expected_canonical_features)
    input_set = set(df.columns)

    if canonical_set.issubset(input_set):
        logger.debug("Input already uses canonical feature schema; skipping CSV mapping.")

        # Keep exactly the features expected by the model, in exact order.
        normalized = df[expected_canonical_features].copy()

        # Ensure numeric values and expected dtype.
        normalized = normalized.apply(pd.to_numeric, errors="coerce").astype(np.float32)

        if normalized.shape[1] != len(expected_canonical_features):
            raise ValueError(
                f"Canonical schema size mismatch: "
                f"{normalized.shape[1]} != {len(expected_canonical_features)}"
            )

        logger.debug(
            f"Canonical schema accepted directly: "
            f"{normalized.shape[1]}/{len(expected_canonical_features)} features"
        )

        return normalized
    
    # Build output array in canonical order
    output_data = []
    missing_features = []
    
    for canonical_idx, canonical_name in enumerate(expected_canonical_features):
        # Special case: Protocol is not in CICIDS2017 CSV
        if canonical_name == "Protocol":
            # Use fallback value (typically 6 for TCP)
            logger.debug(f"Canonical[{canonical_idx}] {canonical_name}: using Protocol fallback value {protocol_fallback}")
            output_data.append(np.full(len(df), protocol_fallback, dtype=np.float32))
            continue
        
        # Find CSV column name that maps to this canonical name
        csv_name = None
        for csv_col, can_name in CSV_TO_CANONICAL_MAPPING.items():
            if can_name == canonical_name:
                csv_name = csv_col
                break
        
        if csv_name is None:
            error_msg = f"No CSV mapping found for canonical feature: {canonical_name}"
            logger.error(error_msg)
            raise KeyError(error_msg)
        
        # Extract value from input CSV
        if csv_name in df.columns:
            logger.debug(f"Canonical[{canonical_idx}] {canonical_name} ← CSV '{csv_name}'")
            output_data.append(df[csv_name].values.astype(np.float32))
        else:
            if strict:
                missing_features.append((canonical_name, csv_name))
            else:
                logger.warning(f"Missing CSV feature '{csv_name}' (canonical {canonical_name}), filling with 0.0")
                output_data.append(np.zeros(len(df), dtype=np.float32))
    
    if missing_features and strict:
        error_msg = f"Missing required CSV features: {missing_features}"
        logger.error(error_msg)
        raise ValueError(error_msg)
    
    # Stack into proper shape and create DataFrame
    output_array = np.column_stack(output_data)
    output_df = pd.DataFrame(output_array, columns=expected_canonical_features, dtype=np.float32)
    
    logger.debug(f"Output shape: {output_df.shape}, columns: {list(output_df.columns[:5])}...{list(output_df.columns[-5:])}")
    logger.info(f"Successfully normalized {len(df)} rows from CSV format to canonical schema ({len(expected_canonical_features)} features)")
    
    return output_df


def validate_schema(df, expected_canonical_features):
    """
    Validate that DataFrame matches expected canonical schema exactly.
    
    Args:
        df: pd.DataFrame to validate
        expected_canonical_features: List of canonical feature names
    
    Returns:
        dict with validation results
        
    Raises:
        ValueError: If schema mismatch
    """
    results = {
        "valid": True,
        "feature_count": len(df.columns),
        "expected_count": len(expected_canonical_features),
        "column_names_match": list(df.columns) == expected_canonical_features,
        "dtype": str(df.dtypes.iloc[0]) if len(df.dtypes) > 0 else "unknown",
        "errors": [],
    }
    
    # Check count
    if len(df.columns) != len(expected_canonical_features):
        results["errors"].append(f"Feature count mismatch: {len(df.columns)} vs {len(expected_canonical_features)}")
        results["valid"] = False
    
    # Check names
    if list(df.columns) != expected_canonical_features:
        mismatches = []
        for i, (got, expected) in enumerate(zip(df.columns, expected_canonical_features)):
            if got != expected:
                mismatches.append(f"[{i}] got {repr(got)}, expected {repr(expected)}")
        if mismatches:
            results["errors"].append(f"Feature name mismatches: {mismatches[:5]}...")
            results["valid"] = False
    
    # Check dtype
    if not np.issubdtype(df.dtypes.iloc[0], np.floating):
        results["errors"].append(f"Expected float dtype, got {df.dtypes.iloc[0]}")
        results["valid"] = False
    
    if not results["valid"]:
        raise ValueError(f"Schema validation failed: {results['errors']}")
    
    return results


if __name__ == "__main__":
    # Quick test
    logging.basicConfig(level=logging.DEBUG)
    
    print("CSV→Canonical mapping (sample):")
    for i, (csv_name, can_name) in enumerate(list(CSV_TO_CANONICAL_MAPPING.items())[:10]):
        print(f"  {csv_name} → {can_name}")
    
    print(f"\nTotal mappings: {len(CSV_TO_CANONICAL_MAPPING)}")
    print(f"None values (dropped): {list(CSV_TO_CANONICAL_MAPPING.values()).count(None)}")
    print(f"Valid mappings: {len([v for v in CSV_TO_CANONICAL_MAPPING.values() if v])}")
