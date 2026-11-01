"""
csv_feature_mapper.py
=====================

Feature mapping layer: Convert CSV/raw flow data columns to canonical feature names.

This layer is responsible for:
1. Mapping CSV column names (with whitespace issues) to canonical feature names
2. Handling features not present in CSV (calculate or default appropriately)
3. Converting raw flow data to 77-feature canonical vector

Used by:
- Feature extraction from CICIDS2017 CSV
- Feature extraction from synthetic PCAP via FlowAggregator
- Any upstream layer preparing features for execute_flow_prediction
"""

import json
import os
import numpy as np
import pandas as pd
from typing import Dict, List, Tuple, Optional


class CSVFeatureMapper:
    """Map CSV columns and raw flow data to canonical feature names."""

    def __init__(self, feature_list_path: str = "models/cicids2017/feature_list.json"):
        """
        Initialize mapper with canonical feature list.

        Args:
            feature_list_path: Path to feature_list.json containing 77 canonical names
        """
        with open(feature_list_path) as f:
            self.canonical_features = json.load(f)

        # CSV column name → Canonical feature name mapping
        # Handles various column naming conventions from CICIDS2017 CSV
        self.csv_to_canonical = {
            # Protocol (not in CSV - will be set to 6 for TCP)
            # "Destination Port" is not Protocol, so we skip it

            # Flow-level metrics
            "Flow Duration": "Flow Duration",

            # Packet counts
            "Total Fwd Packets": "Total Fwd Packets",
            "Total Backward Packets": "Total Backward Packets",

            # Packet length totals
            "Total Length of Fwd Packets": "Fwd Packets Length Total",
            "Total Length of Bwd Packets": "Bwd Packets Length Total",

            # Forward packet length statistics
            "Fwd Packet Length Max": "Fwd Packet Length Max",
            "Fwd Packet Length Min": "Fwd Packet Length Min",
            "Fwd Packet Length Mean": "Fwd Packet Length Mean",
            "Fwd Packet Length Std": "Fwd Packet Length Std",

            # Backward packet length statistics
            "Bwd Packet Length Max": "Bwd Packet Length Max",
            "Bwd Packet Length Min": "Bwd Packet Length Min",
            "Bwd Packet Length Mean": "Bwd Packet Length Mean",
            "Bwd Packet Length Std": "Bwd Packet Length Std",

            # Flow rate metrics
            "Flow Bytes/s": "Flow Bytes/s",
            "Flow Packets/s": "Flow Packets/s",

            # Flow IAT (inter-arrival time) - Flow-level
            "Flow IAT Mean": "Flow IAT Mean",
            "Flow IAT Std": "Flow IAT Std",
            "Flow IAT Max": "Flow IAT Max",
            "Flow IAT Min": "Flow IAT Min",

            # Forward IAT
            "Fwd IAT Total": "Fwd IAT Total",
            "Fwd IAT Mean": "Fwd IAT Mean",
            "Fwd IAT Std": "Fwd IAT Std",
            "Fwd IAT Max": "Fwd IAT Max",
            "Fwd IAT Min": "Fwd IAT Min",

            # Backward IAT
            "Bwd IAT Total": "Bwd IAT Total",
            "Bwd IAT Mean": "Bwd IAT Mean",
            "Bwd IAT Std": "Bwd IAT Std",
            "Bwd IAT Max": "Bwd IAT Max",
            "Bwd IAT Min": "Bwd IAT Min",

            # TCP Flags - PSH
            "Fwd PSH Flags": "Fwd PSH Flags",
            "Bwd PSH Flags": "Bwd PSH Flags",

            # TCP Flags - URG
            "Fwd URG Flags": "Fwd URG Flags",
            "Bwd URG Flags": "Bwd URG Flags",

            # Header lengths
            "Fwd Header Length": "Fwd Header Length",
            "Bwd Header Length": "Bwd Header Length",

            # Packet rates
            "Fwd Packets/s": "Fwd Packets/s",
            "Bwd Packets/s": "Bwd Packets/s",

            # Packet length statistics (aggregate)
            "Min Packet Length": "Packet Length Min",
            "Max Packet Length": "Packet Length Max",
            "Packet Length Mean": "Packet Length Mean",
            "Packet Length Std": "Packet Length Std",
            "Packet Length Variance": "Packet Length Variance",

            # TCP Flags - FIN, SYN, RST, PSH, ACK, URG, CWE, ECE
            "FIN Flag Count": "FIN Flag Count",
            "SYN Flag Count": "SYN Flag Count",
            "RST Flag Count": "RST Flag Count",
            "PSH Flag Count": "PSH Flag Count",
            "ACK Flag Count": "ACK Flag Count",
            "URG Flag Count": "URG Flag Count",
            "CWE Flag Count": "CWE Flag Count",
            "ECE Flag Count": "ECE Flag Count",

            # Ratios
            "Down/Up Ratio": "Down/Up Ratio",

            # Aggregate packet size statistics
            "Average Packet Size": "Avg Packet Size",
            "Avg Fwd Segment Size": "Avg Fwd Segment Size",
            "Avg Bwd Segment Size": "Avg Bwd Segment Size",

            # Bulk statistics
            "Fwd Avg Bytes/Bulk": "Fwd Avg Bytes/Bulk",
            "Fwd Avg Packets/Bulk": "Fwd Avg Packets/Bulk",
            "Fwd Avg Bulk Rate": "Fwd Avg Bulk Rate",
            "Bwd Avg Bytes/Bulk": "Bwd Avg Bytes/Bulk",
            "Bwd Avg Packets/Bulk": "Bwd Avg Packets/Bulk",
            "Bwd Avg Bulk Rate": "Bwd Avg Bulk Rate",

            # Subflow statistics
            "Subflow Fwd Packets": "Subflow Fwd Packets",
            "Subflow Fwd Bytes": "Subflow Fwd Bytes",
            "Subflow Bwd Packets": "Subflow Bwd Packets",
            "Subflow Bwd Bytes": "Subflow Bwd Bytes",

            # TCP Window bytes
            "Init_Win_bytes_forward": "Init Fwd Win Bytes",
            "Init_Win_bytes_backward": "Init Bwd Win Bytes",

            # Active/Idle statistics
            "act_data_pkt_fwd": "Fwd Act Data Packets",
            "min_seg_size_forward": "Fwd Seg Size Min",
            "Active Mean": "Active Mean",
            "Active Std": "Active Std",
            "Active Max": "Active Max",
            "Active Min": "Active Min",
            "Idle Mean": "Idle Mean",
            "Idle Std": "Idle Std",
            "Idle Max": "Idle Max",
            "Idle Min": "Idle Min",
        }

        print(f"[CSVFeatureMapper] Initialized with {len(self.canonical_features)} canonical features")
        print(f"[CSVFeatureMapper] Mapping covers {len(self.csv_to_canonical)} CSV columns")

    def map_csv_row(
        self,
        row: pd.Series,
        strip_whitespace: bool = True,
        protocol: int = 6,
    ) -> Dict[str, float]:
        """
        Map a pandas Series (CSV row) to canonical features.

        Args:
            row: pandas Series from CSV (typically df.loc[index])
            strip_whitespace: If True, strip whitespace from column names
            protocol: Default protocol value (6 = TCP)

        Returns:
            Dict with 77 canonical feature names → float values
        """
        features = {}

        # Handle whitespace in row index (column names)
        if strip_whitespace:
            row.index = row.index.str.strip()

        # Set Protocol (not in CSV, default to TCP)
        features["Protocol"] = float(protocol)

        # Map CSV columns to canonical names
        for csv_col, canonical_name in self.csv_to_canonical.items():
            if csv_col in row.index:
                val = row[csv_col]
                # Handle NaN/Inf
                if pd.isna(val) or np.isinf(val):
                    val = 0.0
                else:
                    val = float(val)
            else:
                # CSV column not found, default to 0
                val = 0.0

            features[canonical_name] = val

        # Fill any remaining missing canonical features with 0
        for canonical_name in self.canonical_features:
            if canonical_name not in features:
                features[canonical_name] = 0.0

        return features

    def map_flow_dict(
        self,
        flow_data: Dict[str, float],
        protocol: int = 6,
    ) -> Dict[str, float]:
        """
        Map a flow data dict (e.g., from FlowAggregator) to canonical features.

        This handles cases where features come from aggregated flow data
        rather than raw CSV.

        Args:
            flow_data: Dict with feature names (may or may not be canonical)
            protocol: Default protocol value (6 = TCP)

        Returns:
            Dict with 77 canonical feature names → float values
        """
        features = {}

        # Set Protocol
        if "Protocol" in flow_data:
            features["Protocol"] = float(flow_data["Protocol"])
        else:
            features["Protocol"] = float(protocol)

        # Copy all features, using canonical names
        for canonical_name in self.canonical_features:
            if canonical_name in flow_data:
                val = flow_data[canonical_name]
                # Handle NaN/Inf
                if isinstance(val, (float, int)):
                    if np.isnan(val) or np.isinf(val):
                        val = 0.0
                    else:
                        val = float(val)
                else:
                    val = 0.0
            else:
                val = 0.0

            features[canonical_name] = val

        return features

    def to_ordered_array(self, features: Dict[str, float]) -> np.ndarray:
        """
        Convert feature dict to ordered numpy array (for XGBoost).

        Args:
            features: Dict with canonical feature names

        Returns:
            numpy array of shape (77,) with features in canonical order
        """
        return np.array(
            [features.get(name, 0.0) for name in self.canonical_features],
            dtype=np.float32,
        )

    def to_dataframe(
        self,
        features_list: List[Dict[str, float]],
        use_space_names: bool = True,
    ) -> pd.DataFrame:
        """
        Convert list of feature dicts to DataFrame (for XGBoost).

        Args:
            features_list: List of feature dicts
            use_space_names: If True, use space-based names (for XGBoost);
                           if False, use underscore-based names (for LightGBM)

        Returns:
            DataFrame with 77 columns in correct order
        """
        # Convert each dict to ordered array
        arrays = [self.to_ordered_array(f) for f in features_list]
        data = np.vstack(arrays) if arrays else np.zeros((0, len(self.canonical_features)))

        # Choose column names
        if use_space_names:
            columns = self.canonical_features
        else:
            columns = [c.replace(" ", "_").replace("-", "_") for c in self.canonical_features]

        return pd.DataFrame(data, columns=columns, dtype=np.float32)


def extract_features_from_csv(
    csv_path: str,
    row_index: Optional[int] = None,
    row_label_filter: Optional[str] = None,
) -> Tuple[Dict[str, float], int]:
    """
    Extract canonical features from a single CSV row.

    Args:
        csv_path: Path to CICIDS2017 CSV file
        row_index: Specific row index to extract (0-indexed)
        row_label_filter: If set, find first row matching this label

    Returns:
        (features_dict, csv_index) where csv_index is the actual row index in CSV
    """
    mapper = CSVFeatureMapper()
    df = pd.read_csv(csv_path)

    if row_index is not None:
        # Extract by index
        row = df.iloc[row_index]
        csv_index = df.index[row_index]
    elif row_label_filter is not None:
        # Extract by label match
        label_col = None
        for col in df.columns:
            if "label" in col.lower():
                label_col = col
                break

        if label_col is None:
            raise ValueError("No label column found in CSV")

        df[label_col] = df[label_col].str.strip()
        mask = df[label_col].str.contains(row_label_filter, case=False, na=False)
        if not mask.any():
            raise ValueError(f"No rows matching label '{row_label_filter}'")

        row = df[mask].iloc[0]
        csv_index = df[mask].index[0]
    else:
        raise ValueError("Must specify row_index or row_label_filter")

    features = mapper.map_csv_row(row, strip_whitespace=True, protocol=6)
    return features, csv_index


if __name__ == "__main__":
    # Quick test
    print("\n[TEST] CSVFeatureMapper\n")

    mapper = CSVFeatureMapper()

    # Test on first DoS Hulk row
    try:
        features, csv_idx = extract_features_from_csv(
            "Wednesday-workingHours.pcap_ISCX.csv",
            row_label_filter="DoS Hulk",
        )

        print(f"Extracted from CSV row index: {csv_idx}")
        print(f"Features extracted: {len(features)}")
        print(f"First 5 features: {list(features.items())[:5]}")

        # Convert to array
        arr = mapper.to_ordered_array(features)
        print(f"\nArray shape: {arr.shape}")
        print(f"Array first 5: {arr[:5]}")

        # Convert to DataFrame
        df = mapper.to_dataframe([features])
        print(f"\nDataFrame shape: {df.shape}")
        print(f"DataFrame columns (first 5): {list(df.columns[:5])}")

        print("\n[OK] CSVFeatureMapper test passed")

    except Exception as e:
        print(f"[ERROR] {e}")
        import traceback
        traceback.print_exc()
