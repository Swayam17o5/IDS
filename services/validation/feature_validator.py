"""
services/validation/feature_validator.py
-----------------------------------------
Centralised 77-feature schema validator for the CICIDS2017 pipeline.

Validates:
  - Feature count  (must equal 77)
  - Feature names  (must match canonical list exactly)
  - Feature order  (must be identical to training order)
  - Data types     (must be numeric / castable to float32)
  - NaN / Inf      (replaced with 0.0 after flagging)
  - Missing fields (reported explicitly)
  - Extra fields   (reported explicitly)

Usage
-----
    from services.validation.feature_validator import FeatureValidator
    validator = FeatureValidator()                     # loads from feature_schema.json
    result = validator.validate(feature_dict)          # returns ValidationResult
    if not result.valid:
        return result.error_response()                 # JSON-serialisable error dict
    df = result.to_dataframe()                         # ready for ML model

"""

import os
import json
import math
import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

import numpy as np
import pandas as pd

logger = logging.getLogger("aegis.validator")


# ---------------------------------------------------------------------------
# Schema loading
# ---------------------------------------------------------------------------

_DEFAULT_SCHEMA_PATH = os.path.join(
    os.path.dirname(__file__), "..", "..", "feature_schema.json"
)


def _load_schema(path: str) -> Dict[str, Any]:
    abs_path = os.path.abspath(path)
    if not os.path.exists(abs_path):
        raise FileNotFoundError(f"Feature schema not found: {abs_path}")
    with open(abs_path, "r") as fh:
        return json.load(fh)


# ---------------------------------------------------------------------------
# Validation result
# ---------------------------------------------------------------------------

@dataclass
class ValidationResult:
    valid: bool
    expected_features: int = 77
    received_features: int = 0
    missing_features: List[str] = field(default_factory=list)
    extra_features: List[str] = field(default_factory=list)
    sanitized_features: List[str] = field(default_factory=list)   # NaN/Inf fixed
    type_errors: List[str] = field(default_factory=list)
    ordered_values: Optional[List[float]] = None  # Sanitised, ordered feature values
    errors: List[str] = field(default_factory=list)

    def error_response(self) -> Dict[str, Any]:
        """Return a JSON-serialisable error dict for the API layer."""
        return {
            "valid": False,
            "expected_features": self.expected_features,
            "received_features": self.received_features,
            "missing_features": self.missing_features,
            "extra_features": self.extra_features,
            "type_errors": self.type_errors,
            "sanitized_features": self.sanitized_features,
            "errors": self.errors,
        }

    def to_dataframe(self, feature_names: List[str]) -> pd.DataFrame:
        """Return a single-row DataFrame with canonical column order."""
        if not self.valid or self.ordered_values is None:
            raise ValueError("Cannot build DataFrame from an invalid ValidationResult")
        return pd.DataFrame([self.ordered_values], columns=feature_names, dtype=np.float32)


# ---------------------------------------------------------------------------
# Validator
# ---------------------------------------------------------------------------

class FeatureValidator:
    """
    Validates a feature dict against the canonical CICIDS2017 77-feature schema.

    Parameters
    ----------
    schema_path : str
        Path to ``feature_schema.json``.  Defaults to the repo-root copy.
    strict_order : bool
        When True (default), the order of keys in the input dict is ignored
        and the canonical order is always enforced on the output.
    """

    def __init__(
        self,
        schema_path: str = _DEFAULT_SCHEMA_PATH,
        strict_order: bool = True,
    ) -> None:
        schema = _load_schema(schema_path)
        self._features: List[Dict[str, Any]] = schema["features"]
        self._feature_names: List[str] = [f["name"] for f in self._features]
        self._feature_set: set = set(self._feature_names)
        self._expected_count: int = len(self._feature_names)
        self.strict_order = strict_order

        logger.info(
            "FeatureValidator loaded schema: %d features, version=%s",
            self._expected_count,
            schema.get("version", "unknown"),
        )

    @property
    def feature_names(self) -> List[str]:
        return self._feature_names

    @property
    def expected_count(self) -> int:
        return self._expected_count

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def validate(self, features: Dict[str, Any]) -> ValidationResult:
        """
        Validate *features* against the canonical schema.

        Returns a :class:`ValidationResult`.  If ``result.valid`` is True,
        ``result.ordered_values`` contains the sanitised float32 feature
        vector in canonical order, ready for ML inference.
        """
        errors: List[str] = []
        sanitized: List[str] = []
        type_errors: List[str] = []

        if not isinstance(features, dict):
            return ValidationResult(
                valid=False,
                received_features=0,
                errors=[f"features must be a dict, got {type(features).__name__}"],
            )

        received_names = set(features.keys())
        missing = [n for n in self._feature_names if n not in received_names]
        extra = sorted(received_names - self._feature_set)
        received_count = len(features)

        if missing:
            errors.append(
                f"{len(missing)} missing feature(s): {missing[:10]}"
                + (" ..." if len(missing) > 10 else "")
            )
        if extra:
            errors.append(
                f"{len(extra)} unexpected feature(s): {extra[:10]}"
                + (" ..." if len(extra) > 10 else "")
            )

        # Even if there are structural errors we try to build the vector so we
        # can surface detailed diagnostics; we just mark result invalid.
        ordered_values: List[float] = []
        for feat_def in self._features:
            name = feat_def["name"]
            raw = features.get(name, None)

            # Type check / coercion
            if raw is None:
                val = 0.0
                type_errors.append(f"{name}: None → 0.0")
            else:
                try:
                    val = float(raw)
                except (TypeError, ValueError):
                    val = 0.0
                    type_errors.append(f"{name}: {type(raw).__name__} '{raw}' → 0.0")

            # NaN / Inf sanitisation
            if math.isnan(val) or math.isinf(val):
                sanitized.append(f"{name}: {'NaN' if math.isnan(val) else 'Inf'} → 0.0")
                val = 0.0

            ordered_values.append(val)

        if type_errors:
            errors.append(f"{len(type_errors)} type coercion(s): {type_errors[:5]}")

        valid = (not missing) and (not extra) and (not type_errors)

        result = ValidationResult(
            valid=valid,
            expected_features=self._expected_count,
            received_features=received_count,
            missing_features=missing,
            extra_features=extra,
            sanitized_features=sanitized,
            type_errors=type_errors,
            ordered_values=ordered_values if (not missing) else None,
            errors=errors,
        )

        if valid:
            logger.debug(
                "Feature validation PASSED: %d features, %d sanitized",
                received_count,
                len(sanitized),
            )
        else:
            logger.warning(
                "Feature validation FAILED: expected=%d received=%d missing=%d extra=%d type_errors=%d",
                self._expected_count,
                received_count,
                len(missing),
                len(extra),
                len(type_errors),
            )

        return result

    def validate_dataframe(self, df: pd.DataFrame) -> ValidationResult:
        """Validate a pre-built DataFrame (single row expected)."""
        if df.shape[0] != 1:
            return ValidationResult(
                valid=False,
                errors=[f"Expected 1 row, got {df.shape[0]}"],
            )
        feature_dict = {col: df.iloc[0][col] for col in df.columns}
        return self.validate(feature_dict)
