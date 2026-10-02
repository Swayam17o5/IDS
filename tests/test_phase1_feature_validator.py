"""
tests/test_phase1_feature_validator.py
----------------------------------------
Phase 1 Feature Schema Validation Tests

Covers:
  - Correct 77 features              → valid=True
  - Missing feature                  → valid=False, missing_features populated
  - Extra feature                    → valid=False, extra_features populated
  - NaN value                        → sanitised to 0.0
  - +Infinity value                  → sanitised to 0.0
  - -Infinity value                  → sanitised to 0.0
  - None value (null)                → coerced to 0.0
  - Wrong datatype (string)          → coerced to 0.0 or type_error
  - Wrong ordering (dict order)      → canonical order enforced on output
  - Empty features dict              → valid=False
  - 76 features (one missing)        → valid=False
  - 78 features (one extra)          → valid=False
"""

import json
import math
import pytest
from services.validation.feature_validator import FeatureValidator, ValidationResult


SCHEMA_PATH = "feature_schema.json"
FEATURE_LIST_PATH = "models/cicids2017/feature_list.json"


@pytest.fixture(scope="module")
def validator():
    return FeatureValidator(schema_path=SCHEMA_PATH)


@pytest.fixture(scope="module")
def canonical_features():
    with open(FEATURE_LIST_PATH) as f:
        return json.load(f)


@pytest.fixture
def valid_features(canonical_features):
    """All 77 features set to 0.0 — valid benign vector."""
    return {feat: 0.0 for feat in canonical_features}


# ─── Happy Path ──────────────────────────────────────────────────────────────

class TestValidFeatures:
    def test_correct_77_features(self, validator, valid_features, canonical_features):
        result = validator.validate(valid_features)
        assert result.valid is True
        assert result.expected_features == 77
        assert result.received_features == 77
        assert result.missing_features == []
        assert result.extra_features == []
        assert result.ordered_values is not None
        assert len(result.ordered_values) == 77

    def test_canonical_order_enforced(self, validator, valid_features, canonical_features):
        """Even if dict keys are in arbitrary order, output vector must match canonical order."""
        # Scramble the dict order by reversing keys
        scrambled = {k: float(i) for i, k in enumerate(reversed(canonical_features))}
        result = validator.validate(scrambled)
        # Each value in ordered_values should correspond to the canonical feature at that index
        # Since we set value=index_from_end, for canonical[0] the scrambled value is 76.0
        # i.e., the validator must NOT just return the values in dict insertion order
        assert result.valid is True
        # The ordered_values must correspond to canonical order
        for idx, feat in enumerate(canonical_features):
            expected_val = scrambled[feat]
            assert result.ordered_values[idx] == pytest.approx(expected_val, abs=1e-5)

    def test_to_dataframe_shape(self, validator, valid_features, canonical_features):
        result = validator.validate(valid_features)
        df = result.to_dataframe(canonical_features)
        assert df.shape == (1, 77)
        assert list(df.columns) == canonical_features


# ─── Structural Errors ───────────────────────────────────────────────────────

class TestMissingFeatures:
    def test_one_missing_feature(self, validator, valid_features):
        missing = dict(valid_features)
        del missing["Flow Duration"]
        result = validator.validate(missing)
        assert result.valid is False
        assert "Flow Duration" in result.missing_features
        assert result.received_features == 76
        assert result.expected_features == 77

    def test_five_missing_features(self, validator, canonical_features):
        features = {feat: 0.0 for feat in canonical_features[:72]}
        result = validator.validate(features)
        assert result.valid is False
        assert len(result.missing_features) == 5
        assert result.received_features == 72

    def test_empty_features_dict(self, validator):
        result = validator.validate({})
        assert result.valid is False
        assert len(result.missing_features) == 77
        assert result.received_features == 0

    def test_error_response_structure(self, validator, valid_features):
        missing = dict(valid_features)
        del missing["Flow Duration"]
        del missing["Protocol"]
        result = validator.validate(missing)
        err = result.error_response()
        assert err["valid"] is False
        assert err["expected_features"] == 77
        assert err["received_features"] == 75
        assert "Flow Duration" in err["missing_features"]
        assert "Protocol" in err["missing_features"]


class TestExtraFeatures:
    def test_one_extra_feature(self, validator, valid_features):
        extra = dict(valid_features)
        extra["UNKNOWN_FEATURE_XYZ"] = 99.9
        result = validator.validate(extra)
        assert result.valid is False
        assert "UNKNOWN_FEATURE_XYZ" in result.extra_features
        assert result.received_features == 78

    def test_error_response_includes_extra(self, validator, valid_features):
        extra = dict(valid_features)
        extra["FAKE_FIELD_1"] = 1.0
        extra["FAKE_FIELD_2"] = 2.0
        result = validator.validate(extra)
        err = result.error_response()
        assert "FAKE_FIELD_1" in err["extra_features"]
        assert "FAKE_FIELD_2" in err["extra_features"]


# ─── Value Sanitisation ──────────────────────────────────────────────────────

class TestValueSanitisation:
    def test_nan_replaced_with_zero(self, validator, valid_features):
        features = dict(valid_features)
        features["Flow Duration"] = float("nan")
        result = validator.validate(features)
        assert result.valid is True
        idx = list(features.keys()).index("Flow Duration")
        # NaN should be in sanitized_features report
        assert any("Flow Duration" in s for s in result.sanitized_features)
        # And the ordered value should be 0.0
        canonical = [k for k in valid_features.keys()]
        flow_dur_idx = canonical.index("Flow Duration")
        assert result.ordered_values[flow_dur_idx] == 0.0

    def test_positive_infinity_replaced_with_zero(self, validator, valid_features):
        features = dict(valid_features)
        features["Flow Bytes/s"] = float("inf")
        result = validator.validate(features)
        assert result.valid is True
        assert any("Flow Bytes/s" in s for s in result.sanitized_features)

    def test_negative_infinity_replaced_with_zero(self, validator, valid_features):
        features = dict(valid_features)
        features["Flow Packets/s"] = float("-inf")
        result = validator.validate(features)
        assert result.valid is True
        assert any("Flow Packets/s" in s for s in result.sanitized_features)

    def test_none_value_coerced_to_zero(self, validator, canonical_features):
        """None maps to 0.0 but is a type error."""
        features = {feat: 0.0 for feat in canonical_features}
        features["Total Fwd Packets"] = None
        result = validator.validate(features)
        # None is a type error → valid=False
        assert result.valid is False
        assert any("Total Fwd Packets" in e for e in result.type_errors)

    def test_string_value_invalid_type(self, validator, canonical_features):
        features = {feat: 0.0 for feat in canonical_features}
        features["Protocol"] = "not_a_number"
        result = validator.validate(features)
        assert result.valid is False
        assert any("Protocol" in e for e in result.type_errors)

    def test_integer_coerced_to_float(self, validator, canonical_features):
        """Integers are valid (castable to float32)."""
        features = {feat: int(i) for i, feat in enumerate(canonical_features)}
        result = validator.validate(features)
        assert result.valid is True
        assert all(isinstance(v, float) for v in result.ordered_values)

    def test_non_dict_input_rejected(self, validator):
        result = validator.validate([1.0, 2.0, 3.0])
        assert result.valid is False
        assert len(result.errors) > 0
