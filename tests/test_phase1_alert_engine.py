"""
tests/test_phase1_alert_engine.py
----------------------------------
Phase 1 Alert Engine Tests

Covers:
  - Severity loaded from severity_config.json (no hardcoding)
  - Confidence threshold filtering
  - Alert deduplication window
  - False-positive suppression
  - Alert reset
  - get_severity method
  - unmark_false_positive restores alerting
"""

import time
import pytest
from services.alert_engine.engine import AlertEngine


SEVERITY_CONFIG = "severity_config.json"


@pytest.fixture
def engine():
    return AlertEngine(
        min_confidence_threshold=0.80,
        dedup_window_seconds=5,
        severity_config_path=SEVERITY_CONFIG,
    )


def _make_payload(label: str, confidence: float = 0.95) -> dict:
    return {
        "final_verdict": {
            "predicted_label": label,
            "confidence": confidence,
            "active_model_used": "weighted_voting_ensemble",
            "detection_method": "MACHINE_LEARNING",
        }
    }


def _meta(src: str = "10.0.0.1", dst: str = "192.168.1.1", port: int = 22) -> dict:
    return {"src_ip": src, "dst_ip": dst, "dst_port": port}


# ─── Severity from Config ─────────────────────────────────────────────────────

class TestSeverityConfig:
    def test_portscan_severity_is_medium(self, engine):
        assert engine.get_severity("PortScan") == "MEDIUM"

    def test_ddos_severity_is_critical(self, engine):
        assert engine.get_severity("DDoS") == "CRITICAL"

    def test_dos_hulk_severity_is_high(self, engine):
        assert engine.get_severity("DoS Hulk") == "HIGH"

    def test_unknown_label_returns_default(self, engine):
        sev = engine.get_severity("UNKNOWN_ATTACK_TYPE")
        assert sev in ("MEDIUM", "HIGH", "CRITICAL", "LOW", "INFO", "NONE")

    def test_benign_severity_is_none(self, engine):
        assert engine.get_severity("Benign") == "NONE"


# ─── Confidence Threshold ─────────────────────────────────────────────────────

class TestConfidenceThreshold:
    def test_high_confidence_attack_triggers_alert(self, engine):
        payload = _make_payload("DDoS", confidence=0.95)
        alert = engine.process_prediction(payload, _meta())
        assert alert is not None
        assert alert["attack_type"] == "DDoS"

    def test_below_threshold_no_alert(self, engine):
        payload = _make_payload("DDoS", confidence=0.70)
        alert = engine.process_prediction(payload, _meta(src="10.0.0.99"))
        assert alert is None

    def test_exactly_threshold_triggers_alert(self, engine):
        # conf=0.80 with default threshold 0.80 → should alert (>= boundary)
        payload = _make_payload("PortScan", confidence=0.80)
        alert = engine.process_prediction(payload, _meta(src="10.1.1.1"))
        # Exact threshold: alerts ONLY when confidence >= threshold
        # (engine uses strict <, so 0.80 should pass)
        assert alert is not None

    def test_just_below_threshold_no_alert(self, engine):
        payload = _make_payload("PortScan", confidence=0.799)
        alert = engine.process_prediction(payload, _meta(src="10.1.1.2"))
        assert alert is None


# ─── Benign Traffic ───────────────────────────────────────────────────────────

class TestBenignTraffic:
    def test_benign_produces_no_alert(self, engine):
        payload = _make_payload("Benign", confidence=0.999)
        alert = engine.process_prediction(payload, _meta())
        assert alert is None

    def test_none_severity_produces_no_alert(self, engine):
        """Benign label has NONE severity → no alert."""
        payload = _make_payload("Benign", confidence=0.999)
        alert = engine.process_prediction(payload, _meta(src="1.2.3.4"))
        assert alert is None


# ─── Alert Structure ──────────────────────────────────────────────────────────

class TestAlertStructure:
    def test_alert_has_required_fields(self):
        engine = AlertEngine(severity_config_path=SEVERITY_CONFIG)
        payload = _make_payload("DDoS", confidence=0.98)
        alert = engine.process_prediction(payload, {"src_ip": "192.168.1.10", "dst_ip": "10.0.0.1", "dst_port": 80})
        assert alert is not None
        required = ["alert_id", "timestamp", "severity", "attack_type", "confidence",
                    "src_ip", "dst_ip", "dst_port", "model_used", "dedup_key", "status"]
        for field in required:
            assert field in alert, f"Missing field: {field}"

    def test_alert_status_is_new(self):
        engine = AlertEngine(severity_config_path=SEVERITY_CONFIG)
        payload = _make_payload("DDoS", confidence=0.98)
        alert = engine.process_prediction(payload, _meta(src="192.168.9.9"))
        assert alert["status"] == "NEW"

    def test_alert_severity_matches_config(self):
        engine = AlertEngine(severity_config_path=SEVERITY_CONFIG)
        payload = _make_payload("DDoS", confidence=0.98)
        alert = engine.process_prediction(payload, _meta(src="1.2.3.5"))
        assert alert["severity"] == "CRITICAL"


# ─── Deduplication ───────────────────────────────────────────────────────────

class TestDeduplication:
    def test_second_identical_alert_is_deduplicated(self, engine):
        meta = _meta(src="172.16.0.1")
        payload = _make_payload("PortScan", confidence=0.92)
        alert1 = engine.process_prediction(payload, meta)
        assert alert1 is not None  # first alert fires
        alert2 = engine.process_prediction(payload, meta)
        assert alert2 is None  # same src/dst/attack within window → deduped

    def test_different_src_ip_generates_separate_alert(self, engine):
        payload = _make_payload("PortScan", confidence=0.92)
        alert1 = engine.process_prediction(payload, _meta(src="172.16.1.1"))
        alert2 = engine.process_prediction(payload, _meta(src="172.16.1.2"))
        assert alert1 is not None
        assert alert2 is not None  # different source → different alert

    def test_alert_fires_again_after_dedup_window_expires(self):
        """Use a 1-second dedup window and wait for it to expire."""
        fast_engine = AlertEngine(
            min_confidence_threshold=0.80,
            dedup_window_seconds=1,
            severity_config_path=SEVERITY_CONFIG,
        )
        meta = _meta(src="172.16.2.1")
        payload = _make_payload("PortScan", confidence=0.92)
        alert1 = fast_engine.process_prediction(payload, meta)
        assert alert1 is not None
        time.sleep(1.1)
        alert2 = fast_engine.process_prediction(payload, meta)
        assert alert2 is not None  # dedup window expired → new alert


# ─── False-Positive Suppression ──────────────────────────────────────────────

class TestFalsePositiveSuppression:
    def test_mark_fp_suppresses_subsequent_alerts(self):
        engine = AlertEngine(severity_config_path=SEVERITY_CONFIG)
        payload = _make_payload("PortScan", confidence=0.92)
        meta = {"src_ip": "10.10.10.1", "dst_ip": "10.10.10.2", "dst_port": 22}

        # First alert fires
        alert1 = engine.process_prediction(payload, meta)
        assert alert1 is not None

        # Mark this pattern as FP
        engine.mark_false_positive("10.10.10.1", 22, "PortScan")

        # Reset dedup cache so the FP suppression is the only gate
        engine.dedup_cache.clear()

        # Now the same alert should be suppressed
        alert2 = engine.process_prediction(payload, meta)
        assert alert2 is None

    def test_unmark_fp_restores_alerting(self):
        engine = AlertEngine(severity_config_path=SEVERITY_CONFIG)
        payload = _make_payload("PortScan", confidence=0.92)
        meta = {"src_ip": "10.10.20.1", "dst_ip": "10.10.20.2", "dst_port": 80}

        engine.mark_false_positive("10.10.20.1", 80, "PortScan")
        engine.unmark_false_positive("10.10.20.1", 80, "PortScan")

        alert = engine.process_prediction(payload, meta)
        assert alert is not None  # FP suppression removed → alert fires


# ─── Reset ───────────────────────────────────────────────────────────────────

class TestReset:
    def test_reset_clears_dedup_cache(self):
        engine = AlertEngine(severity_config_path=SEVERITY_CONFIG)
        payload = _make_payload("PortScan", confidence=0.92)
        meta = _meta(src="10.0.0.55")
        engine.process_prediction(payload, meta)
        assert len(engine.dedup_cache) > 0

        engine.reset()
        assert len(engine.dedup_cache) == 0

    def test_reset_clears_fp_patterns(self):
        engine = AlertEngine(severity_config_path=SEVERITY_CONFIG)
        engine.mark_false_positive("1.1.1.1", 443, "DDoS")
        assert len(engine.fp_suppressed_patterns) > 0

        engine.reset()
        assert len(engine.fp_suppressed_patterns) == 0

    def test_after_reset_alert_fires_again(self):
        engine = AlertEngine(severity_config_path=SEVERITY_CONFIG)
        payload = _make_payload("PortScan", confidence=0.92)
        meta = _meta(src="10.0.0.99")
        alert1 = engine.process_prediction(payload, meta)
        assert alert1 is not None

        engine.reset()

        alert2 = engine.process_prediction(payload, meta)
        assert alert2 is not None  # After reset, alert fires again
