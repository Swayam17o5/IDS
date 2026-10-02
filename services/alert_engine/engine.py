"""
services/alert_engine/engine.py
--------------------------------
Alert processing engine with:
  - Severity loaded from severity_config.json (no hardcoding)
  - Alert deduplication by (src_ip, dst_ip, attack_type, time-window)
  - False-positive session suppression
  - Structured Python logging throughout
"""

import os
import json
import time
import logging
from typing import Dict, Any, Optional

logger = logging.getLogger("aegis.alert_engine")


# ---------------------------------------------------------------------------
# Load severity config from JSON (not hardcoded)
# ---------------------------------------------------------------------------

_DEFAULT_SEVERITY_CONFIG = os.path.join(
    os.path.dirname(__file__), "..", "..", "severity_config.json"
)


def _load_severity_config(path: str) -> Dict[str, Any]:
    abs_path = os.path.abspath(path)
    if os.path.exists(abs_path):
        with open(abs_path, "r") as fh:
            return json.load(fh)
    logger.warning("severity_config.json not found at %s, using built-in defaults", abs_path)
    return {
        "attack_severities": {
            "Benign": "NONE",
            "PortScan": "MEDIUM",
        },
        "default_severity": "MEDIUM",
        "thresholds": {"min_confidence_for_alert": 0.80, "dedup_window_seconds": 120},
    }


class AlertEngine:
    """
    Processes ML predictions into deduplicated security alerts.

    Parameters
    ----------
    min_confidence_threshold : float
        Minimum ML confidence before an alert is generated.
    dedup_window_seconds : int
        How long (seconds) within which duplicate alerts are suppressed.
    severity_config_path : str
        Path to severity_config.json.
    """

    def __init__(
        self,
        min_confidence_threshold: float = 0.80,
        dedup_window_seconds: int = 120,
        severity_config_path: str = _DEFAULT_SEVERITY_CONFIG,
    ) -> None:
        cfg = _load_severity_config(severity_config_path)
        thresholds = cfg.get("thresholds", {})

        # Allow constructor override; otherwise fall back to config
        self.min_confidence = min_confidence_threshold
        self.dedup_window = dedup_window_seconds or thresholds.get("dedup_window_seconds", 120)

        self._severity_map: Dict[str, str] = cfg.get("attack_severities", {})
        self._default_severity: str = cfg.get("default_severity", "MEDIUM")

        # In-memory dedup cache: key -> {"first_seen": ts, "last_seen": ts, "count": int}
        self.dedup_cache: Dict[str, Dict[str, Any]] = {}

        # False-positive suppression: set of (src_ip:dst_port:label) strings
        self.fp_suppressed_patterns: set = set()

        logger.info(
            "AlertEngine initialised: min_confidence=%.2f dedup_window=%ds severity_entries=%d",
            self.min_confidence,
            self.dedup_window,
            len(self._severity_map),
        )

    # ------------------------------------------------------------------
    # Severity lookup
    # ------------------------------------------------------------------

    def get_severity(self, attack_type: str) -> str:
        """Return severity level for *attack_type* from config."""
        return self._severity_map.get(attack_type, self._default_severity)

    # ------------------------------------------------------------------
    # False-positive management
    # ------------------------------------------------------------------

    def mark_false_positive(self, src_ip: str, dst_port: int, attack_type: str) -> None:
        """Suppress subsequent alerts for this pattern in the current session."""
        key = f"{src_ip}:{dst_port}:{attack_type}"
        self.fp_suppressed_patterns.add(key)
        logger.info("FP suppression added: %s", key)

    def unmark_false_positive(self, src_ip: str, dst_port: int, attack_type: str) -> None:
        """Remove pattern from false-positive suppression."""
        key = f"{src_ip}:{dst_port}:{attack_type}"
        self.fp_suppressed_patterns.discard(key)
        logger.info("FP suppression removed: %s", key)

    # ------------------------------------------------------------------
    # Core prediction processing
    # ------------------------------------------------------------------

    def process_prediction(
        self,
        prediction_payload: Dict[str, Any],
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Optional[Dict[str, Any]]:
        """
        Process an ML prediction payload and optionally emit an alert.

        Returns
        -------
        dict  : alert event if a NEW alert should be persisted/emitted
        None  : if benign, below threshold, duplicate, or FP-suppressed
        """
        metadata = metadata or {}
        verdict = prediction_payload.get("final_verdict", {})
        label = verdict.get("predicted_label", "Benign")
        confidence = float(verdict.get("confidence", 0.0))

        # Benign traffic → never alert
        if label == "Benign":
            logger.debug("Benign traffic, no alert generated")
            return None

        # Low confidence → skip
        if confidence < self.min_confidence:
            logger.debug(
                "Confidence %.4f below threshold %.4f for %s — skipping alert",
                confidence, self.min_confidence, label,
            )
            return None

        severity = self.get_severity(label)
        if severity == "NONE":
            return None

        src_ip = metadata.get("src_ip", "0.0.0.0")
        dst_ip = metadata.get("dst_ip", "0.0.0.0")
        dst_port = metadata.get("dst_port", 0)

        # Dedup key: (src_ip, dst_ip, attack_type) — groups related flows
        dedup_key = f"{src_ip}:{dst_ip}:{label}"

        # False-positive pattern check (uses src_ip:dst_port:label for specificity)
        fp_key = f"{src_ip}:{dst_port}:{label}"
        if fp_key in self.fp_suppressed_patterns:
            logger.debug("Alert suppressed by FP pattern: %s", fp_key)
            return None

        now = time.time()

        # Deduplication window check
        if dedup_key in self.dedup_cache:
            entry = self.dedup_cache[dedup_key]
            if now - entry["last_seen"] < self.dedup_window:
                entry["count"] += 1
                entry["last_seen"] = now
                logger.debug(
                    "Alert deduplicated (count=%d): %s", entry["count"], dedup_key
                )
                return None

        # New alert
        self.dedup_cache[dedup_key] = {
            "first_seen": now,
            "last_seen": now,
            "count": 1,
        }

        alert_id = f"ALT-{int(now * 1000)}"
        alert = {
            "alert_id": alert_id,
            "timestamp": now,
            "severity": severity,
            "attack_type": label,
            "confidence": confidence,
            "detection_method": verdict.get("detection_method", "MACHINE_LEARNING"),
            "detection_confidence": verdict.get("detection_confidence", confidence),
            "ml_predicted_label": verdict.get("ml_predicted_label", label),
            "ml_confidence": verdict.get("ml_confidence", confidence),
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "dst_port": dst_port,
            "model_used": verdict.get("active_model_used", "ensemble"),
            "shap_explanations": prediction_payload.get("shap_explanations", []),
            "dedup_key": dedup_key,
            "status": "NEW",
        }

        logger.info(
            "Alert generated: alert_id=%s attack=%s severity=%s src=%s dst=%s:%d conf=%.4f",
            alert_id, label, severity, src_ip, dst_ip, dst_port, confidence,
        )

        return alert

    # ------------------------------------------------------------------
    # Utility
    # ------------------------------------------------------------------

    def get_active_alert_counts(self) -> Dict[str, int]:
        """Return per-severity active alert counts from the dedup cache."""
        counts: Dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for key, entry in self.dedup_cache.items():
            attack_type = key.split(":")[-1]
            sev = self.get_severity(attack_type)
            if sev in counts:
                counts[sev] += entry["count"]
        return counts

    def reset(self) -> None:
        """Clear alert deduplication cache and false-positive suppression."""
        self.dedup_cache.clear()
        self.fp_suppressed_patterns.clear()
        logger.info("AlertEngine state reset (dedup cache and FP patterns cleared)")
