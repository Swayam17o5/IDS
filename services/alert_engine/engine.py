import time
from typing import Dict, Any, Optional, List

SEVERITY_MAP = {
    "DDoS": "CRITICAL",
    "Heartbleed": "CRITICAL",
    "Infiltration": "CRITICAL",
    "DoS Hulk": "HIGH",
    "DoS GoldenEye": "HIGH",
    "DoS Slowhttptest": "HIGH",
    "DoS slowloris": "HIGH",
    "Web Attack - Sql Injection": "HIGH",
    "Bot": "MEDIUM",
    "PortScan": "MEDIUM",
    "SSH-Patator": "MEDIUM",
    "FTP-Patator": "MEDIUM",
    "Web Attack - Brute Force": "MEDIUM",
    "Web Attack - XSS": "MEDIUM",
    "Benign": "INFO"
}

class AlertEngine:
    def __init__(self, min_confidence_threshold: float = 0.80, dedup_window_seconds: int = 300):
        self.min_confidence = min_confidence_threshold
        self.dedup_window = dedup_window_seconds
        # dedup cache: key -> {"last_seen": timestamp, "count": int}
        self.dedup_cache = {}
        # False-positive suppression cache: set of (src_ip:dst_port:label) patterns
        self.fp_suppressed_patterns = set()

    def mark_false_positive(self, src_ip: str, dst_port: int, attack_type: str):
        """Suppresses subsequent alerts for this pattern in the current session."""
        key = f"{src_ip}:{dst_port}:{attack_type}"
        self.fp_suppressed_patterns.add(key)

    def unmark_false_positive(self, src_ip: str, dst_port: int, attack_type: str):
        """Removes pattern from false-positive suppression."""
        key = f"{src_ip}:{dst_port}:{attack_type}"
        self.fp_suppressed_patterns.discard(key)

    def process_prediction(self, prediction_payload: Dict[str, Any], metadata: Optional[Dict[str, Any]] = None) -> Optional[Dict[str, Any]]:
        metadata = metadata or {}
        verdict = prediction_payload.get("final_verdict", {})
        label = verdict.get("predicted_label", "Benign")
        confidence = float(verdict.get("confidence", 0.0))
        
        # Primary guardrail: Only generate alerts if the active champion model predicts an attack
        # with confidence meeting or exceeding the minimum threshold (default 80%).
        if label == "Benign" or confidence < self.min_confidence:
            return None

        severity = SEVERITY_MAP.get(label, "MEDIUM")
        src_ip = metadata.get("src_ip", "0.0.0.0")
        dst_ip = metadata.get("dst_ip", "0.0.0.0")
        dst_port = metadata.get("dst_port", 0)
        
        dedup_key = f"{src_ip}:{dst_port}:{label}"

        # If this exact pattern was marked FALSE_POSITIVE earlier in the session, suppress repeat alert
        if dedup_key in self.fp_suppressed_patterns:
            return None
        
        now = time.time()
        
        # Check deduplication window
        if dedup_key in self.dedup_cache:
            entry = self.dedup_cache[dedup_key]
            if now - entry["last_seen"] < self.dedup_window:
                entry["count"] += 1
                entry["last_seen"] = now
                # Suppress duplicated alert notification
                return None
        
        # New alert
        self.dedup_cache[dedup_key] = {"last_seen": now, "count": 1}
        
        alert = {
            "alert_id": f"ALT-{int(now * 1000)}",
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
            "status": "NEW"
        }
        return alert

    def get_active_alert_counts(self) -> Dict[str, int]:
        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for k, v in self.dedup_cache.items():
            label = k.split(":")[-1]
            sev = SEVERITY_MAP.get(label, "MEDIUM")
            if sev in counts:
                counts[sev] += v["count"]
        return counts

    def reset(self):
        """Clears alert deduplication cache and false-positive suppression cache."""
        self.dedup_cache.clear()
        self.fp_suppressed_patterns.clear()
