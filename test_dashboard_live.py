import os
import sys
import json
from fastapi.testclient import TestClient

sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

from services.inference.app import app, init_models

print("=== TESTING SOC DASHBOARD, TRIAGE WORKFLOW, AND DEMO RELIABILITY ===")
init_models("cicids2017")
client = TestClient(app)

with open("models/cicids2017/feature_list.json") as f:
    feature_names = json.load(f)

# Reset DB state before starting
client.post("/api/reset")

# ========================================================================
# PART 1: Verify HTML Dashboard elements
# ========================================================================
print("\n--- 1. Verifying Dashboard HTML elements & layout ---")
res_html = client.get("/")
assert res_html.status_code == 200
html = res_html.text
assert "Triage" in html, "Alert table should have Triage column header"
assert "Status" in html, "Alert table should have Status column header"
assert "fp-modal" in html, "False Positive correction modal should exist"
assert "fp-corrected-label" in html, "FP modal should have corrected label dropdown"
assert "explanation-container" in html, "Explanation container should exist in SHAP panel"
assert "stat-precision" in html, "Analyst-Verified Precision metric card should exist"
assert "Analyst-Verified Precision" in html, "Analyst-Verified Precision card title should exist"
assert "NSL-KDD (Not yet implemented)" in html, "NSL-KDD status should be clearly marked"
assert "UNSW-NB15 (Not yet implemented)" in html, "UNSW-NB15 status should be clearly marked"
print("[PASSED] Dashboard HTML contains all expected metrics cards, modal elements, and dataset status badges.")

# ========================================================================
# PART 2: Initial Stats Check (Zero state)
# ========================================================================
print("\n--- 2. Verifying Initial Zero Stats & Precision Handling ---")
stats0 = client.get("/api/stats").json()
assert stats0["total_flows"] == 0
assert stats0["total_alerts"] == 0
assert stats0["analyst_precision"] is None, "Analyst precision should be None/null when no alerts have been triaged"
assert stats0["total_triaged"] == 0
print(f"Zero State Precision: {stats0['analyst_precision']} (renders as '—' in UI)")
print("[PASSED] Zero-state stats cleanly handled without fake 0% or 100%.")

# ========================================================================
# PART 3: Generate Real Attack Predictions
# ========================================================================
print("\n--- 3. Generating real attack predictions (XSS via XGBoost) ---")
client.post("/api/models/switch_active", json={"model_id": "xgboost"})

xss_feats = {f: 0.0 for f in feature_names}
xss_feats["Protocol"] = 6.0
xss_feats["Flow Duration"] = 20000.0
xss_feats["Total Fwd Packets"] = 22.0
xss_feats["Total Backward Packets"] = 24.0
xss_feats["Fwd Packets Length Total"] = 1800.0
xss_feats["Bwd Packets Length Total"] = 4000.0
xss_feats["Init Fwd Win Bytes"] = 29200.0
xss_feats["Init Bwd Win Bytes"] = 28960.0
xss_feats["Fwd Seg Size Min"] = 32.0

attack_payload = {
    "features": xss_feats,
    "metadata": {"src_ip": "172.16.0.99", "dst_ip": "192.168.1.1", "dst_port": 80, "src_port": 12345, "protocol": 6}
}

resp = client.post("/predict", json=attack_payload)
assert resp.status_code == 200
pred = resp.json()
print(f"Predicted: {pred['final_verdict']['predicted_label']} (Conf: {pred['final_verdict']['confidence']:.4f})")

alert_gen = pred.get("alert_generated")
assert alert_gen is not None, "Attack prediction should generate an alert!"
alert1_id = alert_gen["alert_id"]
assert alert_gen["status"] == "NEW"

explanation = alert_gen.get("explanation", "")
print(f"Alert ID: {alert1_id} | Status: {alert_gen['status']}")
print(f"Explanation: {explanation}")
assert len(explanation) > 20 and "Flagged as" in explanation
print("[PASSED] Attack prediction generated alert with status=NEW and plain-language explanation.")

# ========================================================================
# PART 4: Test Triage Transitions (ACK, ESCALATE, RESOLVE)
# ========================================================================
print(f"\n--- 4. Testing Triage Transitions for alert {alert1_id} ---")
# NEW -> ACKNOWLEDGED
r_ack = client.post(f"/api/alerts/{alert1_id}/status", json={"status": "ACKNOWLEDGED"})
assert r_ack.status_code == 200
assert r_ack.json()["triage_status"] == "ACKNOWLEDGED"

# ACKNOWLEDGED -> ESCALATED
r_esc = client.post(f"/api/alerts/{alert1_id}/status", json={"status": "ESCALATED"})
assert r_esc.status_code == 200
assert r_esc.json()["triage_status"] == "ESCALATED"

# Verify in DB
alerts = client.get("/api/alerts?limit=5").json()
a1 = [a for a in alerts if a["alert_id"] == alert1_id][0]
assert a1["status"] == "ESCALATED"
assert a1["is_acknowledged"] is True
print("[PASSED] Status transitions (NEW -> ACK -> ESCALATED) verified in DB.")

# Check precision with 1 real alert triaged: 1 real / 1 total = 100.0%
stats1 = client.get("/api/stats").json()
assert stats1["analyst_precision"] == 100.0
assert stats1["total_triaged"] == 1
print(f"Precision with 1 confirmed alert: {stats1['analyst_precision']}%")

# ========================================================================
# PART 5: Test False Positive Workflow & Precision Drop
# ========================================================================
print("\n--- 5. Testing FALSE_POSITIVE workflow & Precision calculation ---")
# Generate alert 2 from a different source
attack2_payload = {
    "features": xss_feats,
    "metadata": {"src_ip": "10.0.0.88", "dst_ip": "192.168.1.1", "dst_port": 8080, "src_port": 44444, "protocol": 6}
}
resp2 = client.post("/predict", json=attack2_payload)
alert2_id = resp2.json()["alert_generated"]["alert_id"]

# Mark alert 2 as FALSE_POSITIVE
r_fp = client.post(f"/api/alerts/{alert2_id}/status", json={
    "status": "FALSE_POSITIVE",
    "corrected_label": "Benign",
    "notes": "Benign developer traffic on port 8080"
})
assert r_fp.status_code == 200
assert r_fp.json()["feedback_logged"] is True

# Verify feedback table
feedback = client.get("/api/feedback").json()
assert len(feedback) >= 1
assert feedback[0]["alert_id"] == alert2_id
assert feedback[0]["corrected_label"] == "Benign"
assert len(feedback[0]["features_json"]) == 77

# Verify Precision: 1 confirmed (Alert 1) / 2 total triaged (Alert 1 + Alert 2) = 50.0%
stats2 = client.get("/api/stats").json()
print(f"Stats after FP: Total Alerts (excl FP): {stats2['total_alerts']} | Precision: {stats2['analyst_precision']}%")
assert stats2["analyst_precision"] == 50.0
assert stats2["total_triaged"] == 2
# Verify total_alerts excludes FALSE_POSITIVE: alert1 is active (ESCALATED), alert2 is FALSE_POSITIVE => total active alerts = 1
assert stats2["total_alerts"] == 1, f"Expected 1 active alert (excluding FP), got {stats2['total_alerts']}"
print("[PASSED] Stats correctly exclude FALSE_POSITIVE alerts and precision calculates to 50.0%.")

# ========================================================================
# PART 6: Test Session-Level False Positive Suppression
# ========================================================================
print("\n--- 6. Testing Session-Level FP Suppression for repeat attacks ---")
# Send identical attack for the pattern marked FALSE_POSITIVE (10.0.0.88 -> :8080 Web Attack - XSS)
resp_repeat = client.post("/predict", json=attack2_payload)
assert resp_repeat.status_code == 200
# The alert_generated should be None because this exact pattern was marked FALSE_POSITIVE in this session
assert resp_repeat.json().get("alert_generated") is None, "Repeat alert for known FP pattern must be suppressed!"
print("[PASSED] Subsequent flow matching false-positive signature was cleanly suppressed.")

# ========================================================================
# PART 7: Test Mutual Exclusivity of Triage State
# ========================================================================
print("\n--- 7. Testing Mutual Exclusivity of Triage State ---")
# Transition Alert 2 from FALSE_POSITIVE to RESOLVED
r_unfp = client.post(f"/api/alerts/{alert2_id}/status", json={"status": "RESOLVED"})
assert r_unfp.status_code == 200

# Now alert2 is RESOLVED (confirmed real), so precision becomes 2 real / 2 total = 100.0%
stats3 = client.get("/api/stats").json()
assert stats3["status_breakdown"]["FALSE_POSITIVE"] == 0
assert stats3["status_breakdown"]["RESOLVED"] == 1
assert stats3["analyst_precision"] == 100.0
assert stats3["total_alerts"] == 2  # Both alert1 (ESCALATED) and alert2 (RESOLVED) are active (non-FP)
print("[PASSED] Mutual exclusivity verified: transition away from FALSE_POSITIVE cleanly updates precision and active alert counts.")

# ========================================================================
# PART 8: Test POST /api/reset Clean Purge
# ========================================================================
print("\n--- 8. Testing POST /api/reset complete state purge ---")
r_reset = client.post("/api/reset")
assert r_reset.status_code == 200

stats_end = client.get("/api/stats").json()
assert stats_end["total_flows"] == 0
assert stats_end["total_predictions"] == 0
assert stats_end["total_alerts"] == 0
assert stats_end["analyst_precision"] is None
assert stats_end["total_triaged"] == 0
assert stats_end["feedback_count"] == 0
assert stats_end["severity_breakdown"]["CRITICAL"] == 0

fb_end = client.get("/api/feedback").json()
assert len(fb_end) == 0

flows_end = client.get("/api/flows").json()
assert len(flows_end) == 0

alerts_end = client.get("/api/alerts").json()
assert len(alerts_end) == 0
print("[PASSED] Reset purged 100% of flows, predictions, alerts, feedback, and telemetry counters.")

# Switch back to default active model
client.post("/api/models/switch_active", json={"model_id": "weighted_voting_ensemble"})

print("\n" + "=" * 70)
print("[SUCCESS] All 8 demo reliability and triage precision tests PASSED!")
print("=" * 70)
