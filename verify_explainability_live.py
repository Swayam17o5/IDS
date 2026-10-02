import urllib.request
import json

def verify_live():
    # Fetch latest real alert from database
    with urllib.request.urlopen("http://127.0.0.1:8000/api/alerts") as r:
        alerts = json.loads(r.read().decode())
        if not alerts:
            print("No alerts found in database.")
            return
        target_alert = alerts[0]
        alert_id = target_alert["alert_id"]
        print(f"Testing live with real alert ID: {alert_id}")

    url = f"http://127.0.0.1:8000/api/alerts/{alert_id}/deep-explanation"
    req = urllib.request.Request(url)
    with urllib.request.urlopen(req) as response:
        data = json.loads(response.read().decode())
        print("=== LIVE REAL ALERT EXPLAINABILITY VERIFICATION ===")
        print(f"Alert ID: {data['alert']['alert_id']}")
        print(f"Final Aegis Decision: {data['alert']['attack_type']}")
        print(f"Detection Method: {data['alert']['detection_method']}")
        print(f"Detection Confidence: {data['alert']['detection_confidence'] * 100:.2f}%")
        print(f"ML Model Prediction: {data['ml_verdict']['predicted_label']}")
        print(f"ML Confidence: {data['ml_verdict']['confidence'] * 100:.2f}%")
        print(f"ML Class Probabilities Count: {len(data['ml_verdict']['class_probabilities'])}")
        print(f"Heuristic Verdict: {data['heuristic_verdict']['attack_type']}")
        print(f"Distinct Ports Scanned: {data['heuristic_verdict']['distinct_ports_scanned']}")
        print(f"Heuristic Confidence: {data['heuristic_verdict']['heuristic_confidence'] * 100:.2f}%")
        print(f"SHAP Base Value: {data['shap']['base_value']}")
        print(f"SHAP Supporting Features Count (+): {len(data['shap']['supporting_features'])}")
        print(f"SHAP Opposing Features Count (-): {len(data['shap']['opposing_features'])}")
        print(f"SHAP All 77 Features Count: {len(data['shap']['all_77_features'])}")
        print("Top Supporting Features:")
        for f in data['shap']['supporting_features'][:3]:
            print(f"  + {f['feature']}: val={f['value']}, shap={f['shap_value']}")
        print("Top Opposing Features:")
        for f in data['shap']['opposing_features'][:3]:
            print(f"  - {f['feature']}: val={f['value']}, shap={f['shap_value']}")
        print(f"Global Feature Importance Top 3: {[g['feature'] + ' (' + str(g['importance_pct']) + '%)' for g in data['global_shap'][:3]]}")
        print("\nForensic Synthesis Rationale:")
        print(data['comparison']['why_alert_generated'])

    # Verify HTML route
    html_url = f"http://127.0.0.1:8000/explainability/{alert_id}"
    with urllib.request.urlopen(html_url) as response:
        html = response.read().decode()
        print("\n=== HTML ROUTE VERIFICATION ===")
        print(f"Status Code: {response.status}")
        print(f"HTML Length: {len(html)} bytes")
        print(f"Contains Title: {'AegisNIDS // AI Explainability' in html}")

if __name__ == "__main__":
    verify_live()
