import time
import requests
import json
import numpy as np
from typing import Dict, Any, List

BASE_URL = "http://localhost:8000"

print("=================================================================")
print("STARTING 2-MINUTE LIVE BROWSING CAPTURE EXPERIMENT")
print("=================================================================")

# Step 1: Clean reset
print("\n[1] Resetting SOC database & telemetry...")
r_reset = requests.post(f"{BASE_URL}/api/reset")
print("Reset response:", r_reset.json())

# Step 2: Start live capture on active Wi-Fi interface
print("\n[2] Starting live capture on 'Wi-Fi' interface...")
r_start = requests.post(f"{BASE_URL}/api/capture/start", json={"interface": "Wi-Fi"})
print("Start capture response:", r_start.json())

# Step 3: Perform ordinary browsing activity for 120 seconds
print("\n[3] Generating 2 minutes (120s) of typical web browsing traffic...")
urls = [
    "https://www.google.com",
    "https://www.youtube.com",
    "https://www.wikipedia.org",
    "https://en.wikipedia.org/wiki/Network_intrusion_detection_system",
    "https://news.ycombinator.com",
    "https://httpbin.org/get",
    "https://httpbin.org/json",
    "https://www.bbc.com",
    "https://www.github.com",
    "https://api.github.com",
    "https://www.cnn.com",
    "https://www.reddit.com",
    "https://fastapi.tiangolo.com",
    "https://scikit-learn.org/stable/"
]

start_time = time.time()
session = requests.Session()
session.headers.update({"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"})

req_idx = 0
while time.time() - start_time < 120:
    elapsed = int(time.time() - start_time)
    target_url = urls[req_idx % len(urls)]
    try:
        res = session.get(target_url, timeout=5)
        print(f"[{elapsed:03d}s] Browsed: {target_url} -> Status {res.status_code} ({len(res.content)} bytes)")
    except Exception as e:
        print(f"[{elapsed:03d}s] Browsed: {target_url} -> {type(e).__name__}")
    
    req_idx += 1
    # Check stats periodically
    if req_idx % 4 == 0:
        s = requests.get(f"{BASE_URL}/api/stats").json()
        print(f"       -> SOC Stats: Flows: {s['total_flows']}, Active Alerts: {s['total_alerts']}, Pkts: {s.get('capture_status', {}).get('packet_count', 0)}")
    
    time.sleep(2.5)

print("\n[4] 120 seconds elapsed. Stopping live capture...")
r_stop = requests.post(f"{BASE_URL}/api/capture/stop")
print("Stop capture response:", r_stop.json())

# Allow 2 seconds for final flushed flows to process
time.sleep(2)

# Step 4: Extract and analyze all captured flows & predictions
print("\n=================================================================")
print("ANALYSIS OF CAPTURED LIVE TRAFFIC")
print("=================================================================")

stats = requests.get(f"{BASE_URL}/api/stats").json()
flows = requests.get(f"{BASE_URL}/api/flows?limit=500").json()
alerts = requests.get(f"{BASE_URL}/api/alerts?limit=500").json()

print(f"\nTotal Flows Captured: {len(flows)}")
print(f"Total Alerts Triggered: {len(alerts)}")

# Classification breakdown
label_counts: Dict[str, int] = {}
attack_confidences: Dict[str, List[float]] = {}
attack_flows: List[Dict[str, Any]] = []

for f in flows:
    lbl = f.get("predicted_label", "Unknown")
    conf = f.get("confidence", 0.0)
    label_counts[lbl] = label_counts.get(lbl, 0) + 1
    
    if lbl.lower() != "benign":
        if lbl not in attack_confidences:
            attack_confidences[lbl] = []
        attack_confidences[lbl].append(conf)
        attack_flows.append(f)

print("\n--- 1. FLOW CLASSIFICATION BREAKDOWN ---")
for lbl, count in sorted(label_counts.items(), key=lambda x: x[1], reverse=True):
    pct = (count / len(flows) * 100.0) if flows else 0.0
    print(f"  - {lbl:30s}: {count:4d} flows ({pct:5.1f}%)")

print("\n--- 2. NON-BENIGN CONFIDENCE DISTRIBUTION ---")
if attack_confidences:
    for lbl, confs in attack_confidences.items():
        arr = np.array(confs)
        print(f"  Attack Type: {lbl}")
        print(f"    Count: {len(arr)}")
        print(f"    Mean Confidence: {np.mean(arr):.4f}")
        print(f"    Min Confidence:  {np.min(arr):.4f}")
        print(f"    Max Confidence:  {np.max(arr):.4f}")
        print(f"    Median (50th%):  {np.median(arr):.4f}")
        print(f"    Percentiles [25th, 75th, 90th]: [{np.percentile(arr, 25):.4f}, {np.percentile(arr, 75):.4f}, {np.percentile(arr, 90):.4f}]")
else:
    print("  No non-Benign flows classified!")

print("\n--- 3. ALERT FEED AUDIT ---")
print(f"Total Alert Records Created: {len(alerts)}")
alert_attack_counts: Dict[str, int] = {}
for a in alerts:
    atk = a.get("attack_type", "Unknown")
    alert_attack_counts[atk] = alert_attack_counts.get(atk, 0) + 1

for atk, cnt in alert_attack_counts.items():
    print(f"  - Alert Attack: {atk:25s} | Count: {cnt}")

# Save detailed results to JSON for deep feature vector inspection
results_data = {
    "summary": {
        "total_flows": len(flows),
        "total_alerts": len(alerts),
        "label_counts": label_counts,
        "attack_confidence_stats": {
            lbl: {
                "count": len(confs),
                "mean": float(np.mean(confs)),
                "min": float(np.min(confs)),
                "max": float(np.max(confs)),
                "median": float(np.median(confs))
            } for lbl, confs in attack_confidences.items()
        }
    },
    "flows": flows[:50],
    "alerts": alerts[:50]
}

with open("scratch/live_browsing_experiment_results.json", "w") as f:
    json.dump(results_data, f, indent=2)

print("\nWrote full summary to scratch/live_browsing_experiment_results.json")
