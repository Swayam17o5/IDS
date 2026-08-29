import urllib.request
import json

base_url = "http://127.0.0.1:8000"

with urllib.request.urlopen(f"{base_url}/api/models/active") as resp:
    print("Active Model Info:", json.loads(resp.read().decode()))

# Feature list template with 77 features
features_template = {
    "Destination Port": 80, "Flow Duration": 15000, "Total Fwd Packets": 10,
    "Total Backward Packets": 12, "Total Length of Fwd Packets": 800,
    "Total Length of Bwd Packets": 1500, "Fwd Packet Length Max": 200,
    "Fwd Packet Length Min": 40, "Fwd Packet Length Mean": 80.0,
    "Fwd Packet Length Std": 12.5, "Bwd Packet Length Max": 300,
    "Bwd Packet Length Min": 50, "Bwd Packet Length Mean": 125.0,
    "Bwd Packet Length Std": 22.1, "Flow Bytes/s": 153333.3,
    "Flow Packets/s": 1466.6, "Flow IAT Mean": 1200.0, "Flow IAT Std": 450.0,
    "Flow IAT Max": 3500.0, "Flow IAT Min": 100.0, "Fwd IAT Total": 14000.0,
    "Fwd IAT Mean": 1500.0, "Fwd IAT Std": 300.0, "Fwd IAT Max": 3000.0,
    "Fwd IAT Min": 200.0, "Bwd IAT Total": 14500.0, "Bwd IAT Mean": 1300.0,
    "Bwd IAT Std": 250.0, "Bwd IAT Max": 2800.0, "Bwd IAT Min": 150.0,
    "Fwd PSH Flags": 1, "Bwd PSH Flags": 0, "Fwd URG Flags": 0, "Bwd URG Flags": 0,
    "Fwd Header Length": 320, "Bwd Header Length": 384, "Fwd Packets/s": 666.6,
    "Bwd Packets/s": 800.0, "Min Packet Length": 40, "Max Packet Length": 300,
    "Packet Length Mean": 104.5, "Packet Length Std": 32.1, "Packet Length Variance": 1030.4,
    "FIN Flag Count": 0, "SYN Flag Count": 1, "RST Flag Count": 0, "PSH Flag Count": 1,
    "ACK Flag Count": 1, "URG Flag Count": 0, "CWE Flag Count": 0, "ECE Flag Count": 0,
    "Down/Up Ratio": 1.2, "Average Packet Size": 109.5, "Avg Fwd Segment Size": 80.0,
    "Avg Bwd Segment Size": 125.0, "Fwd Header Length.1": 320, "Fwd Avg Bytes/Bulk": 0,
    "Fwd Avg Packets/Bulk": 0, "Fwd Avg Bulk Rate": 0, "Bwd Avg Bytes/Bulk": 0,
    "Bwd Avg Packets/Bulk": 0, "Bwd Avg Bulk Rate": 0, "Subflow Fwd Packets": 10,
    "Subflow Fwd Bytes": 800, "Subflow Bwd Packets": 12, "Subflow Bwd Bytes": 1500,
    "Init_Win_bytes_forward": 29200, "Init_Win_bytes_backward": 28960,
    "act_data_pkt_fwd": 8, "min_seg_size_forward": 32, "Active Mean": 5000.0,
    "Active Std": 0.0, "Active Max": 5000.0, "Active Min": 5000.0,
    "Idle Mean": 10000.0, "Idle Std": 0.0, "Idle Max": 10000.0, "Idle Min": 10000.0
}

attacks = [
    {"name": "PortScan", "src": "192.168.1.105", "dst": "192.168.1.1", "port": 22},
    {"name": "DDoS", "src": "10.0.0.45", "dst": "192.168.1.1", "port": 80},
    {"name": "Web Attack - XSS", "src": "172.16.0.88", "dst": "192.168.1.1", "port": 443},
    {"name": "Bot", "src": "192.168.1.200", "dst": "198.51.100.12", "port": 8080},
]

print("\n--- Seeding Attack Telemetry to AegisNIDS Backend ---")
for atk in attacks:
    feats = dict(features_template)
    feats["Destination Port"] = atk["port"]
    payload = {
        "features": feats,
        "metadata": {
            "src_ip": atk["src"],
            "dst_ip": atk["dst"],
            "src_port": 54321,
            "dst_port": atk["port"],
            "protocol": 6
        }
    }
    req = urllib.request.Request(
        f"{base_url}/predict",
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"}
    )
    with urllib.request.urlopen(req) as resp:
        res = json.loads(resp.read().decode())
        print(f"[{atk['name']}] Predicted: {res['final_verdict']['predicted_label']} | Confidence: {res['final_verdict']['confidence']:.4f} | Alert ID: {res.get('alert_generated', {}).get('alert_id')}")

print("\nSeeding complete!")
