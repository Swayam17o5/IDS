"""
3-WAY IAT_S CONTROLLED EXPERIMENT

For each of 3 IAT_S configurations:
1. Generate synthetic DoS Hulk PCAP
2. Replay through production FlowAggregator
3. Extract 77-feature vectors for all flows
4. Run XGBoost inference on all flows
5. Collect and compare results

Goal: Determine if IAT_S controls detection confidence
"""

import os
import sys
import json
import sqlite3
import time
import tempfile
import shutil
from typing import Dict, List, Any, Optional
import numpy as np
import pandas as pd
from dataclasses import dataclass, asdict

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

# Paths
DB_PATH = os.path.join(PROJECT_ROOT, "nids.db")
OUTPUT_DIR = os.path.dirname(__file__)
SCRATCH_DIR = os.path.join(PROJECT_ROOT, "scratch")

# Create backup of DB before experiment
DB_BACKUP_PATH = os.path.join(OUTPUT_DIR, "nids.db.pre_iat_experiment.backup")

@dataclass
class ExperimentConfig:
    """Configuration for one experiment variant."""
    name: str  # "A", "B", "C"
    iat_s_seconds: float
    description: str
    
@dataclass
class FlowStats:
    """Statistics extracted from a single flow."""
    flow_id: int
    prediction: str
    confidence: float
    flow_duration_us: float
    fwd_iat_mean_us: float
    bwd_iat_mean_us: float
    flow_iat_mean_us: float
    flow_bytes_per_s: float
    fwd_packets: int
    bwd_packets: int
    
def backup_database():
    """Create a backup of the database before experiment."""
    try:
        if os.path.exists(DB_PATH):
            print(f"Backing up database to {DB_BACKUP_PATH}...")
            shutil.copy2(DB_PATH, DB_BACKUP_PATH)
            print(f"[OK] Database backed up")
    except Exception as e:
        print(f"WARNING: Could not backup database: {e}")

def restore_database():
    """Restore database to pre-experiment state."""
    try:
        if os.path.exists(DB_BACKUP_PATH):
            print(f"Restoring database from backup...")
            shutil.copy2(DB_BACKUP_PATH, DB_PATH)
            print(f"✓ Database restored")
    except Exception as e:
        print(f"WARNING: Could not restore database: {e}")

def generate_dos_hulk_variant_pcap(iat_s: float, output_path: str) -> bool:
    """
    Generate a DoS Hulk PCAP with a specific IAT_S value.
    
    This temporarily modifies dos_hulk_demo.py, generates the PCAP, then restores it.
    """
    try:
        demo_path = os.path.join(PROJECT_ROOT, "services", "demo", "dos_hulk_demo.py")
        
        # Read original file
        with open(demo_path, "r") as f:
            original_content = f.read()
        
        # Temporarily modify IAT_S
        modified_content = original_content.replace(
            "IAT_S        = 0.000235",
            f"IAT_S        = {iat_s}"
        )
        
        # Write modified version
        with open(demo_path, "w") as f:
            f.write(modified_content)
        
        # Import and call the generator
        from services.demo.dos_hulk_demo import generate_dos_hulk_pcap
        
        # Force reimport to pick up new IAT_S
        import importlib
        import services.demo.dos_hulk_demo
        importlib.reload(services.demo.dos_hulk_demo)
        from services.demo.dos_hulk_demo import generate_dos_hulk_pcap as gen_func
        
        result = gen_func(output_path)
        print(f"  [OK] Generated PCAP with IAT_S={iat_s}: {output_path}")
        
        # Restore original file
        with open(demo_path, "w") as f:
            f.write(original_content)
        
        return True
        
    except Exception as e:
        print(f"  ERROR generating PCAP: {e}")
        # Restore original file in case of error
        try:
            with open(demo_path, "w") as f:
                f.write(original_content)
        except:
            pass
        return False

def replay_pcap_and_extract_flows(pcap_path: str, config_name: str) -> List[Dict]:
    """
    Replay a PCAP through the production FlowAggregator and extract flow statistics.
    """
    try:
        from services.feature_extractor.flow_aggregator import FlowAggregator
        from scapy.all import rdpcap, IP, TCP
        
        print(f"  Replaying PCAP: {pcap_path}")
        packets = rdpcap(pcap_path)
        print(f"  Loaded {len(packets)} packets")
        
        # Create aggregator with correct parameters
        feature_list_path = os.path.join(PROJECT_ROOT, "models", "cicids2017", "feature_list.json")
        aggregator = FlowAggregator(canonical_features_path=feature_list_path, flow_timeout_seconds=120.0)
        
        # Feed packets to aggregator
        completed_flows = []
        for i, pkt in enumerate(packets):
            # Extract IP and TCP info
            if IP in pkt:
                ip_layer = pkt[IP]
                src_ip = str(ip_layer.src)
                dst_ip = str(ip_layer.dst)
                proto = ip_layer.proto
                pkt_len = len(pkt)
                # Convert Scapy EDecimal timestamp to plain float
                timestamp = float(pkt.time)
                
                # Extract TCP info if present
                tcp_flags = 0
                src_port = 0
                dst_port = 0
                win_size = 0
                
                if TCP in pkt:
                    tcp_layer = pkt[TCP]
                    src_port = int(tcp_layer.sport)
                    dst_port = int(tcp_layer.dport)
                    tcp_flags = int(tcp_layer.flags)
                    win_size = int(tcp_layer.window) if hasattr(tcp_layer, 'window') else 0
                    # Extract TCP header length
                    header_len = int(tcp_layer.dataofs * 4) if hasattr(tcp_layer, 'dataofs') else 20
                else:
                    header_len = 20
                
                # Process the packet
                flow_dict = aggregator.process_packet(
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    src_port=src_port,
                    dst_port=dst_port,
                    proto=proto,
                    length=pkt_len,
                    timestamp=timestamp,
                    tcp_flags=tcp_flags,
                    win_size=win_size,
                    header_len=header_len
                )
                
                if flow_dict is not None:
                    completed_flows.append(flow_dict)
        
        print(f"  [OK] Extracted {len(completed_flows)} flows from PCAP")
        return completed_flows
        
    except Exception as e:
        print(f"  ERROR replaying PCAP: {e}")
        import traceback
        traceback.print_exc()
        return []

def run_xgboost_inference_on_flows(flows: List[Dict], config_name: str) -> List[Dict]:
    """
    Run XGBoost inference on extracted flows.
    """
    try:
        import xgboost as xgb
        import pickle
        from services.inference.app import LABEL_MAPPING
        
        model_path = os.path.join(PROJECT_ROOT, "models", "cicids2017", "xgboost_cicids2017.pkl")
        feature_list_path = os.path.join(PROJECT_ROOT, "models", "cicids2017", "feature_list.json")
        
        # Load model and features
        with open(model_path, "rb") as f:
            model = pickle.load(f)
        
        with open(feature_list_path, "r") as f:
            feature_list = json.load(f)
        
        print(f"  Running XGBoost inference on {len(flows)} flows...")
        
        results = []
        for i, flow_dict in enumerate(flows):
            # Extract features in order
            feature_values = [flow_dict.get(f, 0.0) for f in feature_list]
            X = np.array([feature_values], dtype=np.float32)
            
            # Predict
            try:
                proba = model.predict_proba(X)[0]
                pred_class = int(np.argmax(proba))
                pred_label = LABEL_MAPPING.get(pred_class, f"Class_{pred_class}")
                confidence = float(proba[pred_class])
                
                results.append({
                    "flow_id": i,
                    "predicted_label": pred_label,
                    "predicted_class": pred_class,
                    "confidence": confidence,
                    "probabilities": {LABEL_MAPPING.get(j, f"Class_{j}"): float(proba[j]) for j in range(len(proba))}
                })
            except Exception as e:
                print(f"    Warning: Inference failed for flow {i}: {e}")
                results.append({
                    "flow_id": i,
                    "predicted_label": "ERROR",
                    "predicted_class": -1,
                    "confidence": 0.0,
                    "error": str(e)
                })
        
        print(f"  [OK] Inference complete")
        return results
        
    except Exception as e:
        print(f"  ERROR running inference: {e}")
        import traceback
        traceback.print_exc()
        return []

def run_single_variant(config: ExperimentConfig) -> Dict[str, Any]:
    """Run the complete experiment for one IAT_S variant."""
    print(f"\n{'='*80}")
    print(f"VARIANT {config.name}: {config.description}")
    print(f"IAT_S = {config.iat_s_seconds}")
    print(f"{'='*80}")
    
    pcap_path = os.path.join(SCRATCH_DIR, f"iat_test_variant_{config.name}.pcap")
    
    # Step 1: Generate PCAP
    print(f"\n[1/3] Generating PCAP with IAT_S={config.iat_s_seconds}...")
    if not generate_dos_hulk_variant_pcap(config.iat_s_seconds, pcap_path):
        return {"config": asdict(config), "error": "Failed to generate PCAP"}
    
    # Step 2: Replay and extract flows
    print(f"[2/3] Replaying PCAP through FlowAggregator...")
    flows_feature_dicts = replay_pcap_and_extract_flows(pcap_path, config.name)
    if not flows_feature_dicts:
        return {"config": asdict(config), "error": "Failed to extract flows"}
    
    # Step 3: Run inference
    print(f"[3/3] Running XGBoost inference...")
    inference_results = run_xgboost_inference_on_flows(flows_feature_dicts, config.name)
    
    # Compile results
    result = {
        "config": asdict(config),
        "pcap_path": pcap_path,
        "flows_generated": len(flows_feature_dicts),
        "inference_results": inference_results,
        "flow_features": flows_feature_dicts,
        "summary": {
            "total_flows": len(flows_feature_dicts),
            "dos_hulk_predictions": sum(1 for r in inference_results if "DoS" in r.get("predicted_label", "")),
            "benign_predictions": sum(1 for r in inference_results if r.get("predicted_label") == "Benign"),
            "avg_confidence": np.mean([r.get("confidence", 0.0) for r in inference_results]) if inference_results else 0.0,
            "dos_hulk_avg_confidence": np.mean([r.get("confidence", 0.0) for r in inference_results if "DoS" in r.get("predicted_label", "")]) if any("DoS" in r.get("predicted_label", "") for r in inference_results) else 0.0
        }
    }
    
    # Print summary
    print(f"\n[SUMMARY] Variant {config.name}:")
    print(f"  Total Flows: {result['summary']['total_flows']}")
    print(f"  DoS Hulk Predictions: {result['summary']['dos_hulk_predictions']}")
    print(f"  Benign Predictions: {result['summary']['benign_predictions']}")
    print(f"  Average Confidence: {result['summary']['avg_confidence']:.4f}")
    if result['summary']['dos_hulk_avg_confidence'] > 0:
        print(f"  DoS Hulk Avg Confidence: {result['summary']['dos_hulk_avg_confidence']:.4f}")
    
    return result

def main():
    print("="*80)
    print("3-WAY IAT_S CONTROLLED EXPERIMENT")
    print("="*80)
    
    # Define the 3 variants
    configs = [
        ExperimentConfig(
            name="A",
            iat_s_seconds=0.000235,
            description="Current (baseline) - IAT_S=235µs"
        ),
        ExperimentConfig(
            name="B",
            iat_s_seconds=6.5,
            description="Claimed fix - IAT_S=6.5s"
        ),
        ExperimentConfig(
            name="C",
            iat_s_seconds=0.490461,
            description="Genuine median - IAT_S=490.461ms"
        ),
    ]
    
    # Backup database
    backup_database()
    
    # Run all 3 variants
    all_results = {}
    for config in configs:
        result = run_single_variant(config)
        all_results[config.name] = result
    
    # Save results
    output_file = os.path.join(OUTPUT_DIR, "iat_3way_results.json")
    with open(output_file, "w") as f:
        json.dump(all_results, f, indent=2)
    print(f"\n[OK] Results saved to: {output_file}")
    
    # Print comparison
    print(f"\n{'='*80}")
    print("COMPARISON ACROSS VARIANTS")
    print(f"{'='*80}")
    for name, result in all_results.items():
        if "error" in result:
            print(f"Variant {name}: ERROR - {result['error']}")
        else:
            print(f"Variant {name} (IAT_S={result['config']['iat_s_seconds']}):")
            print(f"  DoS Hulk predictions: {result['summary']['dos_hulk_predictions']}/{result['summary']['total_flows']}")
            print(f"  Average confidence: {result['summary']['avg_confidence']:.4f}")

if __name__ == "__main__":
    main()
