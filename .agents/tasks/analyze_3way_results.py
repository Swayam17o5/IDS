"""
Analyze the results from the 3-way IAT_S controlled experiment
"""

import json
import os
import sys
from typing import Dict, List, Any

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

OUTPUT_DIR = os.path.dirname(__file__)
RESULTS_FILE = os.path.join(OUTPUT_DIR, "iat_3way_results.json")
LABEL_MAPPING_FILE = os.path.join(PROJECT_ROOT, "models", "cicids2017", "label_mapping.json")

def load_label_mapping() -> Dict[int, str]:
    """Load the label mapping from file."""
    try:
        with open(LABEL_MAPPING_FILE, "r") as f:
            mapping = json.load(f)
        # Convert string keys to integers
        return {int(k): v for k, v in mapping.items()}
    except Exception as e:
        print(f"ERROR loading label mapping: {e}")
        return {}

def analyze_results():
    """Analyze and compare the 3-way experiment results."""
    
    with open(RESULTS_FILE, "r") as f:
        all_results = json.load(f)
    
    label_mapping = load_label_mapping()
    
    print("=" * 80)
    print("3-WAY IAT_S EXPERIMENT ANALYSIS")
    print("=" * 80)
    
    # Compare variants
    comparison_data = {}
    for variant_name in ["A", "B", "C"]:
        if variant_name not in all_results:
            continue
        
        variant = all_results[variant_name]
        config = variant["config"]
        summary = variant["summary"]
        inference_results = variant["inference_results"]
        
        # Analyze predictions
        class_counts = {}
        dos_hulk_flows = []
        benign_flows = []
        
        for result in inference_results:
            pred_class = result["predicted_class"]
            pred_label = label_mapping.get(pred_class, f"Unknown_{pred_class}")
            confidence = result["confidence"]
            
            # Count by class
            class_counts[pred_label] = class_counts.get(pred_label, 0) + 1
            
            # Collect DoS Hulk predictions
            if pred_class == 4:  # DoS Hulk
                dos_hulk_flows.append({
                    "flow_id": result["flow_id"],
                    "confidence": confidence,
                    "probabilities": result["probabilities"]
                })
            elif pred_class == 0:  # Benign
                benign_flows.append({
                    "flow_id": result["flow_id"],
                    "confidence": confidence,
                    "probabilities": result["probabilities"]
                })
        
        comparison_data[variant_name] = {
            "iat_s": config["iat_s_seconds"],
            "class_distribution": class_counts,
            "dos_hulk_predictions": len(dos_hulk_flows),
            "benign_predictions": len(benign_flows),
            "dos_hulk_avg_confidence": sum(f["confidence"] for f in dos_hulk_flows) / len(dos_hulk_flows) if dos_hulk_flows else 0.0,
            "benign_avg_confidence": sum(f["confidence"] for f in benign_flows) / len(benign_flows) if benign_flows else 0.0,
            "dos_hulk_flows": dos_hulk_flows,
            "benign_flows": benign_flows
        }
        
        print(f"\nVARIANT {variant_name} (IAT_S = {config['iat_s_seconds']}):")
        print(f"  Description: {config['description']}")
        print(f"  Total Flows: {summary['total_flows']}")
        print(f"  Class Distribution:")
        for cls, count in sorted(class_counts.items()):
            print(f"    {cls}: {count}")
        print(f"  DoS Hulk Predictions: {len(dos_hulk_flows)}/15")
        if dos_hulk_flows:
            print(f"    Average Confidence: {comparison_data[variant_name]['dos_hulk_avg_confidence']:.6f}")
            for flow in dos_hulk_flows:
                print(f"    Flow {flow['flow_id']}: {flow['confidence']:.6f}")
        print(f"  Benign Predictions: {len(benign_flows)}/15")
        if benign_flows:
            print(f"    Average Confidence: {comparison_data[variant_name]['benign_avg_confidence']:.6f}")
    
    # Key findings
    print(f"\n{'='*80}")
    print("KEY FINDINGS")
    print(f"{'='*80}")
    
    dos_hulk_counts = [comparison_data[v]["dos_hulk_predictions"] for v in ["A", "B", "C"]]
    print(f"\nDoS Hulk Predictions by Variant:")
    print(f"  Variant A (IAT_S=235µs):     {dos_hulk_counts[0]}/15")
    print(f"  Variant B (IAT_S=6.5s):       {dos_hulk_counts[1]}/15")
    print(f"  Variant C (IAT_S=490.461ms):  {dos_hulk_counts[2]}/15")
    
    if dos_hulk_counts[0] == dos_hulk_counts[1] == dos_hulk_counts[2]:
        if dos_hulk_counts[0] == 0:
            print(f"\n[CRITICAL] All three variants have ZERO DoS Hulk predictions!")
            print(f"  CONCLUSION: IAT_S is NOT controlling the DoS Hulk detection.")
            print(f"  EVIDENCE: Changing IAT_S from 235µs → 6.5s → 490.461ms")
            print(f"            produced NO change in predictions (all Benign).")
            print(f"\n  IMPLICATION: The synthetic PCAP has other fundamental issues")
            print(f"               that make it impossible to detect as DoS Hulk,")
            print(f"               regardless of IAT_S value.")
        else:
            print(f"\n[FINDING] All three variants have {dos_hulk_counts[0]} DoS Hulk predictions.")
            print(f"  CONCLUSION: IAT_S changes do not affect prediction count.")
            print(f"              But at least some DoS Hulk detection is occurring.")
    else:
        print(f"\n[FINDING] Different prediction counts across variants:")
        if dos_hulk_counts[1] > dos_hulk_counts[0]:
            improvement = dos_hulk_counts[1] - dos_hulk_counts[0]
            print(f"  Variant B improved over Variant A by {improvement} predictions.")
            print(f"  TENTATIVE: IAT_S=6.5s may help DoS Hulk detection.")
        if dos_hulk_counts[2] > dos_hulk_counts[0]:
            improvement = dos_hulk_counts[2] - dos_hulk_counts[0]
            print(f"  Variant C improved over Variant A by {improvement} predictions.")
            print(f"  TENTATIVE: IAT_S=490.461ms may help DoS Hulk detection.")
    
    # Save analysis
    analysis_output = {
        "experiment": "3-way IAT_S controlled test",
        "comparison_data": comparison_data,
        "conclusion": {
            "iat_s_is_root_cause": any(dos_hulk_counts[i] != dos_hulk_counts[0] for i in range(1, 3)),
            "dos_hulk_predictions_equal": dos_hulk_counts[0] == dos_hulk_counts[1] == dos_hulk_counts[2],
            "all_zero": dos_hulk_counts[0] == 0,
        }
    }
    
    analysis_file = os.path.join(OUTPUT_DIR, "iat_3way_analysis.json")
    with open(analysis_file, "w") as f:
        json.dump(analysis_output, f, indent=2)
    
    print(f"\n[OK] Analysis saved to: {analysis_file}")

if __name__ == "__main__":
    analyze_results()
