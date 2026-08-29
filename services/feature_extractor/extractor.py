import os
import json
import numpy as np
import pandas as pd
from typing import Dict, List, Any, Optional

try:
    from scapy.all import rdpcap, IP, TCP, UDP
except ImportError:
    pass

import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))

try:
    from services.feature_extractor.flow_aggregator import FlowAggregator
except ImportError:
    from flow_aggregator import FlowAggregator

class PCAPFeatureExtractor:
    """
    Extracts bidirectional network flow records from PCAP packets matching
    the exact 77-feature CICIDS2017 schema required by trained ML/DL models.
    """
    def __init__(self, feature_list_path: str = "models/cicids2017/feature_list.json"):
        self.feature_list_path = feature_list_path
        with open(feature_list_path, "r") as f:
            self.canonical_features = json.load(f)

    def extract_from_pcap(self, pcap_path: str) -> List[Dict[str, Any]]:
        if not os.path.exists(pcap_path):
            raise FileNotFoundError(f"PCAP file not found: {pcap_path}")
        
        packets = rdpcap(pcap_path)
        aggregator = FlowAggregator(self.feature_list_path, flow_timeout_seconds=120.0)
        
        extracted_flows = []
        for pkt in packets:
            if not pkt.haslayer(IP):
                continue
            
            ip_layer = pkt[IP]
            proto = ip_layer.proto
            src_ip = ip_layer.src
            dst_ip = ip_layer.dst
            
            src_port = 0
            dst_port = 0
            tcp_flags = 0
            win_size = 0
            hdr_len = 20
            
            if pkt.haslayer(TCP):
                tcp_layer = pkt[TCP]
                src_port = tcp_layer.sport
                dst_port = tcp_layer.dport
                tcp_flags = int(tcp_layer.flags)
                win_size = tcp_layer.window
                hdr_len = tcp_layer.dataofs * 4 if tcp_layer.dataofs else 20
            elif pkt.haslayer(UDP):
                udp_layer = pkt[UDP]
                src_port = udp_layer.sport
                dst_port = udp_layer.dport
                hdr_len = 8
            
            ts = float(pkt.time)
            length = len(pkt)
            
            completed = aggregator.process_packet(
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                proto=proto,
                length=length,
                timestamp=ts,
                tcp_flags=tcp_flags,
                win_size=win_size,
                header_len=hdr_len
            )
            if completed:
                extracted_flows.append(self._flatten_flow(completed))
                
        # Flush remaining flows
        for flow in aggregator.flush_all():
            extracted_flows.append(self._flatten_flow(flow))
            
        return extracted_flows

    def _flatten_flow(self, flow_dict: Dict[str, Any]) -> Dict[str, Any]:
        """Flattens metadata and features dict for legacy caller compatibility."""
        meta = flow_dict["metadata"]
        feats = flow_dict["features"]
        res = dict(feats)
        res["src_ip"] = meta["src_ip"]
        res["dst_ip"] = meta["dst_ip"]
        res["src_port"] = meta["src_port"]
        res["dst_port"] = meta["dst_port"]
        res["Protocol"] = meta["protocol"]
        return res

    def to_model_features(self, record: Dict[str, Any]) -> pd.DataFrame:
        """
        Converts extracted record into a single-row DataFrame with exact canonical feature order.
        """
        ordered_data = {feat: [record.get(feat, 0.0)] for feat in self.canonical_features}
        df = pd.DataFrame(ordered_data, dtype=np.float32)
        # Ensure no NaNs or Infs
        df = df.replace([np.inf, -np.inf], 0.0).fillna(0.0)
        return df

if __name__ == "__main__":
    import tempfile
    from scapy.all import Ether, IP, TCP, UDP, wrpcap

    print("=== TESTING PCAP FEATURE EXTRACTOR (SHARED AGGREGATOR) ===")
    with tempfile.TemporaryDirectory() as tmpdir:
        pcap_path = os.path.join(tmpdir, "test_traffic.pcap")
        
        # Craft multi-flow packets
        pkts = [
            # Flow 1: HTTP Client <-> Server
            Ether()/IP(src="192.168.1.100", dst="10.0.0.5")/TCP(sport=54321, dport=80, flags="S", seq=100, window=64240),
            Ether()/IP(src="10.0.0.5", dst="192.168.1.100")/TCP(sport=80, dport=54321, flags="SA", seq=500, ack=101, window=65535),
            Ether()/IP(src="192.168.1.100", dst="10.0.0.5")/TCP(sport=54321, dport=80, flags="A", seq=101, ack=501, window=64240),
            Ether()/IP(src="192.168.1.100", dst="10.0.0.5")/TCP(sport=54321, dport=80, flags="PA", seq=101, ack=501, window=64240)/b"GET /index.html HTTP/1.1\r\nHost: 10.0.0.5\r\n\r\n",
            Ether()/IP(src="10.0.0.5", dst="192.168.1.100")/TCP(sport=80, dport=54321, flags="PA", seq=501, ack=150, window=65535)/b"HTTP/1.1 200 OK\r\nContent-Length: 12\r\n\r\nHello World!",
            
            # Flow 2: DNS Query
            Ether()/IP(src="192.168.1.100", dst="8.8.8.8")/UDP(sport=49152, dport=53)/b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01",
            
            # Flow 3: SYN Scan Probe
            Ether()/IP(src="172.16.0.4", dst="192.168.1.1")/TCP(sport=44444, dport=22, flags="S", seq=999, window=1024),
            Ether()/IP(src="172.16.0.4", dst="192.168.1.1")/TCP(sport=44445, dport=23, flags="S", seq=999, window=1024),
            Ether()/IP(src="172.16.0.4", dst="192.168.1.1")/TCP(sport=44446, dport=443, flags="S", seq=999, window=1024)
        ]
        wrpcap(pcap_path, pkts)
        print(f"Generated test PCAP with {len(pkts)} packets at: {pcap_path}")

        extractor = PCAPFeatureExtractor("models/cicids2017/feature_list.json")
        flows = extractor.extract_from_pcap(pcap_path)
        print(f"Extracted {len(flows)} distinct network flows.")

        with open("models/cicids2017/feature_list.json") as f:
            expected_features = json.load(f)

        for i, flow in enumerate(flows):
            df = extractor.to_model_features(flow)
            assert df.shape == (1, 77), f"Expected shape (1, 77), got {df.shape}"
            assert list(df.columns) == expected_features, "Column ordering mismatch!"
            assert not df.isna().any().any(), "Found NaN in feature matrix!"
            assert not np.isinf(df.values).any(), "Found Inf in feature matrix!"
            
            print(f"  [Flow {i+1}] {flow['src_ip']}:{flow['src_port']} -> {flow['dst_ip']}:{flow['dst_port']} (Proto {flow['Protocol']}) | Packets: {flow['Total Fwd Packets'] + flow['Total Backward Packets']} | Vector Shape: {df.shape} [VALIDATED]")

    print("\n[SUCCESS] Feature extractor passed 100% strict schema validation!")
