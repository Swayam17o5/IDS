import os
import json
import pytest
from scapy.all import Ether, IP, TCP, wrpcap
from services.feature_extractor.extractor import PCAPFeatureExtractor

@pytest.fixture
def sample_pcap(tmp_path):
    pcap_file = tmp_path / "test_flow.pcap"
    # Create 4 synthetic packets representing a TCP conversation
    pkts = [
        Ether()/IP(src="192.168.1.10", dst="192.168.1.50")/TCP(sport=12345, dport=80, flags="S", seq=1000, window=8192),
        Ether()/IP(src="192.168.1.50", dst="192.168.1.10")/TCP(sport=80, dport=12345, flags="SA", seq=2000, ack=1001, window=8192),
        Ether()/IP(src="192.168.1.10", dst="192.168.1.50")/TCP(sport=12345, dport=80, flags="PA", seq=1001, ack=2001, window=8192)/b"GET / HTTP/1.1\r\n\r\n",
        Ether()/IP(src="192.168.1.50", dst="192.168.1.10")/TCP(sport=80, dport=12345, flags="PA", seq=2001, ack=1019, window=8192)/b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nHELLO"
    ]
    wrpcap(str(pcap_file), pkts)
    return str(pcap_file)

def test_pcap_extraction_flow_count(sample_pcap):
    extractor = PCAPFeatureExtractor("models/cicids2017/feature_list.json")
    flows = extractor.extract_from_pcap(sample_pcap)
    assert len(flows) == 1
    flow = flows[0]
    assert flow["src_ip"] == "192.168.1.10"
    assert flow["dst_ip"] == "192.168.1.50"
    assert flow["dst_port"] == 80
    assert flow["Protocol"] == 6.0
    assert flow["Total Fwd Packets"] == 2.0
    assert flow["Total Backward Packets"] == 2.0

def test_feature_vector_canonical_schema(sample_pcap):
    extractor = PCAPFeatureExtractor("models/cicids2017/feature_list.json")
    flows = extractor.extract_from_pcap(sample_pcap)
    df = extractor.to_model_features(flows[0])
    assert df.shape == (1, 77)
    with open("models/cicids2017/feature_list.json") as f:
        expected_cols = json.load(f)
    assert list(df.columns) == expected_cols
