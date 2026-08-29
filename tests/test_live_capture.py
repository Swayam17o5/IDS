import os
import time
import pytest
from fastapi.testclient import TestClient
from services.inference.app import app, init_models
from services.feature_extractor.flow_aggregator import FlowAggregator
from services.feature_extractor.live_capture import (
    check_capture_capabilities,
    get_available_interfaces,
    LiveCaptureService
)

@pytest.fixture(scope="module")
def client():
    init_models("cicids2017")
    return TestClient(app)

def test_flow_aggregator_packet_processing():
    aggregator = FlowAggregator("models/cicids2017/feature_list.json", flow_timeout_seconds=0.5)
    
    # 1. Forward SYN Packet
    completed = aggregator.process_packet(
        src_ip="192.168.1.50",
        dst_ip="10.0.0.1",
        src_port=40000,
        dst_port=80,
        proto=6,
        length=60,
        timestamp=100.0,
        tcp_flags=0x02, # SYN
        win_size=64240,
        header_len=20
    )
    assert completed is None, "Flow should not be closed on SYN"
    assert len(aggregator.active_flows) == 1

    # 2. Backward SYN-ACK Packet
    completed = aggregator.process_packet(
        src_ip="10.0.0.1",
        dst_ip="192.168.1.50",
        src_port=80,
        dst_port=40000,
        proto=6,
        length=60,
        timestamp=100.05,
        tcp_flags=0x12, # SYN-ACK
        win_size=65535,
        header_len=20
    )
    assert completed is None
    assert len(aggregator.active_flows) == 1

    # 3. Forward FIN Packet (Closes Flow)
    completed = aggregator.process_packet(
        src_ip="192.168.1.50",
        dst_ip="10.0.0.1",
        src_port=40000,
        dst_port=80,
        proto=6,
        length=54,
        timestamp=100.1,
        tcp_flags=0x01, # FIN
        win_size=64240,
        header_len=20
    )
    assert completed is not None, "Flow should complete upon receiving FIN"
    assert completed["metadata"]["src_ip"] == "192.168.1.50"
    assert completed["metadata"]["dst_ip"] == "10.0.0.1"
    assert completed["metadata"]["total_packets"] == 3
    assert len(completed["features"]) == 77
    assert len(aggregator.active_flows) == 0

def test_flow_aggregator_timeout_flush():
    aggregator = FlowAggregator("models/cicids2017/feature_list.json", flow_timeout_seconds=0.2)
    aggregator.process_packet(
        src_ip="10.0.0.5",
        dst_ip="8.8.8.8",
        src_port=5353,
        dst_port=53,
        proto=17,
        length=85,
        timestamp=200.0
    )
    assert len(aggregator.active_flows) == 1

    # No flush if timestamp is within timeout
    flushed = aggregator.flush_expired_flows(current_time=200.1)
    assert len(flushed) == 0

    # Flush when time exceeds timeout
    flushed = aggregator.flush_expired_flows(current_time=200.3)
    assert len(flushed) == 1
    assert flushed[0]["metadata"]["src_ip"] == "10.0.0.5"
    assert len(aggregator.active_flows) == 0

def test_capture_capabilities_structure():
    caps = check_capture_capabilities()
    assert "scapy_available" in caps
    assert "is_admin" in caps
    assert "has_pcap_driver" in caps
    assert "can_capture_live" in caps
    assert "status_message" in caps

def test_available_interfaces_enumeration():
    ifaces = get_available_interfaces()
    assert len(ifaces) >= 1
    # Loopback must be present as safety default
    loopbacks = [i for i in ifaces if i["id"] == "loopback"]
    assert len(loopbacks) == 1
    assert loopbacks[0]["ip"] == "127.0.0.1"

def test_capture_api_endpoints(client):
    # 1. Capabilities
    res = client.get("/api/capture/capabilities")
    assert res.status_code == 200
    assert "has_pcap_driver" in res.json()

    # 2. Interfaces
    res = client.get("/api/capture/interfaces")
    assert res.status_code == 200
    assert isinstance(res.json(), list)
    assert len(res.json()) > 0

    # 3. Status
    res = client.get("/api/capture/status")
    assert res.status_code == 200
    data = res.json()
    assert data["active_mode"] in ["REPLAY_MODE", "LIVE_CAPTURE"]
