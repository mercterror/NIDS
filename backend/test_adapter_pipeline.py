
from integration.traffic_adapter import TrafficAdapter
from ml.feature_extractor import FeatureExtractor

adapter = TrafficAdapter()
extractor = FeatureExtractor()

packet_data = {
    "src_ip": "192.168.1.100",
    "dst_ip": "192.168.1.50",
    "src_port": 51514,
    "dst_port": 443,
    "protocol": "TCP",
    "packet_size": 512,
    "ttl": 64,
    "tcp_flags": "PA",
    "icmp_type": None,
}

flow_features = {
    "flow_key": ("192.168.1.100", "192.168.1.50", 51514, 443, "TCP"),
    "duration": 5.0,
    "packet_count": 10,
    "byte_count": 5120,
    "packet_rate": 2.0,
    "byte_rate": 1024.0,
    "average_packet_size": 512.0,
    "unique_src_ports": 1,
    "unique_dst_ports": 1,
    "entropy_score": 0.0,
    "avg_inter_arrival": 0.5,
    "idle_time": 0.5,
    "syn_flag_count": 1,
    "ack_flag_count": 8,
    "fin_flag_count": 0,
    "rst_flag_count": 0,
    "psh_flag_count": 5,
    "urg_flag_count": 0,
}

adapted_packet = adapter.adapt_packet(packet_data)
adapted_flow = adapter.adapt_flow(flow_features)

features = extractor.extract_features(adapted_packet, adapted_flow)

print("Adapted source IP:", adapted_packet["source_ip"])
print("Adapted destination IP:", adapted_packet["destination_ip"])
print("Extracted protocol:", features["protocol"])
print("Extracted packet count:", features["packet_count"])
print("Extracted SYN ratio:", features["syn_ratio"])
print("Feature count:", len(features))
print("Pipeline test:", "PASSED" if features is not None else "FAILED")
