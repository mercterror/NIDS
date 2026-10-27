
from ml.feature_extractor import FeatureExtractor

extractor = FeatureExtractor()

packet_data = {
    "source_ip": "192.168.1.100",
    "destination_ip": "192.168.1.50",
    "source_port": 51514,
    "destination_port": 443,
    "protocol": "TCP",
    "packet_size": 512,
    "ttl": 64,
}

flow_features = {
    "duration": 5.0,
    "packet_count": 10,
    "byte_count": 5120,
    "packet_rate": 2.0,
    "byte_rate": 1024.0,
    "average_packet_size": 512.0,
    "unique_src_ports": 1,
    "unique_dst_ports": 1,
    "entropy_score": 0.5,
    "avg_inter_arrival": 0.5,
    "idle_time": 0.0,
    "syn_flag_count": 1,
    "ack_flag_count": 8,
    "fin_flag_count": 0,
    "rst_flag_count": 0,
    "psh_flag_count": 5,
    "urg_flag_count": 0,
}

features = extractor.extract_features(packet_data, flow_features)

if features is None:
    print("FAIL: Feature extraction returned None")
else:
    print("Feature count:", len(features))
    print("Protocol:", features["protocol"])
    print("SYN ratio:", features["syn_ratio"])
    print("Average packet size:", features["average_packet_size"])

    required = [
        "src_port", "dst_port", "protocol", "packet_size", "ttl",
        "flow_duration", "packet_count", "byte_count", "packet_rate",
        "byte_rate", "unique_src_ports", "unique_dst_ports",
        "entropy_score", "inter_arrival_time", "syn_flag_count",
        "ack_flag_count", "fin_flag_count", "rst_flag_count",
        "psh_flag_count", "urg_flag_count", "dns_query_count",
        "failed_connections", "arp_requests",
    ]

    missing = [key for key in required if key not in features]

    print("Missing model features:", missing)
    print("TEST PASSED" if not missing else "TEST FAILED")
