from sniffer.flow_analyzer import FlowAnalyzer
from integration.traffic_adapter import TrafficAdapter
from ml.feature_extractor import FeatureExtractor
from ml.predictor import NIDSPredictor

analyzer = FlowAnalyzer()
adapter = TrafficAdapter()
extractor = FeatureExtractor()
predictor = NIDSPredictor()

packet = {
    "src_ip": "192.168.1.10",
    "dst_ip": "192.168.1.20",
    "src_port": 50000,
    "dst_port": 443,
    "protocol": "TCP",
    "packet_size": 500,
    "ttl": 64,
    "tcp_flags": "S",
    "icmp_type": None
}

flow_features = analyzer.update_flow(packet)

packet_data = adapter.adapt_packet({
    "source_ip": packet["src_ip"],
    "destination_ip": packet["dst_ip"],
    "source_port": packet["src_port"],
    "destination_port": packet["dst_port"],
    "protocol": packet["protocol"],
    "packet_size": packet["packet_size"],
    "ttl": packet["ttl"],
    "tcp_flags": packet["tcp_flags"],
    "icmp_type": packet["icmp_type"]
})

flow_data = adapter.adapt_flow(flow_features)

features = extractor.extract_features(
    packet_data,
    flow_data
)

result = predictor.predict(features)

print("\n" + "=" * 60)
print("LIVE ML PREDICTION TEST")
print("=" * 60)

print(f"Prediction : {result['label']}")
print(f"Confidence : {result['confidence']:.4f}")

print("=" * 60)