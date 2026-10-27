from ml.feature_extractor import FeatureExtractor
from ml.predictor import NIDSPredictor

predictor = NIDSPredictor()
extractor = FeatureExtractor()

attack_tests = [
    ("SYN Flood", {
        "syn_flag_count": 150,
        "ack_flag_count": 2,
        "fin_flag_count": 0,
        "rst_flag_count": 0,
        "psh_flag_count": 0,
        "urg_flag_count": 0,
        "packet_rate": 150,
        "dns_query_count": 0,
        "failed_connections": 0,
        "arp_requests": 0,
    }),

    ("ICMP Flood", {
        "syn_flag_count": 0,
        "ack_flag_count": 0,
        "fin_flag_count": 0,
        "rst_flag_count": 0,
        "psh_flag_count": 0,
        "urg_flag_count": 0,
        "packet_rate": 250,
        "dns_query_count": 0,
        "failed_connections": 0,
        "arp_requests": 0,
    }),

    ("DNS Abuse", {
        "syn_flag_count": 0,
        "ack_flag_count": 0,
        "fin_flag_count": 0,
        "rst_flag_count": 0,
        "psh_flag_count": 0,
        "urg_flag_count": 0,
        "packet_rate": 50,
        "dns_query_count": 150,
        "failed_connections": 0,
        "arp_requests": 0,
    }),

    ("ARP Spoofing", {
        "syn_flag_count": 0,
        "ack_flag_count": 0,
        "fin_flag_count": 0,
        "rst_flag_count": 0,
        "psh_flag_count": 0,
        "urg_flag_count": 0,
        "packet_rate": 20,
        "dns_query_count": 0,
        "failed_connections": 0,
        "arp_requests": 60,
    }),

    ("Brute Force", {
        "syn_flag_count": 50,
        "ack_flag_count": 0,
        "fin_flag_count": 0,
        "rst_flag_count": 0,
        "psh_flag_count": 0,
        "urg_flag_count": 0,
        "packet_rate": 50,
        "dns_query_count": 0,
        "failed_connections": 50,
        "arp_requests": 0,
    }),

    ("Port Scan", {
        "syn_flag_count": 20,
        "ack_flag_count": 0,
        "fin_flag_count": 0,
        "rst_flag_count": 0,
        "psh_flag_count": 0,
        "urg_flag_count": 0,
        "packet_rate": 20,
        "dns_query_count": 0,
        "failed_connections": 0,
        "arp_requests": 0,
    }),
]

confidences = []

print("\n" + "=" * 60)
print("AI ATTACK CONFIDENCE TEST")
print("=" * 60)

for name, attack_values in attack_tests:

    features = {
        "src_port": 50000,
        "dst_port": 443,
        "protocol": "TCP",
        "packet_size": 500,
        "ttl": 64,
        "flow_duration": 1.0,
        "packet_count": 100,
        "byte_count": 50000,
        "packet_rate": 100,
        "byte_rate": 50000,
        "unique_src_ports": 1,
        "unique_dst_ports": 1,
        "entropy_score": 0,
        "inter_arrival_time": 0.01,
        "fin_flag_count": 0,
        "rst_flag_count": 0,
        "psh_flag_count": 0,
        "urg_flag_count": 0,
        "syn_ratio": 0,
        "ack_ratio": 0,
        "average_packet_size": 500,
        "idle_time": 0.01,
    }

    features.update(attack_values)

    result = predictor.predict(features)

    print(f"\n{name}")
    print(f"Prediction  : {result['label']}")
    print(f"Confidence  : {result['confidence']:.4f}")

    if result["label"] != "normal":
        confidences.append(result["confidence"])

    if confidences:
        average = sum(confidences) / len(confidences)

        print("\n" + "=" * 60)
        print("CONFIDENCE SUMMARY")
        print("=" * 60)
        print(f"Attack samples tested : {len(confidences)}")
        print(f"Average confidence    : {average:.4f}")
        print(f"Minimum confidence    : {min(confidences):.4f}")
        print(f"Maximum confidence    : {max(confidences):.4f}")
        print("=" * 60)