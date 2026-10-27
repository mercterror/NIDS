from integration.detection_pipeline import DetectionPipeline


pipeline = DetectionPipeline()


packet = {
    "flow_id": "TEST-MALICIOUS",
    "packet_number": 1,
    "timestamp": "2026-10-06 12:00:00",
    "direction": "Client → Server",
    "source_ip": "192.168.1.10",
    "destination_ip": "192.168.1.20",
    "source_mac": "AA:BB:CC:11:22:33",
    "destination_mac": "DD:EE:FF:44:55:66",
    "source_port": 50000,
    "destination_port": 23,
    "protocol": "TCP",
    "packet_size": 1500,
    "ttl": 64,
    "tcp_flags": "S",
    "icmp_type": None
}


flow = {
    "duration": 0.1,
    "packet_count": 1,
    "byte_count": 1500,
    "packet_rate": 10,
    "byte_rate": 15000,
    "average_packet_size": 1500,
    "unique_src_ports": 1,
    "unique_dst_ports": 1,
    "entropy_score": 0.0,
    "avg_inter_arrival": 0,
    "idle_time": 0,
    "syn_flag_count": 1,
    "ack_flag_count": 0,
    "fin_flag_count": 0,
    "rst_flag_count": 0,
    "psh_flag_count": 0,
    "urg_flag_count": 0
}


result = pipeline.analyze(
    packet,
    flow
)


print("\n" + "=" * 60)
print("MALICIOUS DETECTION TEST")
print("=" * 60)

print("\nRule Detection:")
print(f"Score       : {result['rule_detection']['score']}")
print(f"Suspicious  : {result['rule_detection']['is_suspicious']}")
print(f"Reasons     : {result['rule_detection']['reasons']}")

print("\nAI Detection:")
print(f"Prediction  : {result['ai_detection']['label']}")
print(
    f"Confidence  : "
    f"{result['ai_detection']['confidence']:.4f}"
)

print("\nFinal Decision:")
print(f"Verdict     : {result['final_verdict']}")
print(f"Action      : {result['action']}")

print("=" * 60)