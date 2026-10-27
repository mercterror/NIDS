from sniffer.flow_analyzer import FlowAnalyzer

analyzer = FlowAnalyzer()

packet = {
    "src_ip": "192.168.1.10",
    "dst_ip": "192.168.1.20",
    "src_port": 50000,
    "dst_port": 443,
    "protocol": "TCP",
    "packet_size": 500,
    "tcp_flags": "S"
}

features = analyzer.update_flow(packet)

print("\n" + "=" * 60)
print("FLOW ANALYZER TEST")
print("=" * 60)

for key, value in features.items():
    print(f"{key:<20}: {value}")

print("=" * 60)