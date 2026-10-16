from rules.rule_engine import RuleEngine

rule_engine = RuleEngine()

features = {
    "src_ip": "192.168.1.10",
    "dst_ip": "192.168.1.20",
    "protocol": "TCP",
    "packet_count": 200,
    "flow_duration": 3.0,
    "syn_flag_count": 200,
    "ack_flag_count": 2,
    "syn_ratio": 0.97,
    "average_packet_size": 500,
    "unique_dst_ports": 1,
    "packet_rate": 50,
    "byte_count": 75000,
    "dst_port": 443,
    "failed_connections": 0,
    "dns_query_count": 0,
}

result = rule_engine.detect(features)
rule_engine.display_alert(result)

assert result["attack_detected"] is True
assert result["attack_type"] == "syn_flood"
assert result["threat_score"] == 98

print("\nPASS: Flow-level SYN flood detection works.")