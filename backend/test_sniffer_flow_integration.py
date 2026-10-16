from scapy.all import Ether, IP, TCP
from sniffer.sniffer import PacketSniffer


sniffer = PacketSniffer()

# Keep this test isolated from external side effects.
sniffer.alerts_enabled = False
sniffer.database.insert_traffic_log = lambda data: 1
sniffer.database.update_traffic_threat_score = lambda *args: None
sniffer.database.insert_attack_log = lambda data: None

# Simulate a critical SYN-flood flow.
sniffer.flow_analyzer.update_flow = lambda packet: {
    "flow_key": (
        "192.0.2.10", "192.0.2.20", 50000, 443, "TCP"
    ),
    "duration": 3.0,
    "packet_count": 200,
    "byte_count": 12800,
    "packet_rate": 66.67,
    "byte_rate": 4266.67,
    "average_packet_size": 64,
    "unique_src_ports": 1,
    "unique_dst_ports": 1,
    "avg_inter_arrival": 0.015,
    "idle_time": 0.02,
    "entropy_score": 0.0,
    "syn_flag_count": 200,
    "ack_flag_count": 2,
    "fin_flag_count": 0,
    "rst_flag_count": 0,
    "psh_flag_count": 0,
    "urg_flag_count": 0,
}

# Force deterministic ML output.
sniffer.predictor.predict = lambda features: {
    "label": "normal",
    "confidence": 0.95,
}

# Verify the flow rule detects the synthetic attack.
original_detect = sniffer.rule_engine.detect

def detect_flow(features):
    result = original_detect(features)
    assert result["attack_detected"] is True, result
    assert result["attack_type"] == "syn_flood"
    return result

sniffer.rule_engine.detect = detect_flow

# Capture the final response decision without executing real actions.
captured = {}

def fake_handle_decision(decision, packet):
    captured["decision"] = decision
    return {
        "action": decision["action"],
        "status": "Test dry-run",
        "block_success": False,
    }

sniffer.response_engine.handle_decision = fake_handle_decision

# Build one synthetic packet; no live capture is started.
packet = (
    Ether(src="02:00:00:00:00:10", dst="02:00:00:00:00:20")
    / IP(src="192.0.2.10", dst="192.0.2.20")
    / TCP(sport=50000, dport=443, flags="S")
)

sniffer.parse_packet(packet)

assert captured["decision"]["final_verdict"] == "MALICIOUS"
assert captured["decision"]["action"] == "BLOCK"

print("\nPASS: PacketSniffer used flow-level detection.")
print("PASS: Final decision was MALICIOUS / BLOCK.")
print("PASS: Real response actions and external alerts were not invoked.")