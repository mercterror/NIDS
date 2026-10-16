from scapy.all import Ether, IP, TCP
from sniffer.sniffer import PacketSniffer
import sniffer.sniffer as sniffer_module

sniffer = PacketSniffer(interface=None)

# Keep blocking in simulation mode
assert sniffer.response_engine.dry_run is True

# Force the rule detector to report suspicious traffic.
# This tests the response path, not the detection model.
original_analyze_packet = sniffer_module.analyze_packet

sniffer_module.analyze_packet = lambda packet: {
    "score": 100,
    "is_suspicious": True,
    "reasons": ["Controlled integration test"]
}

# Capture the actual final decision and response result.
captured = {}
original_handle_decision = sniffer.response_engine.handle_decision

def capture_response(decision, response_packet):
    result = original_handle_decision(decision, response_packet)
    captured["decision"] = decision
    captured["response"] = result
    return result

sniffer.response_engine.handle_decision = capture_response

try:
    packet = (
        Ether(
            src="AA:BB:CC:DD:EE:FF",
            dst="11:22:33:44:55:66"
        )
        / IP(
            src="192.0.2.10",
            dst="198.51.100.20"
        )
        / TCP(
            sport=45678,
            dport=80,
            flags="S"
        )
    )

    print("\n--- SYNTHETIC BLOCK RESPONSE TEST ---")

    packet_data, flow_features = sniffer.parse_packet(packet)

    assert sniffer.response_engine.dry_run is True
    assert captured["decision"]["final_verdict"] == "MALICIOUS"
    assert captured["decision"]["action"] == "BLOCK"
    assert captured["response"]["status"] == "Block simulated"

    print("\nPASS: Final verdict is MALICIOUS.")
    print("PASS: Final action is BLOCK.")
    print("PASS: Response status is Block simulated.")

finally:
    sniffer_module.analyze_packet = original_analyze_packet
    sniffer.response_engine.handle_decision = original_handle_decision

print("\nALL BLOCK RESPONSE TESTS PASSED")