
from scapy.all import Ether, IP, TCP
from sniffer.sniffer import PacketSniffer

sniffer = PacketSniffer(interface=None)

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

print("\n--- SYNTHETIC PACKET RESPONSE TEST ---")
sniffer.parse_packet(packet)

print("\nTEST FINISHED")
