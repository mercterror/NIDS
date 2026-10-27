from sniffer.sniffer import PacketSniffer

from scapy.all import Ether, IP, TCP

sniffer = PacketSniffer()

packet = (
    Ether()
    / IP(src="192.168.1.10", dst="192.168.1.20", ttl=64)
    / TCP(sport=50000, dport=443, flags="S")
)

packet_data, flow_features = sniffer.parse_packet(packet)

print("\n" + "=" * 60)
print("SNIFFER PARSE TEST")
print("=" * 60)

print("\nPacket Data:")
for key, value in packet_data.items():
    print(f"{key:<15}: {value}")

print("\nFlow Features:")
for key, value in flow_features.items():
    print(f"{key:<20}: {value}")

print("=" * 60)