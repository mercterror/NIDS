
from scapy.all import sniff, conf

print("Scapy libpcap enabled:", conf.use_pcap)

def show_packet(packet):
    print("\nPacket captured:")
    packet.summary()

print("Capturing packets for 10 seconds...")
sniff(
    filter="tcp or udp or icmp",
    prn=show_packet,
    store=False,
    timeout=10
)

print("\nCapture test finished.")
