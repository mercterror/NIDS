
from scapy.all import Ether, IP, IPv6, TCP, UDP, ICMP, Raw


def simulator_packet_to_scapy(packet):
    """Convert one simulator packet dictionary into a Scapy packet."""

    protocol = packet["protocol"].upper()
    packet_size = max(int(packet.get("packet_size", 64)), 1)

    if protocol == "TCP":
        transport = TCP(
            sport=packet.get("source_port") or 0,
            dport=packet.get("destination_port") or 0,
            flags=packet.get("tcp_flags") or "A",
        )
    elif protocol == "UDP":
        transport = UDP(
            sport=packet.get("source_port") or 0,
            dport=packet.get("destination_port") or 0,
        )
    elif protocol == "ICMP":
        transport = ICMP(type=packet.get("icmp_type") or 8)
    else:
        raise ValueError(f"Unsupported simulator protocol: {protocol}")

    network = IP(
        src=packet["source_ip"],
        dst=packet["destination_ip"],
        ttl=packet.get("ttl") or 64,
    )

    frame = Ether(
        src=packet.get("source_mac") or "00:00:00:00:00:01",
        dst=packet.get("destination_mac") or "00:00:00:00:00:02",
    ) / network / transport

    # Pad or trim the payload so the simulated IP packet is approximately
    # the requested size. Ethernet headers are not included in packet_size.
    header_size = len(bytes(frame))
    payload_size = max(packet_size - len(bytes(network / transport)), 0)

    if payload_size:
        frame = frame / Raw(load=b"X" * payload_size)

    return frame
