def check_rules(packet):
    """Check a packet against predefined IDS rules."""

    reasons = []

    # Extract frequently used packet fields
    destination_port = packet["destination_port"]
    source_port = packet["source_port"]
    protocol = packet["protocol"]
    packet_size = packet["packet_size"]

    # Rule 1: Telnet traffic
    if destination_port == 23:
        reasons.append("Uses Telnet")

    # Rule 2: Very large packet
    if packet_size > 1400:
        reasons.append("Large Packet")

    # Rule 3: FTP traffic
    if destination_port == 21:
        reasons.append("Uses FTP")

    # Rule 4: ICMP packet
    if protocol == "ICMP":
        reasons.append("ICMP Traffic")

    # Rule 5: ICMP packet is unusually large
    if protocol == "ICMP" and packet_size > 1000:
        reasons.append("Large ICMP Packet")

    # Rule 6: Very high destination port
    if destination_port > 60000:
        reasons.append("High Destination Port")

    # Rule 7: Very high source port
    if source_port > 60000:
        reasons.append("High Source Port")

    # Rule 8: Same source and destination port
    if source_port == destination_port:
        reasons.append("Same Source and Destination Port")

    # Rule 9: HTTP using UDP
    if destination_port == 80 and protocol == "UDP":
        reasons.append("HTTP over UDP")

    # Rule 10: HTTPS using UDP
    if destination_port == 443 and protocol == "UDP":
        reasons.append("HTTPS over UDP")

    # Rule 11: DNS using TCP
    if destination_port == 53 and protocol == "TCP":
        reasons.append("DNS over TCP")

    # Rule 12: Extremely small packet
    if packet_size < 80:
        reasons.append("Very Small Packet")

    return reasons