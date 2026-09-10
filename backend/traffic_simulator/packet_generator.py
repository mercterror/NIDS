import random

def generate_ip():
    """Generate a realistic private enterprise IPv4 address."""

    third_octet = random.randint(0, 255)
    fourth_octet = random.randint(1, 254)

    return f"192.168.{third_octet}.{fourth_octet}"


def generate_mac():
    """Generate a realistic enterprise MAC address."""

    vendor_ouis = [
        "00:1A:2B",
        "3C:52:82",
        "00:50:56",
        "B8:27:EB",
        "00:15:5D",
    ]

    vendor = random.choice(vendor_ouis)

    last_three_bytes = []

    for _ in range(3):
        byte = f"{random.randint(0, 255):02X}"
        last_three_bytes.append(byte)

    return vendor + ":" + ":".join(last_three_bytes)


def generate_port():
    """Generate a realistic network port."""

    common_ports = [
        20, 21, 22, 25, 53,
        80, 110, 143, 443,
        3306, 5432, 8080
    ]

    if random.random() < 0.7:
        return random.choice(common_ports)

    return random.randint(1024, 65535)


def generate_protocol():
    """Generate a realistic network protocol."""

    protocols = ["TCP", "UDP", "ICMP"]
    weights = [0.7, 0.25, 0.05]

    return random.choices(
        protocols,
        weights=weights,
        k=1
    )[0]


def generate_ttl(protocol):
    """Generate a realistic IPv4 TTL value."""

    common_ttl_values = [32, 64, 128, 255]

    return random.choice(common_ttl_values)


def generate_tcp_flags(protocol):
    """Generate TCP flags for a simulated packet."""

    if protocol != "TCP":
        return None

    tcp_flag_combinations = [
        "S",
        "SA",
        "A",
        "PA",
        "FA",
        "R"
    ]

    return random.choice(tcp_flag_combinations)


def generate_icmp_type(protocol):
    """Generate an ICMP message type."""

    if protocol != "ICMP":
        return None

    icmp_types = [
        0,   # Echo Reply
        8    # Echo Request
    ]

    return random.choice(icmp_types)


def generate_packet(
    flow_context,
    packet_number,
    direction,
    timestamp
):
    """Generate a packet belonging to an existing network flow."""

    if direction == "Client → Server":

        source_ip = flow_context["source_ip"]
        destination_ip = flow_context["destination_ip"]

        source_mac = flow_context["source_mac"]
        destination_mac = flow_context["destination_mac"]

        source_port = flow_context["source_port"]
        destination_port = flow_context["destination_port"]

    else:

        source_ip = flow_context["destination_ip"]
        destination_ip = flow_context["source_ip"]

        source_mac = flow_context["destination_mac"]
        destination_mac = flow_context["source_mac"]

        source_port = flow_context["destination_port"]
        destination_port = flow_context["source_port"]

    protocol = flow_context["protocol"]

    return {
        "flow_id": flow_context["flow_id"],

        "packet_number": packet_number,

        "timestamp": timestamp,

        "direction": direction,

        "source_ip": source_ip,
        "destination_ip": destination_ip,

        "source_mac": source_mac,
        "destination_mac": destination_mac,

        "source_port": source_port,
        "destination_port": destination_port,

        "protocol": protocol,

        "packet_size": random.randint(64, 1500),

        "ttl": generate_ttl(protocol),

        "tcp_flags": generate_tcp_flags(protocol),

        "icmp_type": generate_icmp_type(protocol)
    }