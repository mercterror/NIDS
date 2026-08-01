import random


def generate_ip():
    """Generate a realistic private enterprise IPv4 address."""

    third_octet = random.randint(0, 255)
    fourth_octet = random.randint(1, 254)

    return f"192.168.{third_octet}.{fourth_octet}"

# print(generate_ip())
# print(generate_ip())
# print(generate_ip())

def generate_mac():
    """Generate a realistic enterprise MAC address."""

    vendor_ouis = [
        "00:1A:2B",  # Cisco
        "3C:52:82",  # Dell
        "00:50:56",  # VMware
        "B8:27:EB",  # Raspberry Pi
        "00:15:5D",  # Microsoft Hyper-V
    ]

    vendor = random.choice(vendor_ouis)

    last_three_bytes = []

    for _ in range(3):
        byte = f"{random.randint(0, 255):02X}"
        last_three_bytes.append(byte)

    return vendor + ":" + ":".join(last_three_bytes)


# print(generate_mac())
# print(generate_mac())
# print(generate_mac())

def generate_port():
    """Generate a realistic network port."""

    common_ports = [20, 21, 22, 25, 53, 80, 110, 143, 443, 3306, 5432, 8080]

    if random.random() < 0.7:
        return random.choice(common_ports)

    return random.randint(1024, 65535)

# print(generate_port())
# print(generate_port())
# print(generate_port())


def generate_protocol():
    """Generate a realistic network protocol."""

    protocols = ["TCP", "UDP", "ICMP"]
    weights = [0.7, 0.25, 0.05]

    return random.choices(protocols, weights=weights, k=1)[0]

# print(generate_protocol())
# print(generate_protocol())
# print(generate_protocol())

def generate_packet(
    flow_context,
    packet_number,
    direction,
    timestamp
):
    """Generate a packet belonging to an existing network flow."""

    if direction == "client_to_server":
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

        "protocol": flow_context["protocol"],

        "packet_size": random.randint(64, 1500)
    }