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

def generate_packet():
    """Generate a simulated network packet."""

    packet = {
        "source_ip": generate_ip(),
        "destination_ip": generate_ip(),
        "source_mac": generate_mac(),
        "destination_mac": generate_mac(),
        "source_port": generate_port(),
        "destination_port": generate_port(),
        "protocol": generate_protocol(),
        "packet_size": random.randint(64, 1500)
    }

    return packet

