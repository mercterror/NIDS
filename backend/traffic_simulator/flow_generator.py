import random

from packet_generator import generate_packet


def generate_flow():
    """Generate a network flow consisting of multiple packets."""

    flow = []

    number_of_packets = random.randint(5, 20)

    for _ in range(number_of_packets):
        packet = generate_packet()
        flow.append(packet)

    return flow

# print(generate_flow())