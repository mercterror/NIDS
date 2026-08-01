import random

from datetime import datetime, timedelta

from packet_generator import (
    generate_packet,
    generate_ip,
    generate_mac,
    generate_port,
    generate_protocol,
)

MIN_PACKETS_PER_FLOW = 5
MAX_PACKETS_PER_FLOW = 20

def generate_flow(flow_number):
    """Generate one realistic network flow."""
    flow_context = {

    "flow_id": f"FLOW-{flow_number:04d}",

    "source_ip": generate_ip(),
    "destination_ip": generate_ip(),

    "source_mac": generate_mac(),
    "destination_mac": generate_mac(),

    "source_port": generate_port(),
    "destination_port": generate_port(),

    "protocol": generate_protocol(),

    "start_time": datetime.now()
    }
    packets = []

    packet_count = random.randint(
        MIN_PACKETS_PER_FLOW,
        MAX_PACKETS_PER_FLOW
    )
    current_time = flow_context["start_time"]

    for packet_number in range(1, packet_count + 1):
        if packet_number % 2 == 1:
             direction = "client_to_server"
        else:
           direction = "server_to_client"
        current_time += timedelta(milliseconds=random.randint(5, 20))

        packet = generate_packet(
            flow_context=flow_context,
            packet_number=packet_number,
            direction=direction,
            timestamp=current_time
        )
        packets.append(packet)

    return packets

# if __name__ == "__main__":

#     flow = generate_flow(1)

#     for packet in flow:
#         print(packet)