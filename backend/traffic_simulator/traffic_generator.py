from .flow_generator import generate_flow
from .packet_generator import (
    generate_ip,
    generate_mac,
    generate_port,
    generate_protocol
)


def generate_traffic(flow_count, direction):
    """Generate multiple one-directional network flows."""

    flows = []

    for flow_number in range(1, flow_count + 1):

        flow = generate_flow(
            flow_number=flow_number,
            direction=direction
        )

        flows.append(flow)

    return flows


def generate_port_scan(flow_count, direction):
    """Generate multiple flows representing a port scan."""

    shared_context = {
        "source_ip": generate_ip(),
        "destination_ip": generate_ip(),
        "source_mac": generate_mac(),
        "destination_mac": generate_mac(),
        "protocol": "TCP"
    }

    flows = []

    for flow_number in range(1, flow_count + 1):
        destination_port = 10000 + flow_number

        flow = generate_flow(
            flow_number=flow_number,
            direction=direction,
            context=shared_context,
            source_port=50000,
            destination_port=destination_port
        )

        flows.append(flow)

    return flows


if __name__ == "__main__":

    flows = generate_port_scan(
        flow_count=5,
        direction="Client → Server"
    )

    print("\nPort Scan Test")
    print(f"Flow Count: {len(flows)}")

    for flow in flows:
        print(
            f"{flow['flow_id']} | "
            f"{flow['source_ip']} → {flow['destination_ip']} | "
            f"{flow['source_port']} → {flow['destination_port']} | "
            f"{flow['protocol']} | "
            f"{flow['direction']}"
        )
    print("\nPacket Verification")

    for flow in flows:
        first_packet = flow["packets"][0]

        print(
            f"{flow['flow_id']} | "
            f"Packet {first_packet['packet_number']} | "
            f"{first_packet['source_ip']} → "
            f"{first_packet['destination_ip']} | "
            f"{first_packet['source_port']} → "
            f"{first_packet['destination_port']}"
        )