import random
import math
from datetime import datetime, timedelta

from .packet_generator import (
    generate_packet,
    generate_ip,
    generate_mac,
    generate_port,
    generate_protocol,
)


def generate_flow(
    flow_number,
    direction,
    context=None,
    source_port=None,
    destination_port=None
):
    
    """Generate one realistic one-directional network flow."""

    if context is None:
        flow_context = {
            "source_ip": generate_ip(),
            "destination_ip": generate_ip(),
            "source_mac": generate_mac(),
            "destination_mac": generate_mac(),
            "protocol": generate_protocol()
        }
    else:
        flow_context = context.copy()

    flow_context["flow_id"] = f"FLOW-{flow_number:04d}"

    flow_context["source_port"] = (
        source_port if source_port is not None
        else generate_port()
    )

    flow_context["destination_port"] = (
        destination_port if destination_port is not None
        else generate_port()
    )

    flow_context["start_time"] = datetime.now()

    packets = []
    packet_count = random.randint(5, 30)
    current_time = flow_context["start_time"]

    for packet_number in range(1, packet_count + 1):

        current_time += timedelta(
            milliseconds=random.randint(5, 30)
        )

        packet = generate_packet(
            flow_context=flow_context,
            packet_number=packet_number,
            direction=direction,
            timestamp=current_time
        )

        packets.append(packet)

    total_bytes = sum(
        packet["packet_size"]
        for packet in packets
    )

    duration = (
        packets[-1]["timestamp"] - packets[0]["timestamp"]
    ).total_seconds()

    if duration <= 0:
        duration = 0.001

    average_packet_size = total_bytes / len(packets)
    packet_rate = len(packets) / duration
    byte_rate = total_bytes / duration

    inter_arrival_times = []

    for i in range(1, len(packets)):
        gap = (
            packets[i]["timestamp"]
            - packets[i - 1]["timestamp"]
        ).total_seconds()

        inter_arrival_times.append(gap)

    if inter_arrival_times:
        idle_time = max(inter_arrival_times)
        avg_inter_arrival = (
            sum(inter_arrival_times)
            / len(inter_arrival_times)
        )
    else:
        idle_time = 0
        avg_inter_arrival = 0

    syn_flag_count = 0
    ack_flag_count = 0
    fin_flag_count = 0
    rst_flag_count = 0
    psh_flag_count = 0
    urg_flag_count = 0

    for packet in packets:
        flags = packet["tcp_flags"]

        if flags:
            if "S" in flags:
                syn_flag_count += 1

            if "A" in flags:
                ack_flag_count += 1

            if "F" in flags:
                fin_flag_count += 1

            if "R" in flags:
                rst_flag_count += 1

            if "P" in flags:
                psh_flag_count += 1

            if "U" in flags:
                urg_flag_count += 1

    total_flags = max(
        syn_flag_count
        + ack_flag_count
        + fin_flag_count
        + rst_flag_count
        + psh_flag_count
        + urg_flag_count,
        1
    )

    syn_ratio = round(
        syn_flag_count / total_flags,
        3
    )

    ack_ratio = round(
        ack_flag_count / total_flags,
        3
    )

    unique_src_ports = set()
    unique_dst_ports = set()

    for packet in packets:
        if packet["source_port"] is not None:
            unique_src_ports.add(packet["source_port"])

        if packet["destination_port"] is not None:
            unique_dst_ports.add(packet["destination_port"])

    unique_src_port_count = len(unique_src_ports)
    unique_dst_port_count = len(unique_dst_ports)

    destination_ports = [
        packet["destination_port"]
        for packet in packets
        if packet["destination_port"] is not None
    ]

    if destination_ports:
        frequency = {}

        for port in destination_ports:
            frequency[port] = frequency.get(port, 0) + 1

        entropy_score = 0

        for count in frequency.values():
            probability = count / len(destination_ports)
            entropy_score -= (
                probability * math.log2(probability)
            )

        entropy_score = round(entropy_score, 4)

    else:
        entropy_score = 0

    return {
        "flow_id": flow_context["flow_id"],

        "source_ip": flow_context["source_ip"],
        "destination_ip": flow_context["destination_ip"],
        "source_port": flow_context["source_port"],
        "destination_port": flow_context["destination_port"],
        "protocol": flow_context["protocol"],

        "direction": direction,

        "start_time": packets[0]["timestamp"],
        "last_seen": packets[-1]["timestamp"],
        "duration": round(duration, 4),

        "packets": packets,

        "packet_count": len(packets),
        "byte_count": total_bytes,

        "average_packet_size": round(
            average_packet_size,
            2
        ),

        "packet_rate": round(
            packet_rate,
            2
        ),

        "byte_rate": round(
            byte_rate,
            2
        ),

        "idle_time": round(
            idle_time,
            6
        ),

        "avg_inter_arrival": round(
            avg_inter_arrival,
            6
        ),

        "syn_flag_count": syn_flag_count,
        "ack_flag_count": ack_flag_count,
        "fin_flag_count": fin_flag_count,
        "rst_flag_count": rst_flag_count,
        "psh_flag_count": psh_flag_count,
        "urg_flag_count": urg_flag_count,

        "syn_ratio": syn_ratio,
        "ack_ratio": ack_ratio,

        "unique_src_ports": unique_src_port_count,
        "unique_dst_ports": unique_dst_port_count,

        "entropy_score": entropy_score
    }


if __name__ == "__main__":
    shared_context = {
        "source_ip": "192.168.1.100",
        "destination_ip": "192.168.1.200",
        "source_mac": "AA:BB:CC:11:22:33",
        "destination_mac": "DD:EE:FF:44:55:66",
        "protocol": "TCP"
    }

    flow1 = generate_flow(
        flow_number=1,
        direction="Client → Server",
        context=shared_context,
        source_port=50000,
        destination_port=22
    )

    flow2 = generate_flow(
        flow_number=2,
        direction="Client → Server",
        context=shared_context,
        source_port=50000,
        destination_port=80
    )

    print("\nShared Context Test")

    print("\nFlow 1")
    print(flow1["flow_id"])
    print(flow1["source_ip"], "→", flow1["destination_ip"])
    print(flow1["source_port"], "→", flow1["destination_port"])
    print(flow1["protocol"])

    print("\nFlow 2")
    print(flow2["flow_id"])
    print(flow2["source_ip"], "→", flow2["destination_ip"])
    print(flow2["source_port"], "→", flow2["destination_port"])
    print(flow2["protocol"])