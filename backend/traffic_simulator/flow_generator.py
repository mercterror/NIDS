import random
import math
from datetime import datetime, timedelta
from packet_generator import (
    generate_packet,
    generate_ip,
    generate_mac,
    generate_port,
    generate_protocol,
)

MIN_PACKETS_PER_FLOW = 5
MAX_PACKETS_PER_FLOW = 30

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
             direction = "Client → Server"
        else:
           direction = "Server → Client"
        current_time += timedelta(milliseconds=random.randint(5, 30))

        packet = generate_packet(
            flow_context=flow_context,
            packet_number=packet_number,
            direction=direction,
            timestamp=current_time
        )
        packets.append(packet)

    total_bytes = sum(packet["packet_size"] for packet in packets)
    
    duration = (
        packets[-1]["timestamp"] - packets[0]["timestamp"]
    ).total_seconds()
    
    if duration <= 0:
        duration = 0.001
    
    average_packet_size = total_bytes / len(packets)
    packet_rate = len(packets) / duration
    byte_rate = total_bytes / duration
    inter_arrival_times = []

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
        syn_flag_count +
        ack_flag_count +
        fin_flag_count +
        rst_flag_count +
        psh_flag_count +
        urg_flag_count,
        1
    )

    syn_ratio = round(syn_flag_count / total_flags, 3)
    ack_ratio = round(ack_flag_count / total_flags, 3)
        
    for i in range(1, len(packets)):
        gap = (
            packets[i]["timestamp"] - packets[i - 1]["timestamp"]
        ).total_seconds()
        inter_arrival_times.append(gap)

    if inter_arrival_times:
        idle_time = max(inter_arrival_times)
    else:
        idle_time = 0

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
            entropy_score -= probability * math.log2(probability)

        entropy_score = round(entropy_score, 4)
    else:
        entropy_score = 0
    
    return {
        "flow_id": flow_context["flow_id"],
        "packets": packets,
        "packet_count": len(packets),
        "byte_count": total_bytes,
        "duration": round(duration, 4),
        "average_packet_size": round(average_packet_size, 2),
        "packet_rate": round(packet_rate, 2),
        "byte_rate": round(byte_rate, 2),
        "idle_time": round(idle_time, 6),
        "syn_flag_count": syn_flag_count,
        "ack_flag_count": ack_flag_count,
        "fin_flag_count": fin_flag_count,
        "rst_flag_count": rst_flag_count,
        "psh_flag_count": psh_flag_count,
        "urg_flag_count": urg_flag_count,
        "syn_ratio": syn_ratio,
        "ack_ratio": ack_ratio,
        "unique_src_port_count": unique_src_port_count,
        "unique_dst_port_count": unique_dst_port_count  ,
        "entropy_score": entropy_score,
    }

if __name__ == "__main__":

    flow = generate_flow(1)

    print("\nFlow Statistics")
    print(f"Flow ID              : {flow['flow_id']}")
    print(f"Packet Count         : {flow['packet_count']}")
    print(f"Byte Count           : {flow['byte_count']}")
    print(f"Duration             : {flow['duration']} seconds")
    print(f"Average Packet Size  : {flow['average_packet_size']} bytes")
    print(f"Packet Rate          : {flow['packet_rate']} packets/sec")
    print(f"Byte Rate            : {flow['byte_rate']} bytes/sec")
    print(f"Idle Time            : {flow['idle_time']} seconds")
    print(f"SYN Flags            : {flow['syn_flag_count']}")
    print(f"ACK Flags            : {flow['ack_flag_count']}")
    print(f"FIN Flags            : {flow['fin_flag_count']}")
    print(f"RST Flags            : {flow['rst_flag_count']}")
    print(f"PSH Flags            : {flow['psh_flag_count']}")
    print(f"URG Flags            : {flow['urg_flag_count']}")
    print(f"SYN Ratio            : {flow['syn_ratio']}")
    print(f"ACK Ratio            : {flow['ack_ratio']}")
    print(f"Unique Source Ports  : {flow['unique_src_port_count']}")
    print(f"Unique Dest Ports    : {flow['unique_dst_port_count']}")
    print(f"Entropy Score        : {flow['entropy_score']}")

    print("\nPackets")
    for packet in flow["packets"]:
        print(packet)