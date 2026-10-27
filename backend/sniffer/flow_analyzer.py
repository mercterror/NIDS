from collections import defaultdict
from pyexpat import features
import time
import math

class FlowAnalyzer:

    def __init__(self):
        self.flows = defaultdict(self.create_flow)
        self.flow_timeout = 60

    def create_flow(self):
        return {
            "start_time": time.time(),
            "last_seen": time.time(),
            "packet_count": 0,
            "byte_count": 0,
            "src_ports": set(),
            "dst_ports": set(),
            "protocol": None,
            "inter_arrival_times": [],
            "last_packet_time": None,
            "tcp_flags": defaultdict(int)
        }

    def generate_flow_key(self, packet_data):
        return (
            packet_data["src_ip"],
            packet_data["dst_ip"],
            packet_data["src_port"],
            packet_data["dst_port"],
            packet_data["protocol"]
        )

    def calculate_entropy(self, values):
        if not values:
            return 0

        frequency = defaultdict(int)
        for value in values:
            frequency[value] += 1

        entropy = 0
        total = len(values)

        for count in frequency.values():
            probability = count / total
            entropy -= probability * math.log2(probability)

        return round(entropy, 4)

    def update_flow(self, packet_data):
        flow_key = self.generate_flow_key(packet_data)
        flow = self.flows[flow_key]
        current_time = time.time()

        # =========================
        # BASIC STATS
        # =========================
        flow["packet_count"] += 1
        flow["byte_count"] += packet_data["packet_size"]
        flow["last_seen"] = current_time
        flow["protocol"] = packet_data["protocol"]

        # =========================
        # PORT TRACKING
        # =========================
        if packet_data["src_port"]:
            flow["src_ports"].add(packet_data["src_port"])

        if packet_data["dst_port"]:
            flow["dst_ports"].add(packet_data["dst_port"])

        # =========================
        # INTER ARRIVAL TIME
        # =========================
        if flow["last_packet_time"]:
            inter_arrival = current_time - flow["last_packet_time"]
            flow["inter_arrival_times"].append(inter_arrival)

        flow["last_packet_time"] = current_time

        # =========================
        # TCP FLAGS
        # =========================
        if packet_data["tcp_flags"]:
            flags = packet_data["tcp_flags"]
            for flag in flags:
                flow["tcp_flags"][flag] += 1

        return self.calculate_flow_features(flow_key)

    def calculate_flow_features(self, flow_key):
        flow = self.flows[flow_key]
        duration = time.time() - flow["start_time"]

        if duration <= 0:
            duration = 1
        packets_per_sec = flow["packet_count"] / duration
        bytes_per_sec = flow["byte_count"] / duration
        average_packet_size = flow["byte_count"] / flow["packet_count"]

        avg_inter_arrival = 0
        if flow["inter_arrival_times"]:
            avg_inter_arrival = sum(flow["inter_arrival_times"]) / len(flow["inter_arrival_times"])

        if flow["inter_arrival_times"]:
            idle_time = max(flow["inter_arrival_times"])
        else:
            idle_time = 0

        entropy_score = self.calculate_entropy(list(flow["dst_ports"]))

        syn_flag_count = flow["tcp_flags"].get("S", 0)
        ack_flag_count = flow["tcp_flags"].get("A", 0)
        fin_flag_count = flow["tcp_flags"].get("F", 0)
        rst_flag_count = flow["tcp_flags"].get("R", 0)
        psh_flag_count = flow["tcp_flags"].get("P", 0)
        urg_flag_count = flow["tcp_flags"].get("U", 0)


        return {
            "flow_key": flow_key,
            "duration": round(duration, 2),
            "packet_count": flow["packet_count"],
            "byte_count": flow["byte_count"],
            "packet_rate": round(packets_per_sec, 2),
            "byte_rate": round(bytes_per_sec, 2),
            "average_packet_size": round(average_packet_size, 2),
            "unique_src_ports": len(flow["src_ports"]),
            "unique_dst_ports": len(flow["dst_ports"]),
            "avg_inter_arrival": round(avg_inter_arrival, 6),
            "idle_time": round(idle_time, 6),
            "entropy_score": entropy_score,
            "syn_flag_count": syn_flag_count,
            "ack_flag_count": ack_flag_count,
            "fin_flag_count": fin_flag_count,
            "rst_flag_count": rst_flag_count,
            "psh_flag_count": psh_flag_count,
            "urg_flag_count": urg_flag_count
        }

    def expire_old_flows(self):
        current_time = time.time()
        expired = []

        for flow_key, flow in self.flows.items():
            if current_time - flow["last_seen"] > self.flow_timeout:
                expired.append(flow_key)

        for flow_key in expired:
            del self.flows[flow_key]

    def display_flow(self, features):
        print("\n" + "=" * 60)
        print("FLOW ANALYSIS")
        print("=" * 60)
        print(f"Flow Key          : {features['flow_key']}")
        print(f"Duration          : {features['duration']} sec")
        print(f"Packet Count      : {features['packet_count']}")
        print(f"Byte Count        : {features['byte_count']}")
        print(f"Packets/sec       : {features['packet_rate']}")
        print(f"Bytes/sec         : {features['byte_rate']}")
        print(f"Unique Src Ports  : {features['unique_src_ports']}")
        print(f"Unique Dst Ports  : {features['unique_dst_ports']}")
        print(f"Inter Arrival Avg : {features['avg_inter_arrival']}")
        print(f"Entropy Score     : {features['entropy_score']}")
        print(f"SYN Flags         : {features['syn_flag_count']}")
        print(f"ACK Flags         : {features['ack_flag_count']}")
        print(f"FIN Flags         : {features['fin_flag_count']}")
        print(f"RST Flags         : {features['rst_flag_count']}")
        print(f"PSH Flags         : {features['psh_flag_count']}")
        print(f"URG Flags         : {features['urg_flag_count']}")
        print("=" * 60)