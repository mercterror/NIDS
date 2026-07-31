from collections import defaultdict
import time
import math


class FlowAnalyzer:

    def __init__(self):
        self.flows = defaultdict(self.create_flow)

        # Remove inactive flows after 60 seconds
        self.flow_timeout = 60

        # Don't calculate ML features until this many packets
        self.minimum_packets = 5

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

            "packet_sizes": [],

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

        now = time.time()

        flow["packet_count"] += 1
        flow["byte_count"] += packet_data["packet_size"]

        flow["packet_sizes"].append(packet_data["packet_size"])

        flow["last_seen"] = now
        flow["protocol"] = packet_data["protocol"]

        if packet_data["src_port"]:
            flow["src_ports"].add(packet_data["src_port"])

        if packet_data["dst_port"]:
            flow["dst_ports"].add(packet_data["dst_port"])

        if flow["last_packet_time"] is not None:

            flow["inter_arrival_times"].append(
                now - flow["last_packet_time"]
            )

        flow["last_packet_time"] = now

        if packet_data["tcp_flags"]:

            for flag in packet_data["tcp_flags"]:
                flow["tcp_flags"][flag] += 1

        return self.calculate_flow_features(flow_key)

    def calculate_flow_features(self, flow_key):

        flow = self.flows[flow_key]

        # Wait until enough packets exist
        if flow["packet_count"] < self.minimum_packets:
            return None

        duration = time.time() - flow["start_time"]

        duration = max(duration, 1.0)

        packets_per_sec = flow["packet_count"] / duration

        bytes_per_sec = flow["byte_count"] / duration

        average_packet_size = (
            flow["byte_count"] /
            flow["packet_count"]
        )

        if flow["inter_arrival_times"]:

            avg_inter_arrival = (
                sum(flow["inter_arrival_times"])
                /
                len(flow["inter_arrival_times"])
            )

        else:

            avg_inter_arrival = 0

        idle_time = (
            time.time()
            -
            flow["last_seen"]
        )

        entropy_score = self.calculate_entropy(
            list(flow["dst_ports"])
        )

        return {

            "flow_key": flow_key,

            "duration": round(duration, 2),

            "packet_count": flow["packet_count"],

            "byte_count": flow["byte_count"],

            "packets_per_sec": round(packets_per_sec, 2),

            "bytes_per_sec": round(bytes_per_sec, 2),

            "average_packet_size": round(
                average_packet_size,
                2
            ),

            "unique_src_ports": len(
                flow["src_ports"]
            ),

            "unique_dst_ports": len(
                flow["dst_ports"]
            ),

            "avg_inter_arrival": round(
                avg_inter_arrival,
                6
            ),

            "idle_time": round(
                idle_time,
                3
            ),

            "entropy_score": entropy_score,

            "tcp_flags": dict(
                flow["tcp_flags"]
            )
        }

    def expire_old_flows(self):

        now = time.time()

        expired = []

        for key, flow in self.flows.items():

            if now - flow["last_seen"] > self.flow_timeout:
                expired.append(key)

        for key in expired:
            del self.flows[key]

    def display_flow(self, features):

        if features is None:
            return

        print("\n" + "=" * 60)
        print("FLOW ANALYSIS")
        print("=" * 60)

        print(f"Flow Key          : {features['flow_key']}")
        print(f"Duration          : {features['duration']} sec")
        print(f"Packet Count      : {features['packet_count']}")
        print(f"Byte Count        : {features['byte_count']}")
        print(f"Packets/sec       : {features['packets_per_sec']}")
        print(f"Bytes/sec         : {features['bytes_per_sec']}")
        print(f"Average Packet    : {features['average_packet_size']}")
        print(f"Unique Src Ports  : {features['unique_src_ports']}")
        print(f"Unique Dst Ports  : {features['unique_dst_ports']}")
        print(f"Inter Arrival Avg : {features['avg_inter_arrival']}")
        print(f"Idle Time         : {features['idle_time']}")
        print(f"Entropy Score     : {features['entropy_score']}")
        print(f"TCP Flags         : {features['tcp_flags']}")
        print("=" * 60)