import pandas as pd
import numpy as np
from collections import defaultdict

class FeatureExtractor:

    def __init__(self):
        self.failed_connections = defaultdict(int)
        self.dns_query_counter = defaultdict(int)
        self.arp_request_counter = defaultdict(int)

    def extract_features(self, packet_data, flow_features):
        features = {}

        # =========================
        # BASIC NETWORK FEATURES
        # =========================
        features["src_ip"] = packet_data["src_ip"]
        features["dst_ip"] = packet_data["dst_ip"]
        features["src_port"] = packet_data["src_port"] if packet_data["src_port"] else 0
        features["dst_port"] = packet_data["dst_port"] if packet_data["dst_port"] else 0
        features["packet_size"] = packet_data["packet_size"]
        features["ttl"] = packet_data["ttl"] if packet_data["ttl"] else 0
        features["protocol"] = packet_data["protocol"]

        # =========================
        # FLOW FEATURES
        # =========================
        features["flow_duration"] = flow_features["duration"]
        features["packet_count"] = flow_features["packet_count"]
        features["byte_count"] = flow_features["byte_count"]
        features["packet_rate"] = flow_features["packets_per_sec"]
        features["byte_rate"] = flow_features["bytes_per_sec"]
        features["unique_src_ports"] = flow_features["unique_src_ports"]
        features["unique_dst_ports"] = flow_features["unique_dst_ports"]
        features["entropy_score"] = flow_features["entropy_score"]
        features["inter_arrival_time"] = flow_features["avg_inter_arrival"]

        # =========================
        # TCP FLAG FEATURES
        # =========================
        tcp_flags = flow_features["tcp_flags"]
        features["syn_flag_count"] = tcp_flags.get("S", 0)
        features["ack_flag_count"] = tcp_flags.get("A", 0)
        features["fin_flag_count"] = tcp_flags.get("F", 0)
        features["rst_flag_count"] = tcp_flags.get("R", 0)
        features["psh_flag_count"] = tcp_flags.get("P", 0)
        features["urg_flag_count"] = tcp_flags.get("U", 0)

        # =========================
        # DNS FEATURES
        # =========================
        if features["dst_port"] == 53 or features["src_port"] == 53:
            self.dns_query_counter[features["src_ip"]] += 1

        features["dns_query_count"] = self.dns_query_counter[features["src_ip"]]

        # =========================
        # FAILED CONNECTIONS
        # =========================
        if features["syn_flag_count"] > 0 and features["ack_flag_count"] == 0:
            self.failed_connections[features["src_ip"]] += 1

        features["failed_connections"] = self.failed_connections[features["src_ip"]]

        # =========================
        # ARP FEATURES
        # =========================
        if packet_data["protocol"] == "ARP":
            self.arp_request_counter[features["src_ip"]] += 1

        features["arp_requests"] = self.arp_request_counter[features["src_ip"]]

        return features

    def to_dataframe(self, features):
        df = pd.DataFrame([features])
        return df

    def display_features(self, features):
        print("\n" + "=" * 60)
        print("AI FEATURE EXTRACTION")
        print("=" * 60)
        for key, value in features.items():
            print(f"{key:<25}: {value}")
        print("=" * 60)