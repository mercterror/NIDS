import pandas as pd
from collections import defaultdict


class FeatureExtractor:

    def __init__(self):

        self.dns_query_counter = defaultdict(int)
        self.arp_request_counter = defaultdict(int)

    def extract_features(self, packet_data, flow_features):

        if flow_features is None:
            return None

        features = {}

        # =====================================================
        # BASIC FEATURES
        # =====================================================

        features["src_ip"] = packet_data.get("source_ip")
        features["dst_ip"] = packet_data.get("destination_ip")

        features["src_port"] = packet_data.get("source_port") or 0
        features["dst_port"] = packet_data.get("destination_port") or 0

        features["protocol"] = packet_data.get("protocol")
        features["packet_size"] = packet_data.get("packet_size", 0)
        features["ttl"] = packet_data.get("ttl") or 0

        # =====================================================
        # FLOW FEATURES
        # =====================================================

        features["flow_duration"] = flow_features["duration"]

        features["packet_count"] = flow_features["packet_count"]

        features["byte_count"] = flow_features["byte_count"]

        features["packet_rate"] = flow_features["packet_rate"]

        features["byte_rate"] = flow_features["byte_rate"]

        features["average_packet_size"] = flow_features["average_packet_size"]

        features["unique_src_ports"] = flow_features["unique_src_ports"]

        features["unique_dst_ports"] = flow_features["unique_dst_ports"]

        features["entropy_score"] = flow_features["entropy_score"]

        features["inter_arrival_time"] = flow_features["avg_inter_arrival"]

        features["idle_time"] = flow_features["idle_time"]

        # =====================================================
        # TCP FLAGS
        # =====================================================

       # =====================================================
       # TCP FLAGS
       # =====================================================

        syn = flow_features["syn_flag_count"]
        ack = flow_features["ack_flag_count"]
        fin = flow_features["fin_flag_count"]
        rst = flow_features["rst_flag_count"]
        psh = flow_features["psh_flag_count"]
        urg = flow_features["urg_flag_count"]

        features["syn_flag_count"] = syn
        features["ack_flag_count"] = ack
        features["fin_flag_count"] = fin
        features["rst_flag_count"] = rst
        features["psh_flag_count"] = psh
        features["urg_flag_count"] = urg

        total_flags = max(
            syn + ack + fin + rst + psh + urg,
            1
        )

        features["syn_ratio"] = round(
            syn / total_flags,
            3
        )

        features["ack_ratio"] = round(
            ack / total_flags,
            3
        )

        # =====================================================
        # DNS FEATURES
        # =====================================================

        if (
            features["src_port"] == 53
            or
            features["dst_port"] == 53
        ):
            self.dns_query_counter[
                features["src_ip"]
            ] += 1

        features["dns_query_count"] = (
            self.dns_query_counter[
                features["src_ip"]
            ]
        )

                # =====================================================
        # FAILED CONNECTIONS
        # =====================================================

        # Do not infer failed connections from cumulative flow flags.
        # This feature will remain zero until connection-attempt
        # tracking is implemented consistently.
        features["failed_connections"] = 0



        # =====================================================
        # ARP
        # =====================================================

        if packet_data.get("protocol") == "ARP":

            self.arp_request_counter[
                features["src_ip"]
            ] += 1

        features["arp_requests"] = (
            self.arp_request_counter[
                features["src_ip"]
            ]
        )

        # =====================================================
        # SIMPLE CONNECTION STATE
        # =====================================================

        if syn > 0 and ack == 0:

            features["connection_state"] = "SYN"

        elif syn > 0 and ack > 0:

            features["connection_state"] = "ESTABLISHED"

        elif rst > 0:

            features["connection_state"] = "RESET"

        elif fin > 0:

            features["connection_state"] = "FINISHED"

        else:

            features["connection_state"] = "NORMAL"

        return features

    def to_dataframe(self, features):

        if features is None:
            return None

        return pd.DataFrame([features])

    def display_features(self, features):

        if features is None:
            return

        print("\n" + "=" * 65)
        print("AI FEATURE EXTRACTION")
        print("=" * 65)

        for key, value in features.items():
            print(f"{key:<28}: {value}")

        print("=" * 65)