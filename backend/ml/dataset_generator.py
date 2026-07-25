import csv
import os
from datetime import datetime


class DatasetGenerator:

    def __init__(self):

        self.dataset_path = "dataset/traffic_dataset.csv"

        self.headers = [
            "timestamp",
            "src_ip",
            "dst_ip",
            "src_port",
            "dst_port",
            "protocol",
            "packet_size",
            "ttl",
            "flow_duration",
            "packet_count",
            "byte_count",
            "packet_rate",
            "byte_rate",
            "unique_src_ports",
            "unique_dst_ports",
            "entropy_score",
            "inter_arrival_time",
            "syn_flag_count",
            "ack_flag_count",
            "fin_flag_count",
            "rst_flag_count",
            "psh_flag_count",
            "urg_flag_count",
            "dns_query_count",
            "failed_connections",
            "arp_requests",
            "label"
        ]

        self.initialize_dataset()

    def initialize_dataset(self):

        os.makedirs("dataset", exist_ok=True)

        if not os.path.exists(self.dataset_path):

            with open(
                self.dataset_path,
                mode="w",
                newline=""
            ) as file:

                writer = csv.writer(file)

                writer.writerow(self.headers)

            print(f"[+] Dataset created: {self.dataset_path}")

    def determine_label(self, features):

        if (
            features["syn_flag_count"] > 100
            and features["ack_flag_count"] < 5
        ):
            return "syn_flood"

        if (
            features["protocol"] == "ICMP"
            and features["packet_rate"] > 200
        ):
            return "icmp_flood"

        if features["unique_dst_ports"] > 20:
            return "port_scan"

        if features["dns_query_count"] > 100:
            return "dns_abuse"

        if features["arp_requests"] > 50:
            return "arp_spoofing"

        if features["failed_connections"] > 40:
            return "brute_force"

        return "normal"

    def save_feature_row(self, features):

        label = self.determine_label(features)

        row = [
            datetime.now().strftime("%Y-%m-%d %H:%M:%S"),

            features["src_ip"],
            features["dst_ip"],

            features["src_port"],
            features["dst_port"],

            features["protocol"],

            features["packet_size"],

            features["ttl"],

            features["flow_duration"],

            features["packet_count"],

            features["byte_count"],

            features["packet_rate"],

            features["byte_rate"],

            features["unique_src_ports"],

            features["unique_dst_ports"],

            features["entropy_score"],

            features["inter_arrival_time"],

            features["syn_flag_count"],

            features["ack_flag_count"],

            features["fin_flag_count"],

            features["rst_flag_count"],

            features["psh_flag_count"],

            features["urg_flag_count"],

            features["dns_query_count"],

            features["failed_connections"],

            features["arp_requests"],

            label
        ]

        with open(
            self.dataset_path,
            mode="a",
            newline=""
        ) as file:

            writer = csv.writer(file)

            writer.writerow(row)

        print(f"[+] Dataset Row Saved → Label: {label}")
