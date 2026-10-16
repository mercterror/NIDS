from traffic_simulator.traffic_generator import (
    generate_traffic,
    generate_port_scan,
)

import random

from ml.feature_extractor import FeatureExtractor
from ml.dataset_generator import DatasetGenerator


# ============================================================
# CONFIGURATION
# ============================================================

NORMAL_FLOWS = 100
PORT_SCAN_FLOWS = 20
ATTACK_EXAMPLES = 100


# ============================================================
# HELPERS
# ============================================================



def save_features(
    feature_extractor,
    dataset_generator,
    packet,
    flow,
    modifications=None,
    label_override=None
):
    features = feature_extractor.extract_features(packet, flow)

    if features is None:
        return

    if modifications:
        for key, value in modifications.items():
            features[key] = value

    dataset_generator.save_feature_row(
        features,
        label_override=label_override
    )



# ============================================================
# NORMAL TRAFFIC
# ============================================================

def generate_normal_traffic(
    feature_extractor,
    dataset_generator
):
    print("\n" + "=" * 60)
    print("GENERATING NORMAL TRAFFIC")
    print("=" * 60)

    flows = generate_traffic(
        flow_count=NORMAL_FLOWS,
        direction="Client → Server"
    )

    for flow in flows:

        packet = flow["packets"][0]

        save_features(
            feature_extractor,
            dataset_generator,
            packet,
            flow,
            label_override="normal"
        )

    print(
        f"[+] Normal traffic generated: "
        f"{len(flows)}"
    )


# ============================================================
# PORT SCAN
# ============================================================

def generate_port_scan_data(
    feature_extractor,
    dataset_generator
):
    print("\n" + "=" * 60)
    print("GENERATING PORT SCAN DATA")
    print("=" * 60)

    flows = generate_port_scan(
        flow_count=PORT_SCAN_FLOWS,
        direction="Client → Server"
    )

    for flow in flows:

        packet = flow["packets"][0]

        save_features(
            feature_extractor,
            dataset_generator,
            packet,
            flow,
            {
                "unique_dst_ports": 20
            },
            label_override="port_scan"
        )

    print(
        f"[+] Port scan examples generated: "
        f"{len(flows)}"
    )


# ============================================================
# SYN FLOOD
# ============================================================

def generate_syn_flood_data(
    feature_extractor,
    dataset_generator
):
    print("\n" + "=" * 60)
    print("GENERATING SYN FLOOD DATA")
    print("=" * 60)

    flows = generate_traffic(
        flow_count=ATTACK_EXAMPLES,
        direction="Client → Server"
    )

    for flow in flows:

        packet = flow["packets"][0]

        save_features(
            feature_extractor,
            dataset_generator,
            packet,
            flow,
            {
                "syn_flag_count": 150,
                "ack_flag_count": 2
            },
            label_override="syn_flood"
        )

    print(
        f"[+] SYN flood examples generated: "
        f"{len(flows)}"
    )


# ============================================================
# ICMP FLOOD
# ============================================================

def generate_icmp_flood_data(
    feature_extractor,
    dataset_generator
):
    print("\n" + "=" * 60)
    print("GENERATING ICMP FLOOD DATA")
    print("=" * 60)

    flows = generate_traffic(
        flow_count=ATTACK_EXAMPLES,
        direction="Client → Server"
    )

    for flow in flows:

        # Force the feature conditions used by
        # DatasetGenerator.determine_label()

        packet = flow["packets"][0]

        packet["protocol"] = "ICMP"

        save_features(
            feature_extractor,
            dataset_generator,
            packet,
            flow,
            {
                "packet_rate": 250
            },
            label_override="icmp_flood"
        )

    print(
        f"[+] ICMP flood examples generated: "
        f"{len(flows)}"
    )


# ============================================================
# DNS ABUSE
# ============================================================

def generate_dns_abuse_data(
    feature_extractor,
    dataset_generator
):
    print("\n" + "=" * 60)
    print("GENERATING DNS ABUSE DATA")
    print("=" * 60)

    flows = generate_traffic(
        flow_count=ATTACK_EXAMPLES,
        direction="Client → Server"
    )

    for flow in flows:

        packet = flow["packets"][0]

        save_features(
            feature_extractor,
            dataset_generator,
            packet,
            flow,
            {
                "dns_query_count": 150
            },
            label_override="dns_abuse"
        )

    print(
        f"[+] DNS abuse examples generated: "
        f"{len(flows)}"
    )


# ============================================================
# ARP SPOOFING
# ============================================================

def generate_arp_spoofing_data(
    feature_extractor,
    dataset_generator
):
    print("\n" + "=" * 60)
    print("GENERATING ARP SPOOFING DATA")
    print("=" * 60)

    flows = generate_traffic(
        flow_count=ATTACK_EXAMPLES,
        direction="Client → Server"
    )

    for flow in flows:

        packet = flow["packets"][0]

        packet["protocol"] = "ARP"

        save_features(
            feature_extractor,
            dataset_generator,
            packet,
            flow,
            {
                "arp_requests": 60
            },
            label_override="arp_spoofing"
        )

    print(
        f"[+] ARP spoofing examples generated: "
        f"{len(flows)}"
    )



# ============================================================
# MAIN
# ============================================================

if __name__ == "__main__":

    print("\n" + "=" * 60)
    print("NIDS TRAINING DATA GENERATION")
    print("=" * 60)

    feature_extractor = FeatureExtractor()

    dataset_generator = DatasetGenerator()

    # --------------------------------------------------------
    # NORMAL
    # --------------------------------------------------------

    generate_normal_traffic(
        feature_extractor,
        dataset_generator
    )

    # --------------------------------------------------------
    # PORT SCAN
    # --------------------------------------------------------

    generate_port_scan_data(
        feature_extractor,
        dataset_generator
    )

    # --------------------------------------------------------
    # SYN FLOOD
    # --------------------------------------------------------

    generate_syn_flood_data(
        feature_extractor,
        dataset_generator
    )

    # --------------------------------------------------------
    # ICMP FLOOD
    # --------------------------------------------------------

    generate_icmp_flood_data(
        feature_extractor,
        dataset_generator
    )

    # --------------------------------------------------------
    # DNS ABUSE
    # --------------------------------------------------------

    generate_dns_abuse_data(
        feature_extractor,
        dataset_generator
    )

    # --------------------------------------------------------
    # ARP SPOOFING
    # --------------------------------------------------------

    generate_arp_spoofing_data(
        feature_extractor,
        dataset_generator
    )



    print("\n" + "=" * 60)
    print("DATASET GENERATION COMPLETED")
    print("=" * 60)