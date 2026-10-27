import pandas as pd

df = pd.read_csv("D:\\NIDS\\backend\\dataset\\traffic_dataset.csv")

print("\nDataset Shape")
print("=" * 40)
print(df.shape)

print("\nLabel Counts")
print("=" * 40)
print(df["label"].value_counts())

print("\nAttack Feature Check")
print("=" * 40)

for label in df["label"].unique():

    subset = df[df["label"] == label]

    print(f"\n--- {label} ---")

    if label == "port_scan":
        print("unique_dst_ports:")
        print(subset["unique_dst_ports"].describe())

    elif label == "syn_flood":
        print("syn_flag_count:")
        print(subset["syn_flag_count"].describe())
        print("ack_flag_count:")
        print(subset["ack_flag_count"].describe())

    elif label == "icmp_flood":
        print("packet_rate:")
        print(subset["packet_rate"].describe())

    elif label == "dns_abuse":
        print("dns_query_count:")
        print(subset["dns_query_count"].describe())

    elif label == "arp_spoofing":
        print("arp_requests:")
        print(subset["arp_requests"].describe())

    elif label == "brute_force":
        print("failed_connections:")
        print(subset["failed_connections"].describe())