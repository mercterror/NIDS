import pandas as pd
from ml.predictor import NIDSPredictor

DATASET_PATH = "dataset/traffic_dataset.csv"

predictor = NIDSPredictor()
dataset = pd.read_csv(DATASET_PATH)

attack_labels = [
    "syn_flood",
    "icmp_flood",
    "dns_abuse",
    "arp_spoofing",
    "brute_force",
    "port_scan"
]

results = []

print("\n" + "=" * 65)
print("DATASET ATTACK CONFIDENCE TEST")
print("=" * 65)

for _, row in dataset.iterrows():

    if row["label"] not in attack_labels:
        continue

    features = row.to_dict()
    result = predictor.predict(features)

    if result["label"] == row["label"]:
        results.append({
            "actual": row["label"],
            "confidence": result["confidence"]
        })

print(f"\nCorrect attack predictions : {len(results)}")

if results:
    confidences = [item["confidence"] for item in results]

    print(f"Average confidence        : {sum(confidences) / len(confidences):.4f}")
    print(f"Minimum confidence        : {min(confidences):.4f}")
    print(f"Maximum confidence        : {max(confidences):.4f}")

print("\n" + "=" * 65)
print("CONFIDENCE BY ATTACK TYPE")
print("=" * 65)

for attack in attack_labels:

    attack_confidences = [
        item["confidence"]
        for item in results
        if item["actual"] == attack
    ]

    if attack_confidences:
        average = sum(attack_confidences) / len(attack_confidences)

        print(
            f"{attack:<15} "
            f"Count: {len(attack_confidences):<4} "
            f"Average: {average:.4f} "
            f"Minimum: {min(attack_confidences):.4f}"
        )