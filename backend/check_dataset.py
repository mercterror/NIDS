import pandas as pd

from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix
)


# ============================================================
# LOAD DATASET
# ============================================================

DATASET_PATH = "D:\\NIDS\\backend\\dataset\\traffic_dataset.csv"

df = pd.read_csv(DATASET_PATH)

print("\n" + "=" * 60)
print("NIDS MACHINE LEARNING TRAINING")
print("=" * 60)

print(f"\nDataset shape: {df.shape}")

print("\nLabel distribution:")
print(df["label"].value_counts())


# ============================================================
# SELECT FEATURES
# ============================================================

feature_columns = [
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
    "arp_requests"
]

X = df[feature_columns].copy()
y = df["label"]


# ============================================================
# ENCODE PROTOCOL
# ============================================================

protocol_encoder = LabelEncoder()

X["protocol"] = protocol_encoder.fit_transform(
    X["protocol"]
)

print("\nProtocol encoding:")
for index, protocol in enumerate(protocol_encoder.classes_):
    print(f"{protocol} -> {index}")


# ============================================================
# ENCODE LABELS
# ============================================================

label_encoder = LabelEncoder()

y_encoded = label_encoder.fit_transform(y)

print("\nAttack label encoding:")
for index, label in enumerate(label_encoder.classes_):
    print(f"{label} -> {index}")


# ============================================================
# TRAIN / TEST SPLIT
# ============================================================

X_train, X_test, y_train, y_test = train_test_split(
    X,
    y_encoded,
    test_size=0.20,
    random_state=42,
    stratify=y_encoded
)

print("\nTraining samples:", len(X_train))
print("Testing samples:", len(X_test))


# ============================================================
# TRAIN MODEL
# ============================================================

model = RandomForestClassifier(
    n_estimators=100,
    random_state=42,
    class_weight="balanced"
)

print("\nTraining Random Forest...")

model.fit(
    X_train,
    y_train
)

print("[+] Model training completed.")


# ============================================================
# PREDICTION
# ============================================================

y_pred = model.predict(X_test)


# ============================================================
# EVALUATION
# ============================================================

accuracy = accuracy_score(
    y_test,
    y_pred
)

print("\n" + "=" * 60)
print("MODEL EVALUATION")
print("=" * 60)

print(f"\nAccuracy: {accuracy:.4f}")

print("\nClassification Report:")

print(
    classification_report(
        y_test,
        y_pred,
        target_names=label_encoder.classes_,
        zero_division=0
    )
)

print("\nConfusion Matrix:")

print(
    confusion_matrix(
        y_test,
        y_pred
    )
)