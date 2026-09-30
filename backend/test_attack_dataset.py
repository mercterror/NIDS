from traffic_simulator.traffic_generator import generate_port_scan
from ml.feature_extractor import FeatureExtractor
from ml.dataset_generator import DatasetGenerator


feature_extractor = FeatureExtractor()
dataset_generator = DatasetGenerator()

print("\nAttack Dataset Generation Test")


# Generate port-scan traffic
flows = generate_port_scan(
    flow_count=20,
    direction="Client → Server"
)


for flow in flows:

    packet = flow["packets"][0]

    features = feature_extractor.extract_features(
        packet,
        flow
    )

    # Force the port-scan feature condition
    # used by DatasetGenerator.determine_label().
    features["unique_dst_ports"] = 20

    dataset_generator.save_feature_row(
        features
    )


print("\nPort Scan dataset generation completed.")