from traffic_simulator.traffic_generator import generate_port_scan
from ml.feature_extractor import FeatureExtractor
from ml.dataset_generator import DatasetGenerator


# Generate port-scan traffic
flows = generate_port_scan(
    flow_count=20,
    direction="Client → Server"
)

feature_extractor = FeatureExtractor()
dataset_generator = DatasetGenerator()

print("\nDataset Generation Test")

for flow in flows:

    # Use the first packet from each flow
    packet = flow["packets"][0]

    print("\nFlow keys:")
    print(flow.keys())

    print("\nFlow data:")
    print(flow)
    # Extract features from the flow
    features = feature_extractor.extract_features(
        packet,
        flow
    )

    # Save features to dataset
    dataset_generator.save_feature_row(
        features
    )

print("\nDataset generation test completed.")