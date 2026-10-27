from traffic_simulator.simulator import run_simulator
from integration.traffic_adapter import TrafficAdapter
from ml.feature_extractor import FeatureExtractor
from ml.predictor import NIDSPredictor


simulation = run_simulator(1)

flow = simulation[0]
packet = flow["packets"][0]

adapter = TrafficAdapter()
extractor = FeatureExtractor()
predictor = NIDSPredictor()


packet_data = adapter.adapt_packet(packet)
flow_features = adapter.adapt_flow(flow)

features = extractor.extract_features(
    packet_data,
    flow_features
)

result = predictor.predict(features)

print("\n" + "=" * 60)
print("NIDS AI PREDICTION")
print("=" * 60)

print(f"Prediction : {result['label']}")
print(f"Confidence : {result['confidence']:.4f}")

print("=" * 60)