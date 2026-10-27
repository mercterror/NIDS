from traffic_simulator.simulator import run_simulator
from integration.traffic_adapter import TrafficAdapter
from ml.feature_extractor import FeatureExtractor

simulation = run_simulator(1)

flow = simulation[0]
packet = flow["packets"][0]

adapter = TrafficAdapter()
extractor = FeatureExtractor()

packet_data = adapter.adapt_packet(packet)
flow_features = adapter.adapt_flow(flow)

features = extractor.extract_features(
    packet_data,
    flow_features
)

extractor.display_features(features)