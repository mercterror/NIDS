from traffic_simulator.simulator import run_simulator
from integration.traffic_adapter import TrafficAdapter

simulation = run_simulator(1)

flow = simulation[0]
packet = flow["packets"][0]

adapter = TrafficAdapter()

packet_data = adapter.adapt_packet(packet)
flow_features = adapter.adapt_flow(flow)

print("\nPacket Data:")
print(packet_data)

print("\nFlow Features:")
print(flow_features)