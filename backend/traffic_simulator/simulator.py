from flow_generator import generate_flow


def run_simulator(number_of_flows=10):
    """Generate multiple network flows."""

    all_flows = []

    for _ in range(number_of_flows):
        flow = generate_flow()
        all_flows.append(flow)

    return all_flows

simulation = run_simulator(2)

for flow_number, flow in enumerate(simulation, start=1):
    print(f"\nFlow {flow_number}")

    for packet in flow:
        print(packet)