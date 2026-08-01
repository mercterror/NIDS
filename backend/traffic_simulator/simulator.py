from traffic_simulator.flow_generator import generate_flow

def run_simulator(number_of_flows=10):
    """Generate multiple network flows."""

    all_flows = []

    for flow_number in range(1, number_of_flows + 1):
        flow = generate_flow(flow_number)
        all_flows.append(flow)

    return all_flows


# if __name__ == "__main__":

#     simulation = run_simulator(2)

#     for flow in simulation:
#         print(f"\n{flow[0]['flow_id']}")
#         print("-" * 60)

#         for packet in flow:
#             print(packet)