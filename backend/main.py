
from traffic_simulator.simulator import run_simulator
from integration.simulator_adapter import simulator_packet_to_scapy
from sniffer.sniffer import PacketSniffer

MIN_FLOWS = 5
MAX_FLOWS = 30


def main():
    """Run simulated traffic through the existing NIDS pipeline."""

    while True:
        try:
            number_of_flows = int(
                input(
                    f"Enter the number of flows to simulate "
                    f"({MIN_FLOWS}-{MAX_FLOWS}): "
                )
            )

            if MIN_FLOWS <= number_of_flows <= MAX_FLOWS:
                break

            print(
                f"Please enter a whole number between "
                f"{MIN_FLOWS} and {MAX_FLOWS}."
            )

        except ValueError:
            print("Invalid input. Please enter a whole number.")

    simulation = run_simulator(number_of_flows)

    sniffer = PacketSniffer()
    sniffer.alerts_enabled = True
    sniffer.response_engine.dry_run = True
    
    for flow in simulation:
        for packet_data in flow["packets"]:
            scapy_packet = simulator_packet_to_scapy(packet_data)
            sniffer.parse_packet(scapy_packet)


if __name__ == "__main__":
    main()
