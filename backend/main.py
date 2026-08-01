from traffic_simulator.simulator import run_simulator
from detection_engine.detector import analyze_packet

MIN_FLOWS = 5
MAX_FLOWS = 30

def display_result(result):
    """Display the packet analysis result."""

    packet = result["packet"]

    print("=" * 60)
    print("Packet Analysis Result")
    print("=" * 60)
    print(f"Flow ID       : {packet['flow_id']}")
    print(f"Packet Number : {packet['packet_number']}")
    print(f"Direction     : {packet['direction']}")
    print(f"Protocol      : {packet['protocol']}")
    print(f"Threat Score  : {result['score']}")
    print(f"Source IP     : {packet['source_ip']}")
    print(f"Destination IP: {packet['destination_ip']}")
    print(f"Source Port   : {packet['source_port']}")
    print(f"Destination Port: {packet['destination_port']}")
    print(f"Packet Size   : {packet['packet_size']} Bytes")

    print("\nDetection Reasons:")

    if result["reasons"]:
        for reason in result["reasons"]:
            print(f"  - {reason}")
    else:
        print("  None")
        print()

    if result["is_suspicious"]:
        print("Status        : SUSPICIOUS")
        print("=" * 60)
        return True

    print("Status        : NORMAL")
    print("=" * 60)
    return False
def main():
    """Run the complete IDS simulation."""

    while True:
        try:
            number_of_flows = int(
                input(
                    f"Enter the number of flows to simulate ({MIN_FLOWS}-{MAX_FLOWS}): "
                )
            )

            if MIN_FLOWS <= number_of_flows <= MAX_FLOWS:
                break

            print(
                f"Please enter a whole number between {MIN_FLOWS} and {MAX_FLOWS}."
            )

        except ValueError:
            print(
                f"Invalid input. Please enter a whole number between {MIN_FLOWS} and {MAX_FLOWS}."
            )

    simulation = run_simulator(number_of_flows)

    for flow in simulation:
        for packet in flow:
            result = analyze_packet(packet)

            # AI analysis

            # Telegram alert

            display_result(result)

if __name__ == "__main__":
    main()