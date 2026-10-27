from collections import defaultdict
from datetime import timedelta


class PortScanTracker:
    def __init__(self, threshold=20, window_seconds=10):
        self.threshold = threshold
        self.window = timedelta(seconds=window_seconds)
        self.activities = defaultdict(list)

    def update(self, flow):
        source_ip = flow["source_ip"]
        destination_ip = flow["destination_ip"]
        destination_port = flow["destination_port"]
        timestamp = flow["start_time"]

        activity_key = (source_ip, destination_ip)

        self.activities[activity_key].append(
            (timestamp, destination_port)
        )

        current_time = timestamp
        cutoff_time = current_time - self.window

        self.activities[activity_key] = [
            (time, port)
            for time, port in self.activities[activity_key]
            if time >= cutoff_time
        ]

        unique_ports = {
            port
            for time, port in self.activities[activity_key]
        }

        is_port_scan = len(unique_ports) >= self.threshold

        return {
            "source_ip": source_ip,
            "destination_ip": destination_ip,
            "unique_destination_ports": len(unique_ports),
            "is_port_scan": len(unique_ports) >= self.threshold,
            "reason": "Port Scan" if is_port_scan else None
        }
    
if __name__ == "__main__":
    from traffic_simulator.traffic_generator import generate_port_scan
    from detection_engine.detector import analyze_packet

    flows = generate_port_scan(
        flow_count=20,
        direction="Client → Server"
    )

    tracker = PortScanTracker(
        threshold=20,
        window_seconds=10
    )

    print("\nDetection Compatibility Test")

    # Run the port-scan activity detector
    port_scan_result = None

    for flow in flows:
        port_scan_result = tracker.update(flow)

    print("\nPort Scan Tracker")
    print(
        f"Unique Destination Ports: "
        f"{port_scan_result['unique_destination_ports']}"
    )
    print(
        f"Port Scan Detected: "
        f"{port_scan_result['is_port_scan']}"
    )
    print(
        f"Reason: "
        f"{port_scan_result['reason']}"
    )

    # Run the existing packet-level detection
    print("\nExisting Rule Detection")

    first_packet = flows[0]["packets"][0]
    rule_result = analyze_packet(first_packet)

    print(f"Score: {rule_result['score']}")
    print(f"Suspicious: {rule_result['is_suspicious']}")
    print(f"Reasons: {rule_result['reasons']}")