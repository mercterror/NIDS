
import subprocess

from scapy.all import Ether, IP, TCP
from sniffer.sniffer import PacketSniffer


TEST_IP = "192.0.2.10"
RULE_NAME = f"NIDS_BLOCK_{TEST_IP}"


def firewall_rule_exists():
    result = subprocess.run(
        [
            "netsh",
            "advfirewall",
            "firewall",
            "show",
            "rule",
            f"name={RULE_NAME}",
        ],
        capture_output=True,
        text=True,
        timeout=10,
    )

    output = result.stdout + result.stderr

    return (
        result.returncode == 0
        and RULE_NAME.lower() in output.lower()
        and "Enabled:" in output
        and "Yes" in output
        and "Action:" in output
        and "Block" in output
        and f"{TEST_IP}/32" in output
    )


def firewall_rule_removed():
    result = subprocess.run(
        [
            "netsh",
            "advfirewall",
            "firewall",
            "show",
            "rule",
            f"name={RULE_NAME}",
        ],
        capture_output=True,
        text=True,
        timeout=10,
    )

    return "No rules match" in (result.stdout + result.stderr)


def main():
    sniffer = PacketSniffer(dry_run=False)

    # Prevent database and external alert side effects during this test.
    sniffer.alerts_enabled = False
    sniffer.database.insert_traffic_log = lambda data: 1
    sniffer.database.update_traffic_threat_score = lambda *args: None
    sniffer.database.insert_attack_log = lambda data: None

    # Make the flow-level detection deterministic.
    sniffer.flow_analyzer.update_flow = lambda packet: {
        "flow_key": (
            TEST_IP, "192.0.2.20", 50000, 443, "TCP"
        ),
        "duration": 3.0,
        "packet_count": 200,
        "byte_count": 12800,
        "packet_rate": 66.67,
        "byte_rate": 4266.67,
        "average_packet_size": 64,
        "unique_src_ports": 1,
        "unique_dst_ports": 1,
        "avg_inter_arrival": 0.015,
        "idle_time": 0.02,
        "entropy_score": 0.0,
        "syn_flag_count": 200,
        "ack_flag_count": 2,
        "fin_flag_count": 0,
        "rst_flag_count": 0,
        "psh_flag_count": 0,
        "urg_flag_count": 0,
    }

    sniffer.predictor.predict = lambda features: {
        "label": "normal",
        "confidence": 0.95,
    }

    # Keep the actual response engine and IP blocker enabled.
    # Refuse to proceed if local IP discovery fails.
    if not sniffer.response_engine.get_local_ips():
        raise RuntimeError("Local IP discovery returned no addresses.")

    if not sniffer.response_engine.local_ip_discovery_success:
        raise RuntimeError("Local IP discovery failed; test refused.")

    if TEST_IP in sniffer.response_engine.get_local_ips():
        raise RuntimeError("Test IP is local; test refused.")

    print("\n=== LIVE RESPONSE-PATH TEST ===")
    print("Synthetic packet only; no live capture will start.")

    try:
        # Build one synthetic SYN packet.
        packet = (
            Ether(
                src="02:00:00:00:00:10",
                dst="02:00:00:00:00:20",
            )
            / IP(src=TEST_IP, dst="192.0.2.20")
            / TCP(sport=50000, dport=443, flags="S")
        )

        print("\n=== PROCESS SYNTHETIC PACKET ===")
        sniffer.parse_packet(packet)

        # Confirm that the actual response engine created the rule.
        if not firewall_rule_exists():
            raise RuntimeError(
                "The expected firewall rule was not found. "
                "Check the response-engine output."
            )

        print("\nPASS: The firewall block rule was created.")

    finally:
        print("\n=== CLEANUP ===")

        cleanup = sniffer.response_engine.ip_blocker.unblock_ip(TEST_IP)
        print(cleanup)

        if not cleanup.get("success"):
            print(
                "WARNING: Cleanup failed. Run this in an "
                "Administrator PowerShell window:"
            )
            print(
                f'netsh advfirewall firewall delete rule '
                f'name="{RULE_NAME}"'
            )
            raise RuntimeError("Test firewall rule cleanup failed.")

        if not firewall_rule_removed():
            raise RuntimeError(
                "Could not confirm firewall rule removal. "
                "Inspect Windows Firewall before continuing."
            )

        print("PASS: Temporary firewall rule removed.")

    print("\nPASS: End-to-end response-path test completed.")


if __name__ == "__main__":
    main()
