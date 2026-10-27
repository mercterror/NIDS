import os
import tempfile
from unittest.mock import MagicMock

from scapy.all import Ether, IP, TCP, Raw

from database.database import IDSDatabase
from sniffer.sniffer import PacketSniffer


def test_full_pipeline_alerts():
    fd, db_path = tempfile.mkstemp(suffix=".db")
    os.close(fd)

    try:
        sniffer = PacketSniffer()
        sniffer.database = IDSDatabase(db_path=db_path)

        # Prevent real firewall actions.
        sniffer.response_engine = MagicMock()
        sniffer.response_engine.handle_decision.return_value = {
            "action": "BLOCK",
            "status": "Test only - blocking disabled",
        }

        # Create a synthetic packet with Telnet traffic
        # and a large payload to trigger detection rules.
        packet = (
            Ether()
            / IP(
                src="192.0.2.10",
                dst="198.51.100.20",
            )
            / TCP(
                sport=54321,
                dport=23,
                flags="S",
            )
            / Raw(load=b"A" * 1600)
        )

        print("\nRunning packet through the real detection pipeline...")

        result = sniffer.parse_packet(packet)

        assert result is not None, "Packet processing failed"

        attacks = sniffer.database.get_recent_attacks(limit=10)

        assert len(attacks) == 1, (
            f"Expected 1 detected attack, got {len(attacks)}. "
            "Check the rule score and final verdict in the output."
        )

        attack = attacks[0]

        assert attack["src_ip"] == "192.0.2.10"
        assert attack["dst_ip"] == "198.51.100.20"

        print("\nPASS: Real detection pipeline classified an attack")
        print("PASS: Attack was recorded in the temporary database")
        print("\nCheck the output above for both alert delivery results.")
        print("Check Telegram and email for the test alert.")

    finally:
        if os.path.exists(db_path):
            os.remove(db_path)


if __name__ == "__main__":
    test_full_pipeline_alerts()