import os
import tempfile
from unittest.mock import MagicMock, patch

from scapy.all import Ether, IP, TCP

from database.database import IDSDatabase
from sniffer.sniffer import PacketSniffer


def run_packet_test(db_path, malicious=False):
    sniffer = PacketSniffer()
    sniffer.database = IDSDatabase(db_path=db_path)

    # Mock Telegram and email alerts.
    sniffer.telegram_alert = MagicMock()
    telegram_mock = sniffer.telegram_alert

    sniffer.email_alert = MagicMock()
    email_mock = sniffer.email_alert

    # Prevent real firewall actions.
    sniffer.response_engine = MagicMock()
    sniffer.response_engine.handle_decision.return_value = {
        "action": "BLOCK" if malicious else "ALLOW",
        "status": "Block simulated" if malicious else "Allowed",
    }

    packet = (
        Ether()
        / IP(src="192.0.2.10", dst="198.51.100.20")
        / TCP(
            sport=54321,
            dport=23 if malicious else 80,
            flags="S",
        )
    )

    if malicious:
        ai_result = {"label": "NORMAL", "confidence": 0.60}
        rule_result = {
            "score": 60,
            "is_suspicious": True,
            "reasons": ["Uses Telnet", "Large Packet"],
        }
        decision = {
            "final_verdict": "MALICIOUS",
            "action": "BLOCK",
        }
    else:
        ai_result = {"label": "NORMAL", "confidence": 0.99}
        rule_result = {
            "score": 0,
            "is_suspicious": False,
            "reasons": [],
        }
        decision = {
            "final_verdict": "NORMAL",
            "action": "ALLOW",
        }

    with (
        patch.object(sniffer, "display_packet"),
        patch.object(sniffer.flow_analyzer, "display_flow"),
        patch.object(
            sniffer.predictor,
            "predict",
            return_value=ai_result,
        ),
        patch(
            "sniffer.sniffer.make_final_decision",
            return_value=decision,
        ),
        patch(
            "sniffer.sniffer.analyze_packet",
            return_value=rule_result,
        ),
    ):
        result = sniffer.parse_packet(packet)

    assert result is not None, "Packet parsing failed"

    return sniffer.database, telegram_mock, email_mock


def test_sniffer_database_logging():
    fd, db_path = tempfile.mkstemp(suffix=".db")
    os.close(fd)

    try:
        # Test 1: Normal packet logs traffic only.
        database, telegram_mock, email_mock = run_packet_test(
            db_path,
            malicious=False,
        )

        traffic = database.get_recent_traffic(limit=10)
        attacks = database.get_recent_attacks(limit=10)

        assert len(traffic) == 1, (
            f"Expected 1 normal traffic record, got {len(traffic)}"
        )
        assert len(attacks) == 0, (
            f"Expected no attack records, got {len(attacks)}"
        )
        assert traffic[0]["src_ip"] == "192.0.2.10"
        assert traffic[0]["dst_ip"] == "198.51.100.20"
        assert traffic[0]["protocol"] == "TCP"

        telegram_mock.send_attack_alert.assert_not_called()
        email_mock.send_attack_alert.assert_not_called()

        print("PASS: Normal packet logged as traffic only")
        print("PASS: Normal packet triggered neither alert")

        # Test 2: Malicious packet logs traffic and an attack.
        database, telegram_mock, email_mock = run_packet_test(
            db_path,
            malicious=True,
        )

        traffic = database.get_recent_traffic(limit=10)
        attacks = database.get_recent_attacks(limit=10)

        assert len(traffic) == 2, (
            f"Expected 2 traffic records, got {len(traffic)}"
        )
        assert len(attacks) == 1, (
            f"Expected 1 attack record, got {len(attacks)}"
        )

        attack = attacks[0]

        assert attack["src_ip"] == "192.0.2.10"
        assert attack["dst_ip"] == "198.51.100.20"
        assert attack["attack_type"] == "Uses Telnet, Large Packet"
        assert attack["severity"] == "HIGH"
        assert attack["threat_score"] == 60
        assert attack["status"] == "Block simulated"

        telegram_mock.send_attack_alert.assert_called_once()
        email_mock.send_attack_alert.assert_called_once()

        telegram_argument = (
            telegram_mock.send_attack_alert.call_args.args[0]
        )
        email_argument = (
            email_mock.send_attack_alert.call_args.args[0]
        )

        for alert_argument in (telegram_argument, email_argument):
            assert alert_argument["src_ip"] == "192.0.2.10"
            assert alert_argument["dst_ip"] == "198.51.100.20"
            assert alert_argument["threat_score"] == 60

        print("PASS: Malicious packet logged as traffic and attack")
        print("PASS: Attack details verified")
        print("PASS: Telegram alert triggered exactly once")
        print("PASS: Email alert triggered exactly once")

    finally:
        if os.path.exists(db_path):
            os.remove(db_path)


if __name__ == "__main__":
    test_sniffer_database_logging()