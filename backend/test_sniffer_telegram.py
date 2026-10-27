from sniffer.sniffer import PacketSniffer


def test_sniffer_telegram():
    sniffer = PacketSniffer()

    test_attack = {
        "timestamp": "2026-10-12 21:00:00",
        "src_ip": "192.0.2.10",
        "dst_ip": "198.51.100.20",
        "protocol": "TCP",
        "attack_type": "Telegram Integration Test",
        "severity": "MEDIUM",
        "threat_score": 40,
        "confidence": 0.95,
        "status": "Test only",
    }

    sniffer.telegram_alert.send_attack_alert(test_attack)


if __name__ == "__main__":
    test_sniffer_telegram()
    id="q7p4km"