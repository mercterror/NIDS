from sniffer.sniffer import PacketSniffer


def test_dual_alerts():
    sniffer = PacketSniffer()

    test_attack = {
        "timestamp": "2026-10-13 10:00:00",
        "src_ip": "192.0.2.10",
        "dst_ip": "198.51.100.20",
        "protocol": "TCP",
        "attack_type": "Dual Alert Integration Test",
        "severity": "HIGH",
        "threat_score": 60,
        "confidence": 0.95,
        "status": "Test only - no blocking performed",
    }

    print("\nSending real Telegram alert...")
    sniffer.telegram_alert.send_attack_alert(test_attack)

    print("\nSending real email alert...")
    email_success = sniffer.email_alert.send_attack_alert(test_attack)

    if email_success:
        print("\nPASS: Both alert services were called.")
    else:
        print("\nFAIL: Email alert failed. Check the error above.")


if __name__ == "__main__":
    test_dual_alerts()