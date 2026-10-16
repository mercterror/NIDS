from alerts.email_alert import EmailAlert


def test_email_alert():
    email_alert = EmailAlert()

    test_attack = {
        "timestamp": "2026-10-12 23:30:00",
        "src_ip": "192.0.2.10",
        "dst_ip": "198.51.100.20",
        "protocol": "TCP",
        "attack_type": "Email Integration Test",
        "severity": "MEDIUM",
        "threat_score": 40,
        "confidence": 0.95,
        "status": "Test only",
    }

    success = email_alert.send_attack_alert(test_attack)

    if success:
        print("PASS: Email alert test completed")
    else:
        print("FAIL: Email alert test failed")


if __name__ == "__main__":
    test_email_alert()
    id="emailtest1"