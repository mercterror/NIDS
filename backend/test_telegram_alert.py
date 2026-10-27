
from alerts.telegram_alert import TelegramAlert

telegram = TelegramAlert()

test_alert = {
    "src_ip": "192.0.2.10",
    "dst_ip": "198.51.100.20",
    "protocol": "TCP",
    "attack_type": "Test Alert",
    "severity": "MEDIUM",
    "threat_score": 60,
    "confidence": 0.95,
    "packet_rate": 10,
    "byte_rate": 540
}

telegram.send_attack_alert(test_alert)
