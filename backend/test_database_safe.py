
import os
import tempfile

from database.database import IDSDatabase


fd, db_path = tempfile.mkstemp(suffix=".db")
os.close(fd)

try:
    db = IDSDatabase(db_path)

    print("\n=== TEST 1: INSERT TRAFFIC LOG ===")
    db.insert_traffic_log({
        "src_ip": "192.0.2.10",
        "dst_ip": "198.51.100.20",
        "src_port": 50000,
        "dst_port": 443,
        "protocol": "TCP",
        "packet_count": 10,
        "byte_count": 1500,
        "packet_rate": 5.0,
        "byte_rate": 750.0,
        "flow_duration": 2.0,
        "entropy_score": 1.2,
        "threat_score": 20,
    })

    traffic = db.get_recent_traffic(limit=10)
    assert len(traffic) == 1
    assert traffic[0]["src_ip"] == "192.0.2.10"
    print("PASS: Traffic log inserted and retrieved.")

    print("\n=== TEST 2: INSERT ATTACK LOG ===")
    db.insert_attack_log({
        "src_ip": "192.0.2.10",
        "dst_ip": "198.51.100.20",
        "attack_type": "test_attack",
        "severity": "HIGH",
        "protocol": "TCP",
        "threat_score": 90,
        "confidence": 0.95,
        "status": "detected",
    })

    attacks = db.get_recent_attacks(limit=10)
    assert len(attacks) == 1
    assert attacks[0]["attack_type"] == "test_attack"
    print("PASS: Attack log inserted and retrieved.")

    print("\n=== TEST 3: STATISTICS ===")
    stats = db.get_statistics()
    assert stats["total_traffic_logs"] == 1
    assert stats["total_attacks"] == 1
    print(stats)
    print("PASS: Statistics match the test records.")

finally:
    os.remove(db_path)
    print("\nTemporary test database removed.")
