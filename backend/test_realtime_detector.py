from ml.realtime_detector import RealtimeDetector


detector = RealtimeDetector()

# Prevent real database writes and Telegram messages.
detector.db.insert_attack_log = lambda attack_data: None
detector.telegram.send_attack_alert = lambda attack_data: None
detector.rule_engine.display_alert = lambda rule_result: None

normal_features = {
    "timestamp": "2026-10-11 12:00:00",
    "src_ip": "192.0.2.10",
    "dst_ip": "192.0.2.20",
    "protocol": "TCP",
    "src_port": 51514,
    "dst_port": 443,
    "packet_count": 10,
    "flow_duration": 5.0,
    "packet_rate": 2,
    "byte_count": 5000,
    "syn_flag_count": 1,
    "ack_flag_count": 9,
    "failed_connections": 0,
    "dns_query_count": 0,
    "unique_dst_ports": 1,
    "arp_requests": 0,
}

print("\n=== TEST 1: NORMAL TRAFFIC ===")

# Control both detection stages so this test is deterministic.
detector.rule_engine.detect = lambda features: {
    "attack_detected": False
}
detector.ai_detection = lambda features: {
    "prediction": "normal",
    "confidence": 99.0
}

result = detector.detect_attack(normal_features)

assert result is None, f"Expected no alert, got: {result}"
print("PASS: Normal traffic did not produce an attack alert.")


print("\n=== TEST 2: RULE-DETECTED ATTACK ===")

detector.rule_engine.detect = lambda features: {
    "timestamp": features["timestamp"],
    "attack_detected": True,
    "attack_type": "syn_flood",
    "severity": "CRITICAL",
    "threat_score": 98,
    "confidence": 98,
}

result = detector.detect_attack(normal_features)

assert result is not None, "Expected a rule-based attack result."
assert result["attack_type"] == "syn_flood"
assert result["status"] == "detected"

print("PASS: Rule-based attack produced the expected result.")


print("\n=== TEST 3: AI CONFIDENCE THRESHOLD ===")

# Use a fresh detector to avoid duplicate-alert state.
detector = RealtimeDetector()
detector.db.insert_attack_log = lambda attack_data: None
detector.telegram.send_attack_alert = lambda attack_data: None
detector.rule_engine.display_alert = lambda rule_result: None

detector.rule_engine.detect = lambda features: {
    "attack_detected": False
}

detector.ai_detection = lambda features: {
    "prediction": "syn_flood",
    "confidence": 96.0
}

result = detector.detect_attack(normal_features)

assert result is None, f"Expected no alert at 96%, got: {result}"
print("PASS: AI prediction below 97% did not produce an alert.")

detector.ai_detection = lambda features: {
    "prediction": "syn_flood",
    "confidence": 98.0
}

result = detector.detect_attack(normal_features)

assert result is not None, "Expected an alert at 98% confidence."
assert result["attack_type"] == "syn_flood"
assert result["confidence"] == 98.0

print("PASS: AI prediction at 98% produced an attack result.")

print("\nALL REALTIME DETECTOR TESTS PASSED")

print("\n=== TEST 4: DUPLICATE-ALERT SUPPRESSION ===")

# Use a fresh detector and a fixed clock to make the test deterministic.
import ml.realtime_detector as realtime_module

detector = RealtimeDetector()

current_time = [1000.0]
realtime_module.time.time = lambda: current_time[0]

attack_key = (
    "192.0.2.10",
    "192.0.2.20",
    "TCP",
    "syn_flood",
)

first_alert = detector.is_duplicate_attack(attack_key)
second_alert = detector.is_duplicate_attack(attack_key)

assert first_alert is False, "The first alert should not be a duplicate."
assert second_alert is True, "The repeated alert should be suppressed."

print("PASS: Repeated attack was suppressed within 60 seconds.")

# After 61 seconds, the same attack should be allowed again.
current_time[0] += 61

third_alert = detector.is_duplicate_attack(attack_key)

assert third_alert is False, "The attack should be allowed after 60 seconds."

print("PASS: The attack was allowed again after 61 seconds.")
print("DUPLICATE-ALERT TESTS PASSED")

print("\n=== TEST 5: IGNORED TRAFFIC ===")

detector = RealtimeDetector()

valid_features = {
    "src_ip": "192.0.2.10",
    "dst_ip": "192.0.2.20",
    "protocol": "TCP",
    "packet_count": 10,
    "flow_duration": 5.0,
}

# Missing source IP
features = {**valid_features, "src_ip": None}
assert detector.should_ignore(features) is True
print("PASS: Missing source IP was ignored.")

# Loopback traffic
features = {**valid_features, "src_ip": "127.0.0.1"}
assert detector.should_ignore(features) is True
print("PASS: Loopback traffic was ignored.")

# IPv6 traffic
features = {**valid_features, "src_ip": "2001:db8::1"}
assert detector.should_ignore(features) is True
print("PASS: IPv6 traffic was ignored.")

# Very small flow: both conditions must be met
features = {
    **valid_features,
    "packet_count": 2,
    "flow_duration": 0.2,
}
assert detector.should_ignore(features) is True
print("PASS: Very small flow was ignored.")

# Valid IPv4 flow should not be ignored
assert detector.should_ignore(valid_features) is False
print("PASS: Valid IPv4 flow was not ignored.")

print("IGNORED-TRAFFIC TESTS PASSED")