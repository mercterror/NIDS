
from response_engine.response_engine import ResponseEngine

engine = ResponseEngine(dry_run=True)

print("\n--- TEST 1: ALLOW ---")
result = engine.handle_decision(
    {"action": "ALLOW"},
    {"source_ip": "192.0.2.10", "source_mac": None}
)
print(result)
assert result["status"] == "No action required"

print("\n--- TEST 2: INVALID IP ---")
result = engine.handle_decision(
    {"action": "BLOCK"},
    {"source_ip": "not-an-ip", "source_mac": None}
)
print(result)
assert result["block_success"] is False

print("\n--- TEST 3: LOCAL IP ---")
local_ip = next(
    ip for ip in engine.get_local_ips()
    if ip == "127.0.0.1"
)
result = engine.handle_decision(
    {"action": "BLOCK"},
    {"source_ip": local_ip, "source_mac": None}
)
print(result)
assert result["status"] == "Protected local IP"

print("\n--- TEST 4: DRY-RUN BLOCK ---")
result = engine.handle_decision(
    {"action": "BLOCK"},
    {"source_ip": "192.0.2.10", "source_mac": None}
)
print(result)
assert result["status"] == "Block simulated"

print("\n--- TEST 5: IPV6 REJECTION ---")
engine.dry_run = False
result = engine.handle_decision(
    {"action": "BLOCK"},
    {"source_ip": "2001:db8::10", "source_mac": None}
)
print(result)
assert result["block_success"] is False
assert result["status"] == (
    "Block failed: IPv6 blocking is not implemented"
)

print("\nALL RESPONSE ENGINE TESTS PASSED")
