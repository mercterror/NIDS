
from response_engine.response_engine import ResponseEngine

engine = ResponseEngine(dry_run=False)

def simulate_firewall_error(ip_address):
    raise RuntimeError("Simulated firewall failure")

# Temporarily replace the blocker method for this test
engine.ip_blocker.block_ip = simulate_firewall_error

decision = {
    "action": "BLOCK"
}

packet = {
    "source_ip": "192.0.2.10",
    "source_mac": None
}

result = engine.handle_decision(decision, packet)

print("\n--- EXCEPTION HANDLING TEST ---")
print(result)

assert result["block_success"] is False
assert result["status"] == "Block failed: unexpected error"

print("\nTEST PASSED: Firewall exception handled safely.")
