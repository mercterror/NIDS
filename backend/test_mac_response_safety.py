from response_engine.response_engine import ResponseEngine

engine = ResponseEngine(dry_run=True)

# Replace the MAC blocker with a function that fails if called.
def unexpected_mac_block(mac_address):
    raise AssertionError(
        f"MAC blocking should not be called in dry-run mode: {mac_address}"
    )

engine.mac_blocker.block_mac = unexpected_mac_block

decision = {"action": "BLOCK"}

packet = {
    "source_ip": "192.0.2.10",
    "source_mac": "AA:BB:CC:DD:EE:FF"
}

result = engine.handle_decision(decision, packet)

print("\n--- MAC RESPONSE SAFETY TEST ---")
print(result)

assert result["status"] == "Block simulated"

print("PASS: MAC blocker was not called in dry-run mode.")
print("MAC RESPONSE SAFETY TEST PASSED")