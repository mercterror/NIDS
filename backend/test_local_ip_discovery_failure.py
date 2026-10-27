
from response_engine.response_engine import ResponseEngine


engine = ResponseEngine(dry_run=False)

# Simulate failure to discover the machine's local IP addresses.
def failed_local_ip_discovery():
    engine.local_ip_discovery_success = False
    return {"127.0.0.1", "::1"}


# Fail the test immediately if real IP blocking is attempted.
def unexpected_ip_block(source_ip):
    raise AssertionError(
        f"IP blocker must not be called after discovery fails: {source_ip}"
    )


engine.get_local_ips = failed_local_ip_discovery
engine.ip_blocker.block_ip = unexpected_ip_block

result = engine.handle_decision(
    {"action": "BLOCK"},
    {
        "source_ip": "192.0.2.10",
        "source_mac": "AA:BB:CC:DD:EE:FF",
    },
)

print("\n--- LOCAL IP DISCOVERY FAILURE TEST ---")
print(result)

assert result["block_success"] is False
assert "local IP discovery failed" in result["status"]
assert engine.local_ip_discovery_success is False

print("PASS: Blocking was refused after local IP discovery failed.")
