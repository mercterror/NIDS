
from response_engine.response_engine import ResponseEngine

engine = ResponseEngine(dry_run=False)

def unexpected_block_call(ip_address):
    raise AssertionError(
        "The blocker should not be called for IPv6"
    )

engine.ip_blocker.block_ip = unexpected_block_call

packet = {
    "source_ip": "2001:db8::10",
    "source_mac": None
}

result = engine.handle_decision(
    {"action": "BLOCK"},
    packet
)

print("\n--- IPv6 SAFEGUARD TEST ---")
print(result)

assert result["block_success"] is False
assert result["status"] == (
    "Block failed: IPv6 blocking is not implemented"
)

print("\nTEST PASSED: IPv6 was rejected before blocking.")
