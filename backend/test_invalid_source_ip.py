
from response_engine.response_engine import ResponseEngine

engine = ResponseEngine(dry_run=False)

test_cases = [
    None,
    "",
    "not-an-ip",
    "999.999.999.999"
]

for source_ip in test_cases:
    packet = {
        "source_ip": source_ip,
        "source_mac": None
    }

    result = engine.handle_decision(
        {"action": "BLOCK"},
        packet
    )

    print(f"\nInput IP: {source_ip!r}")
    print(result)

    assert result["status"] == (
        "Block failed: missing or invalid source IP"
    )
    assert result["block_success"] is False

print("\nTEST PASSED: Invalid IPs were rejected.")
