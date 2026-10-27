from response_engine.response_engine import ResponseEngine

engine = ResponseEngine(dry_run=True)

# Select an IPv4 address that the engine identifies as local.
local_ips = engine.get_local_ips()
local_ipv4_addresses = [
    ip for ip in local_ips
    if "." in ip and ":" not in ip
]

assert local_ipv4_addresses, "No local IPv4 addresses were detected."

local_ip = next(
    (ip for ip in local_ipv4_addresses if ip != "127.0.0.1"),
    "127.0.0.1"
)

decision = {
    "action": "BLOCK"
}

packet = {
    "source_ip": local_ip,
    "source_mac": None
}

result = engine.handle_decision(decision, packet)

print("\n--- LOCAL IP PROTECTION TEST ---")
print("Test IP:", local_ip)
print(result)

assert result["status"] == "Protected local IP", (
    f"Expected local IP protection, got: {result['status']}"
)

print("\nTEST PASSED: Local IP blocking was prevented.")