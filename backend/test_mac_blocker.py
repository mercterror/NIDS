from response_engine.mac_blocker import MACBlocker

blocker = MACBlocker()
test_mac = "AA:BB:CC:DD:EE:FF"

print("\n--- MAC BLOCK TEST ---")
result = blocker.block_mac(test_mac)
print(result)