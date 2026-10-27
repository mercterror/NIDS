
from response_engine.ip_blocker import IPBlocker

blocker = IPBlocker()
test_ip = "192.0.2.10"

print("\n--- FIRST BLOCK REQUEST ---")
first_result = blocker.block_ip(test_ip)
print(first_result)

print("\n--- SECOND BLOCK REQUEST ---")
second_result = blocker.block_ip(test_ip)
print(second_result)

print("\n--- CLEANUP ---")
cleanup_result = blocker.unblock_ip(test_ip)
print(cleanup_result)
