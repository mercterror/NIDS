
from response_engine.response_engine import ResponseEngine

engine = ResponseEngine(dry_run=True)

local_ips = engine.get_local_ips()

print("\n--- LOCAL IP DETECTION TEST ---")
print("Detected local IP addresses:")

for ip_address in sorted(local_ips):
    print(ip_address)

print("\nLoopback protection:", "127.0.0.1" in local_ips)
