from response_engine.ip_blocker import IPBlocker
from response_engine.mac_blocker import MACBlocker

ip_result = IPBlocker().unblock_ip("192.0.2.10")
mac_result = MACBlocker().unblock_mac("AA:BB:CC:DD:EE:FF")

print("IP cleanup:", ip_result)
print("MAC cleanup:", mac_result)