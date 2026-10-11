import subprocess
from response_engine.ip_blocker import IPBlocker
from response_engine.mac_blocker import MACBlocker
import socket,uuid,ipaddress

class ResponseEngine:
    
    
    def __init__(self, dry_run=True):
        self.dry_run = dry_run
        self.ip_blocker = IPBlocker()
        self.mac_blocker = MACBlocker()

    
    
    def get_local_ips(self):
        local_ips = {"127.0.0.1", "::1"}

        try:
            result = subprocess.run(
                ["ipconfig"],
                capture_output=True,
                text=True,
                check=True
            )

            for line in result.stdout.splitlines():
                line = line.strip()

                if ":" not in line:
                    continue

                label, value = line.split(":", 1)
                label = label.strip().lower()
                value = value.strip().split("%")[0]

                if (
                    "ipv4 address" in label
                    or "ipv6 address" in label
                ):
                    if self.is_valid_ip(value):
                        local_ips.add(value)

        except (OSError, subprocess.SubprocessError) as error:
            print(f"[WARNING] Could not discover local IPs: {error}")

        return local_ips



    def get_local_mac(self):
        mac = uuid.getnode()
        mac_address = ":".join(
            f"{(mac >> i) & 0xff:02X}"
            for i in range(40, -1, -8)
        )
        return mac_address

    def is_valid_ip(self, ip_address):
        if not ip_address:
            return False

        try:
            ipaddress.ip_address(ip_address)
            return True
        except ValueError:
            return False

    def handle_decision(self, decision, packet):
        
        if not isinstance(decision, dict):
            return {
                "action": "BLOCK",
                "status": "Block failed: invalid decision",
                "block_success": False
            }

        if decision.get("action") != "BLOCK":
            return {
                "action": "ALLOW",
                "status": "No action required"
            }


        source_ip = packet.get("source_ip")
        source_mac = packet.get("source_mac")

        local_ips = self.get_local_ips()
        local_mac = self.get_local_mac()

        if not self.is_valid_ip(source_ip):
            return {
                "action": "BLOCK",
                "status": "Block failed: missing or invalid source IP",
                "source_ip": source_ip,
                "source_mac": source_mac,
                "block_success": False
            }

        if source_ip in local_ips: 
            print("\n[PROTECTION] Block request targets the NIDS machine.")
            print("[PROTECTION] Blocking skipped.")

            return {
                "action": "BLOCK",
                "status": "Protected local IP",
                "source_ip": source_ip,
                "source_mac": source_mac
            }

        if source_mac and source_mac.upper() == local_mac.upper():
            print("\n[PROTECTION] Block request targets the NIDS machine MAC.")
            print("[PROTECTION] MAC blocking skipped.")

            return {
                "action": "BLOCK",
                "status": "Protected local MAC",
                "source_ip": source_ip,
                "source_mac": source_mac
            }

        if self.dry_run:
            print("\n[DRY RUN] BLOCK requested")
            print(f"[DRY RUN] Source IP  : {source_ip}")
            print(f"[DRY RUN] Source MAC : {source_mac}")

            return {
                "action": "BLOCK",
                "status": "Block simulated",
                "source_ip": source_ip,
                "source_mac": source_mac
            }

        
        try:
           
            ip_version = ipaddress.ip_address(source_ip).version

            if ip_version != 4:
                return {
                    "action": "BLOCK",
                    "source_ip": source_ip,
                    "source_mac": source_mac,
                    "block_success": False,
                    "status": "Block failed: IPv6 blocking is not implemented"
                }

            ip_result = self.ip_blocker.block_ip(source_ip)


            return {
                "action": "BLOCK",
                "source_ip": source_ip,
                "source_mac": source_mac,
                "ip_blocking": ip_result,
                "block_success": block_success,
                "status": status
            }

        except Exception as error:
            print(f"\n[ERROR] IP blocking failed: {error}")

            return {
                "action": "BLOCK",
                "source_ip": source_ip,
                "source_mac": source_mac,
                "block_success": False,
                "status": "Block failed: unexpected error"
            }

        