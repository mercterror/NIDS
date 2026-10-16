
import ipaddress
import subprocess
import uuid

from response_engine.ip_blocker import IPBlocker
from response_engine.mac_blocker import MACBlocker


class ResponseEngine:
    def __init__(self, dry_run=True):
        self.dry_run = dry_run
        self.ip_blocker = IPBlocker()
        self.mac_blocker = MACBlocker()
        self.local_ip_discovery_success = False

    
    def get_local_ips(self):
        local_ips = {"127.0.0.1", "::1"}
        self.local_ip_discovery_success = False

        try:
            result = subprocess.run(
                ["ipconfig"],
                capture_output=True,
                text=True,
                check=True,
                timeout=10,
            )

            for line in result.stdout.splitlines():
                line = line.strip()

                if ":" not in line:
                    continue

                label, value = line.split(":", 1)
                label = label.strip().lower()
                value = value.strip().split("%")[0]

                if "ipv4 address" in label or "ipv6 address" in label:
                    if self.is_valid_ip(value):
                        local_ips.add(
                            str(ipaddress.ip_address(value))
                        )

            self.local_ip_discovery_success = True

        except (OSError, subprocess.SubprocessError) as error:
            print(f"[WARNING] Could not discover local IPs: {error}")

        return local_ips

    @staticmethod
    def get_local_mac():
        mac = uuid.getnode()

        # Refuse to trust a potentially randomly generated MAC.
        if mac & (1 << 40):
            return None

        return ":".join(
            f"{(mac >> shift) & 0xFF:02X}"
            for shift in range(40, -1, -8)
        )

    @staticmethod
    def is_valid_ip(ip_address):
        if not isinstance(ip_address, str) or not ip_address.strip():
            return False

        try:
            ipaddress.ip_address(ip_address.strip())
            return True
        except ValueError:
            return False

    @staticmethod
    def normalize_mac(mac_address):
        if not isinstance(mac_address, str):
            return None

        normalized = mac_address.strip().upper().replace("-", ":")

        parts = normalized.split(":")

        if len(parts) != 6:
            return None

        if any(
            len(part) != 2
            or any(char not in "0123456789ABCDEF" for char in part)
            for part in parts
        ):
            return None

        return normalized

    @staticmethod
    def _response(
        status,
        source_ip=None,
        source_mac=None,
        block_success=False,
        **extra,
    ):
        result = {
            "action": "BLOCK",
            "status": status,
            "source_ip": source_ip,
            "source_mac": source_mac,
            "block_success": block_success,
        }
        result.update(extra)
        return result

    def handle_decision(self, decision, packet):
        if not isinstance(decision, dict):
            return self._response("Block failed: invalid decision")

        if decision.get("action") != "BLOCK":
            return {
                "action": "ALLOW",
                "status": "No action required",
                "block_success": False,
            }

        if not isinstance(packet, dict):
            return self._response("Block failed: invalid packet")

        source_ip = packet.get("source_ip")
        source_mac = packet.get("source_mac")

        if not self.is_valid_ip(source_ip):
            return self._response(
                "Block failed: missing or invalid source IP",
                source_ip,
                source_mac,
            )

        parsed_ip = ipaddress.ip_address(source_ip.strip())
        source_ip = str(parsed_ip)

        # Dry-run must never execute a firewall-blocking command.
        if self.dry_run:
            local_ips = self.get_local_ips()
            discovery_success = self.local_ip_discovery_success

            if discovery_success and source_ip in local_ips:
                return self._response(
                    "Protected local IP",
                    source_ip,
                    source_mac,
                )

            print("\n[DRY RUN] BLOCK requested")
            print(f"[DRY RUN] Source IP  : {source_ip}")
            print(f"[DRY RUN] Source MAC : {source_mac}")

            return self._response(
                "Block simulated",
                source_ip,
                source_mac,
                dry_run=True,
            )

        # Real blocking requires successful local IP discovery.
        local_ips = self.get_local_ips()
        discovery_success = self.local_ip_discovery_success

        if not discovery_success:
            return self._response(
                "Block failed: local IP discovery failed; blocking refused",
                source_ip,
                source_mac,
            )

        if source_ip in local_ips:
            print("\n[PROTECTION] Block request targets the NIDS machine.")
            print("[PROTECTION] Blocking skipped.")

            return self._response(
                "Protected local IP",
                source_ip,
                source_mac,
            )

        normalized_source_mac = self.normalize_mac(source_mac)
        local_mac = self.get_local_mac()

        if (
            normalized_source_mac is not None
            and local_mac is not None
            and normalized_source_mac == local_mac
        ):
            print("\n[PROTECTION] Block request targets the NIDS machine MAC.")
            print("[PROTECTION] Blocking skipped.")

            return self._response(
                "Protected local MAC",
                source_ip,
                source_mac,
            )

        if parsed_ip.version != 4:
            return self._response(
                "Block failed: IPv6 blocking is not implemented",
                source_ip,
                source_mac,
            )

        try:
            ip_result = self.ip_blocker.block_ip(source_ip)

            if not isinstance(ip_result, dict):
                return self._response(
                    "Block failed: invalid IP blocker response",
                    source_ip,
                    source_mac,
                    ip_blocking=ip_result,
                )

            ip_success = ip_result.get("success") is True
            ip_message = ip_result.get(
                "message",
                "Unknown blocking result",
            )

            # MAC blocking remains unavailable until a supported
            # mechanism is implemented and verified.
            mac_result = {
                "success": False,
                "message": (
                    "MAC blocking unavailable: no verified supported "
                    "blocking mechanism is configured"
                ),
            }

            if ip_success:
                status = "IP blocked; MAC blocking unavailable"
            else:
                status = f"IP blocking failed: {ip_message}"

            return self._response(
                status,
                source_ip,
                source_mac,
                block_success=ip_success,
                ip_blocking=ip_result,
                mac_blocking=mac_result,
            )

        except Exception as error:
            print(f"\n[ERROR] IP blocking failed: {error}")

            return self._response(
                "Block failed: unexpected error",
                source_ip,
                source_mac,
            )
