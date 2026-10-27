import re
import subprocess
import uuid


class MACBlocker:
    def __init__(self):
        pass

    @staticmethod
    def _normalize_mac(mac_address):
        if not isinstance(mac_address, str):
            return None

        mac_address = mac_address.strip().upper()

        # Accept colon-separated or hyphen-separated MAC addresses.
        if not re.fullmatch(
            r"(?:[0-9A-F]{2}[:-]){5}[0-9A-F]{2}",
            mac_address,
        ):
            return None

        return mac_address.replace("-", ":")

    @staticmethod
    def _get_local_mac():
        mac = uuid.getnode()

        # uuid.getnode() may return a random MAC if detection fails.
        # Do not use a potentially random address as a safety guarantee.
        if mac & (1 << 40):
            return None

        return ":".join(
            f"{(mac >> shift) & 0xFF:02X}"
            for shift in range(40, -1, -8)
        )

    def block_mac(self, mac_address):
        normalized_mac = self._normalize_mac(mac_address)

        if normalized_mac is None:
            return {
                "success": False,
                "message": "Invalid MAC address",
            }

        local_mac = self._get_local_mac()

        if local_mac is None:
            return {
                "success": False,
                "message": (
                    "Could not safely identify the local MAC address; "
                    "blocking refused"
                ),
            }

        if normalized_mac == local_mac:
            return {
                "success": False,
                "message": "Blocking the local MAC address is not allowed",
            }

        rule_name = f"NIDS_MAC_BLOCK_{normalized_mac}"

        command = [
            "netsh",
            "advfirewall",
            "firewall",
            "add",
            "rule",
            f"name={rule_name}",
            "dir=in",
            "action=block",
            "remoteMAC=" + normalized_mac,
            "protocol=any",
        ]

        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=15,
            )
        except (OSError, subprocess.SubprocessError) as error:
            return {
                "success": False,
                "message": f"Firewall command failed: {error}",
            }

        if result.returncode == 0:
            return {
                "success": True,
                "message": f"MAC {normalized_mac} blocked",
                "rule_name": rule_name,
            }

        return {
            "success": False,
            "message": (
                result.stderr.strip()
                or result.stdout.strip()
                or f"netsh exited with code {result.returncode}"
            ),
        }

    def unblock_mac(self, mac_address):
        normalized_mac = self._normalize_mac(mac_address)

        if normalized_mac is None:
            return {
                "success": False,
                "message": "Invalid MAC address",
            }

        local_mac = self._get_local_mac()

        if local_mac is None:
            return {
                "success": False,
                "message": (
                    "Could not safely identify the local MAC address; "
                    "cleanup refused"
                ),
            }

        if normalized_mac == local_mac:
            return {
                "success": False,
                "message": "Cleanup of the local MAC address is not allowed",
            }

        rule_name = f"NIDS_MAC_BLOCK_{normalized_mac}"

        command = [
            "netsh",
            "advfirewall",
            "firewall",
            "delete",
            "rule",
            f"name={rule_name}",
        ]

        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=15,
            )
        except (OSError, subprocess.SubprocessError) as error:
            return {
                "success": False,
                "message": f"Firewall cleanup failed: {error}",
            }

        if result.returncode == 0:
            return {
                "success": True,
                "message": (
                    result.stdout.strip()
                    or f"MAC blocking rule {rule_name} deleted"
                ),
                "rule_name": rule_name,
            }

        return {
            "success": False,
            "message": (
                result.stderr.strip()
                or result.stdout.strip()
                or f"netsh exited with code {result.returncode}"
            ),
        }