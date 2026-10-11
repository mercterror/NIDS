import subprocess


class MACBlocker:

    def block_mac(self, mac_address):
        rule_name = f"NIDS_MAC_BLOCK_{mac_address}"

        command = [
            "netsh",
            "advfirewall",
            "firewall",
            "add",
            "rule",
            f"name={rule_name}",
            "dir=in",
            "action=block",
            "remoteip=any",
            f"remoteMAC={mac_address}",
            "protocol=any"
        ]

        result = subprocess.run(
            command,
            capture_output=True,
            text=True
        )

        if result.returncode == 0:
            return {
                "success": True,
                "message": f"MAC {mac_address} blocked",
                "rule_name": rule_name
            }

        return {
            "success": False,
            "message": (
                result.stderr.strip()
                or result.stdout.strip()
                or f"netsh exited with code {result.returncode}"
            )
        }

    def unblock_mac(self, mac_address):
        rule_name = f"NIDS_MAC_BLOCK_{mac_address}"

        command = [
            "netsh",
            "advfirewall",
            "firewall",
            "delete",
            "rule",
            f"name={rule_name}"
        ]

        result = subprocess.run(
            command,
            capture_output=True,
            text=True
        )

        return {
            "success": result.returncode == 0,
            "message": result.stdout.strip() or result.stderr.strip()
        }