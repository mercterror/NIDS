import subprocess


class IPBlocker:

   
    def block_ip(self, ip_address):
        rule_name = f"NIDS_BLOCK_{ip_address}"

        check_command = [
            "netsh",
            "advfirewall",
            "firewall",
            "show",
            "rule",
            f"name={rule_name}"
        ]

        check_result = subprocess.run(
            check_command,
            capture_output=True,
            text=True
        )

        if check_result.returncode == 0 and "No rules match" not in (
            check_result.stdout + check_result.stderr
        ):
            return {
                "success": True,
                "message": f"IP {ip_address} already has a firewall rule",
                "rule_name": rule_name
            }

        command = [
            "netsh",
            "advfirewall",
            "firewall",
            "add",
            "rule",
            f"name={rule_name}",
            "dir=in",
            "action=block",
            f"remoteip={ip_address}",
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
                "message": f"IP {ip_address} blocked",
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


    def unblock_ip(self, ip_address):
        rule_name = f"NIDS_BLOCK_{ip_address}"

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