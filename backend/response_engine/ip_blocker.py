import subprocess
import ipaddress

class IPBlocker:

   
    def _is_local_ip(self, ip_address):
        local_ips = {"127.0.0.1"}

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

                if "ipv4 address" in label:
                    try:
                        ipaddress.ip_address(value)
                        local_ips.add(value)
                    except ValueError:
                        continue

        except (OSError, subprocess.SubprocessError):
            # Fail safely if local addresses cannot be discovered.
            return True

        return ip_address in local_ips

  
    def block_ip(self, ip_address):
        # Validate input before running any firewall command.
        try:
            if not isinstance(ip_address, str) or not ip_address.strip():
                raise ValueError("Invalid IP address")

            parsed_ip = ipaddress.ip_address(ip_address)

            if parsed_ip.version != 4:
                raise ValueError("Only IPv4 blocking is supported")

        except ValueError as error:
            return {
                "success": False,
                "message": str(error)
            }

        # Protect local IP addresses before running firewall commands.
        if self._is_local_ip(ip_address):
            return {
                "success": False,
                "message": "Blocking local IP addresses is not allowed"
            }

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