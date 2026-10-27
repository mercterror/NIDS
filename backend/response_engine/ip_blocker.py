
import ipaddress
import subprocess


class IPBlocker:
    COMMAND_TIMEOUT = 10

    @staticmethod
    def _validate_ipv4(ip_address):
        if not isinstance(ip_address, str) or not ip_address.strip():
            raise ValueError("Invalid IP address")

        parsed_ip = ipaddress.ip_address(ip_address.strip())

        if parsed_ip.version != 4:
            raise ValueError("Only IPv4 blocking is supported")

        return str(parsed_ip)

    def _get_local_ips(self):
        local_ips = {"127.0.0.1"}

        result = subprocess.run(
            ["ipconfig"],
            capture_output=True,
            text=True,
            check=True,
            timeout=self.COMMAND_TIMEOUT,
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
                    parsed_ip = ipaddress.ip_address(value)
                    if parsed_ip.version == 4:
                        local_ips.add(str(parsed_ip))
                except ValueError:
                    continue

        return local_ips

    def _is_local_ip(self, ip_address):
        try:
            local_ips = self._get_local_ips()
        except (OSError, subprocess.SubprocessError) as error:
            print(
                "[WARNING] Could not safely discover local IPs: "
                f"{error}"
            )
            # Fail safely: never block or clean up when discovery fails.
            return True

        return ip_address in local_ips

    @staticmethod
    def _run_command(command):
        return subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=IPBlocker.COMMAND_TIMEOUT,
        )

    def block_ip(self, ip_address):
        try:
            ip_address = self._validate_ipv4(ip_address)
        except ValueError as error:
            return {
                "success": False,
                "message": str(error),
            }

        if self._is_local_ip(ip_address):
            return {
                "success": False,
                "message": "Blocking local IP addresses is not allowed",
            }

        rule_name = f"NIDS_BLOCK_{ip_address}"

        check_command = [
            "netsh",
            "advfirewall",
            "firewall",
            "show",
            "rule",
            f"name={rule_name}",
        ]

        add_command = [
            "netsh",
            "advfirewall",
            "firewall",
            "add",
            "rule",
            f"name={rule_name}",
            "dir=in",
            "action=block",
            f"remoteip={ip_address}",
            "protocol=any",
        ]

        try:
            check_result = self._run_command(check_command)

            check_output = (
                check_result.stdout + check_result.stderr
            )

            if check_result.returncode == 0:
                if "No rules match" not in check_output:
                    return {
                        "success": True,
                        "message": (
                            f"IP {ip_address} already has a firewall rule"
                        ),
                        "rule_name": rule_name,
                    }

            elif "No rules match" not in check_output:
                return {
                    "success": False,
                    "message": (
                        check_result.stderr.strip()
                        or check_result.stdout.strip()
                        or "Could not verify the existing firewall rule"
                    ),
                }

            result = self._run_command(add_command)

            if result.returncode == 0:
                return {
                    "success": True,
                    "message": f"IP {ip_address} blocked",
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

        except (OSError, subprocess.SubprocessError) as error:
            return {
                "success": False,
                "message": f"Firewall command failed: {error}",
            }

    def unblock_ip(self, ip_address):
        try:
            ip_address = self._validate_ipv4(ip_address)
        except ValueError as error:
            return {
                "success": False,
                "message": str(error),
            }

        if self._is_local_ip(ip_address):
            return {
                "success": False,
                "message": (
                    "Cleanup of local IP addresses is not allowed"
                ),
            }

        rule_name = f"NIDS_BLOCK_{ip_address}"

        command = [
            "netsh",
            "advfirewall",
            "firewall",
            "delete",
            "rule",
            f"name={rule_name}",
        ]

        try:
            result = self._run_command(command)

            if result.returncode == 0:
                return {
                    "success": True,
                    "message": (
                        result.stdout.strip()
                        or f"Firewall rule {rule_name} deleted"
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

        except (OSError, subprocess.SubprocessError) as error:
            return {
                "success": False,
                "message": f"Firewall cleanup failed: {error}",
            }
