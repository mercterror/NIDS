
import ipaddress
import subprocess

from response_engine.response_engine import ResponseEngine


TEST_IP = "192.0.2.10"
RULE_NAME = f"NIDS_BLOCK_{TEST_IP}"


def verify_rule_exists():
    result = subprocess.run(
        [
            "netsh",
            "advfirewall",
            "firewall",
            "show",
            "rule",
            f"name={RULE_NAME}",
        ],
        capture_output=True,
        text=True,
        timeout=10,
    )

    output = result.stdout + result.stderr

    return (
        result.returncode == 0
        and RULE_NAME.lower() in output.lower()
        and "Enabled:" in output
        and "Yes" in output
        and "Action:" in output
        and "Block" in output
        and f"{TEST_IP}/32" in output
    )


def verify_rule_removed():
    result = subprocess.run(
        [
            "netsh",
            "advfirewall",
            "firewall",
            "show",
            "rule",
            f"name={RULE_NAME}",
        ],
        capture_output=True,
        text=True,
        timeout=10,
    )

    output = result.stdout + result.stderr
    return "No rules match" in output


def main():
    parsed_ip = ipaddress.ip_address(TEST_IP)

    if parsed_ip.version != 4 or not parsed_ip.is_private:
        raise RuntimeError("The test IP is not an approved test address.")

    engine = ResponseEngine(dry_run=False)

    local_ips = engine.get_local_ips()

    if not engine.local_ip_discovery_success:
        raise RuntimeError(
            "Local IP discovery failed. Real blocking test refused."
        )

    if TEST_IP in local_ips:
        raise RuntimeError(
            "Test IP unexpectedly matches a local IP. Test refused."
        )

    print("\n=== REAL RESPONSE ENGINE TEST ===")
    print("Test IP:", TEST_IP)
    print("Live sniffer is not started by this test.")

    # Never leave a test rule behind, even if verification fails.
    try:
        print("\n=== STEP 1: REQUEST BLOCK THROUGH RESPONSE ENGINE ===")

        result = engine.handle_decision(
            {"action": "BLOCK"},
            {
                "source_ip": TEST_IP,
                "source_mac": None,
            },
        )

        print(result)

        if result.get("block_success") is not True:
            raise RuntimeError(
                "Response engine did not report successful IP blocking."
            )

        print("\n=== STEP 2: VERIFY FIREWALL RULE ===")

        if not verify_rule_exists():
            raise RuntimeError(
                "The expected enabled firewall block rule was not found."
            )

        print("PASS: Firewall rule exists and is enabled.")

    finally:
        print("\n=== CLEANUP: REMOVE TEST RULE ===")

        cleanup = engine.ip_blocker.unblock_ip(TEST_IP)
        print(cleanup)

        if not cleanup.get("success"):
            print(
                "WARNING: Cleanup reported failure. "
                "Check the firewall rule manually."
            )
            print(
                f'Run as Administrator: netsh advfirewall firewall '
                f'delete rule name="{RULE_NAME}"'
            )
            raise RuntimeError("Test rule cleanup failed.")

        if not verify_rule_removed():
            print(
                "WARNING: Rule removal could not be confirmed. "
                "Check Windows Firewall manually."
            )
            raise RuntimeError("Test rule may still exist.")

        print("PASS: Test rule removal confirmed.")

    print("\nPASS: Real response-engine test completed.")


if __name__ == "__main__":
    main()
