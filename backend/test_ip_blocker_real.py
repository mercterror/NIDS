
from response_engine.ip_blocker import IPBlocker

TEST_IP = "192.0.2.10"
RULE_NAME = f"NIDS_BLOCK_{TEST_IP}"

blocker = IPBlocker()

print("\n=== STEP 1: CREATE FIREWALL RULE ===")
result = blocker.block_ip(TEST_IP)
print(result)

if not result.get("success"):
    print("\nTEST STOPPED: Rule creation failed.")
    print("Check the error above and do not continue.")
    raise SystemExit(1)

print("\n=== STEP 2: VERIFY FIREWALL RULE ===")
import subprocess

check = subprocess.run(
    [
        "netsh", "advfirewall", "firewall", "show",
        "rule", f"name={RULE_NAME}",
    ],
    capture_output=True,
    text=True,
    timeout=10,
)

print(check.stdout)
print(check.stderr)

rule_found = (
    check.returncode == 0
    and RULE_NAME.lower() in check.stdout.lower()
    and "Enabled:" in check.stdout
    and "Yes" in check.stdout
    and "Action:" in check.stdout
    and "Block" in check.stdout
)

print("RULE VERIFIED:", rule_found)

print("\n=== STEP 3: CLEAN UP FIREWALL RULE ===")
cleanup = blocker.unblock_ip(TEST_IP)
print(cleanup)

print("\n=== STEP 4: CONFIRM RULE REMOVAL ===")
after = subprocess.run(
    [
        "netsh", "advfirewall", "firewall", "show",
        "rule", f"name={RULE_NAME}",
    ],
    capture_output=True,
    text=True,
    timeout=10,
)

print(after.stdout or after.stderr)

rule_removed = (
    "No rules match" in (after.stdout + after.stderr)
    or (
        after.returncode != 0
        and "No rules match" in (after.stdout + after.stderr)
    )
)

print("RULE REMOVED:", rule_removed)

if rule_found and cleanup.get("success") and rule_removed:
    print("\nPASS: Python rule creation, verification and cleanup succeeded.")
else:
    print("\nCHECK REQUIRED: One or more steps did not pass.")
    raise SystemExit(1)
