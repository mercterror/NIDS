
from sniffer.sniffer import PacketSniffer


def main():
    print("\n=== TEST 1: DEFAULT MODE ===")
    default_sniffer = PacketSniffer()
    assert default_sniffer.response_engine.dry_run is True
    print("PASS: Default mode is dry-run.")

    print("\n=== TEST 2: EXPLICIT DRY-RUN ===")
    safe_sniffer = PacketSniffer(dry_run=True)
    assert safe_sniffer.response_engine.dry_run is True
    print("PASS: Explicit dry-run mode works.")

    print("\n=== TEST 3: EXPLICIT REAL MODE CONFIGURATION ===")
    real_mode_sniffer = PacketSniffer(dry_run=False)
    assert real_mode_sniffer.response_engine.dry_run is False
    print("PASS: Real mode can be explicitly selected.")
    print("No packets were captured and no firewall rules were changed.")

    print("\nALL RESPONSE MODE TESTS PASSED")


if __name__ == "__main__":
    main()
