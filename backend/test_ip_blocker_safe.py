from unittest.mock import patch, Mock
from response_engine.ip_blocker import IPBlocker

blocker = IPBlocker()

print("\n=== TEST 1: EXISTING RULE ===")

with patch("response_engine.ip_blocker.subprocess.run") as mock_run:
    mock_run.side_effect = [
        Mock(
            returncode=0,
            stdout="IPv4 Address. . . . . . . . . . . : 192.168.29.146",
            stderr=""
        ),
        Mock(
            returncode=0,
            stdout="Rule Name: NIDS_BLOCK_192.0.2.10",
            stderr=""
        )
    ]

    result = blocker.block_ip("192.0.2.10")

    print(result)
    assert result["success"] is True
    assert "already has a firewall rule" in result["message"]
    assert mock_run.call_count == 2

print("PASS: Existing rule prevented a duplicate add.")



print("\n=== TEST 2: NEW RULE ===")

with patch("response_engine.ip_blocker.subprocess.run") as mock_run:
    mock_run.side_effect = [
        Mock(
            returncode=0,
            stdout="IPv4 Address. . . . . . . . . . . : 192.168.29.146",
            stderr=""
        ),
        Mock(
            returncode=0,
            stdout="No rules match the specified criteria.",
            stderr=""
        ),
        Mock(returncode=0, stdout="Ok.", stderr="")
    ]
    result = blocker.block_ip("192.0.2.10")

    print(result)
    assert result["success"] is True
    assert "blocked" in result["message"]
    assert mock_run.call_count == 3

print("PASS: A missing rule was added successfully in the mock.")


print("\n=== TEST 3: FIREWALL ADD FAILURE ===")

with patch("response_engine.ip_blocker.subprocess.run") as mock_run:
    mock_run.side_effect = [
        Mock(
            returncode=0,
            stdout="IPv4 Address. . . . . . . . . . . : 192.168.29.146",
            stderr=""
        ),
        Mock(
            returncode=0,
            stdout="No rules match the specified criteria.",
            stderr=""
        ),
        Mock(returncode=1, stdout="", stderr="Access is denied.")
    ]

    result = blocker.block_ip("192.0.2.10")

    print(result)
    assert result["success"] is False
    assert "Access is denied" in result["message"]

print("PASS: Firewall command failure was reported.")



print("\n=== TEST 4: CLEANUP ===")

with patch("response_engine.ip_blocker.subprocess.run") as mock_run:
    mock_run.side_effect = [
        Mock(
            returncode=0,
            stdout="IPv4 Address. . . . . . . . . . . : 192.168.29.146",
            stderr=""
        ),
        Mock(
            returncode=0,
            stdout="Deleted 1 rule(s).",
            stderr=""
        )
    ]

    result = blocker.unblock_ip("192.0.2.10")

    print(result)
    assert result["success"] is True
    assert mock_run.call_count == 2
    assert mock_run.call_args_list[0].args[0] == ["ipconfig"]
    assert mock_run.call_args_list[1].args[0][0] == "netsh"

print("PASS: Cleanup result was handled.")


print("\n=== TEST 5: INVALID IP REJECTION ===")

invalid_ips = [
    None,
    "",
    "not-an-ip",
    "999.999.999.999",
]

for invalid_ip in invalid_ips:
    with patch("response_engine.ip_blocker.subprocess.run") as mock_run:
        try:
            blocker.block_ip(invalid_ip)
        except (ValueError, TypeError):
            pass

        assert mock_run.call_count == 0, (
            f"Firewall command was invoked for invalid IP: {invalid_ip!r}"
        )

print("PASS: No firewall commands were run for invalid IP inputs.")



print("\n=== TEST 6: INVALID IP CLEANUP ===")

invalid_ips = [
    None,
    "",
    "not-an-ip",
    "999.999.999.999",
]

for invalid_ip in invalid_ips:
    with patch("response_engine.ip_blocker.subprocess.run") as mock_run:
        result = blocker.unblock_ip(invalid_ip)

        assert result["success"] is False
        assert mock_run.call_count == 0, (
            f"Firewall command was invoked for invalid IP: {invalid_ip!r}"
        )

print("PASS: Invalid IP cleanup was rejected.")


print("\n=== TEST 7: LOCAL IP CLEANUP ===")

local_ip = "192.168.29.146"

mock_ipconfig = Mock(
    returncode=0,
    stdout="IPv4 Address. . . . . . . . . . . : 192.168.29.146",
    stderr=""
)

with patch(
    "response_engine.ip_blocker.subprocess.run",
    return_value=mock_ipconfig
) as mock_run:
    result = blocker.unblock_ip(local_ip)

    print(result)

    assert result["success"] is False
    assert result["message"] == (
        "Cleanup of local IP addresses is not allowed"
    )
    assert mock_run.call_count == 1
    assert mock_run.call_args.args[0] == ["ipconfig"]

print("PASS: Local IP cleanup was rejected.")
print("PASS: No firewall deletion command was executed.")
