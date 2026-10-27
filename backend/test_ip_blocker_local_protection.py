
from unittest.mock import patch, Mock

from response_engine.ip_blocker import IPBlocker


blocker = IPBlocker()
local_ip = "192.168.29.146"

print("\n=== TEST: DIRECT LOCAL-IP BLOCKING ===")

mock_ipconfig = Mock()
mock_ipconfig.returncode = 0
mock_ipconfig.stdout = """
   IPv4 Address. . . . . . . . . . . : 192.168.29.146
"""
mock_ipconfig.stderr = ""

with patch(
    "response_engine.ip_blocker.subprocess.run",
    return_value=mock_ipconfig
) as mock_run:
    result = blocker.block_ip(local_ip)

    print(result)

    assert result["success"] is False
    assert result["message"] == (
        "Blocking local IP addresses is not allowed"
    )

    # Only the ipconfig lookup should have occurred.
    assert mock_run.call_count == 1
    assert mock_run.call_args.args[0] == ["ipconfig"]

print("PASS: Local IP was protected.")
print("PASS: No firewall commands were executed.")
