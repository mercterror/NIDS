THREAT_SCORES = {
    "Uses Telnet": 40,
    "Large Packet": 20,
    "Uses FTP": 30,
    "ICMP Traffic": 10,
    "Large ICMP Packet": 25,
    "High Destination Port": 15,
    "High Source Port": 10,
    "Same Source and Destination Port": 20,
    "HTTP over UDP": 35,
    "HTTPS over UDP": 35,
    "DNS over TCP": 15,
}

def calculate_score(reasons):
    """Calculate the total threat score."""

    score = 0

    for reason in reasons:
        score += THREAT_SCORES.get(reason, 0)

    return score

# sample_reasons = [
#     "Uses Telnet",
#     "Large Packet",
#     "ICMP Traffic"
# ]

# print(calculate_score(sample_reasons))