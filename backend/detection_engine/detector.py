from threat_rules import check_rules
from scorer import calculate_score


def analyze_packet(packet):
    """Analyze a packet and determine whether it is suspicious."""

    reasons = check_rules(packet)

    score = calculate_score(reasons)

    return {
        "packet": packet,
        "score": score,
        "is_suspicious": score >= 50,
        "reasons": reasons
    }