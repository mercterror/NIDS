from detection_engine.threat_rules import check_rules
from detection_engine.scorer import calculate_score


def analyze_packet(packet):
    """Analyze a packet and determine whether it is suspicious."""

    # Check the packet against all IDS rules
    reasons = check_rules(packet)

    # Calculate the overall threat score
    score = calculate_score(reasons)

    # Store the analysis result
    result = {
        "packet": packet,
        "score": score,
        "is_suspicious": score >= 50,
        "reasons": reasons
    }

    return result