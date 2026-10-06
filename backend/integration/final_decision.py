AI_CONFIDENCE_THRESHOLD = 0.80


def make_final_decision(rule_result, ai_result):

    rule_suspicious = rule_result["is_suspicious"]

    ai_attack = (
        ai_result["label"] != "normal"
        and ai_result["confidence"] >= AI_CONFIDENCE_THRESHOLD
    )

    if rule_suspicious or ai_attack:
        return {
            "final_verdict": "MALICIOUS",
            "action": "BLOCK"
        }

    return {
        "final_verdict": "NORMAL",
        "action": "ALLOW"
    }