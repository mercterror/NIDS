
from integration.final_decision import make_final_decision
from response_engine.response_engine import ResponseEngine

engine = ResponseEngine(dry_run=True)

# Simulate a malicious detection
rule_result = {
    "is_suspicious": True
}

ai_result = {
    "label": "normal",
    "confidence": 0.95
}

decision = make_final_decision(rule_result, ai_result)

packet = {
    "source_ip": "192.0.2.10",
    "source_mac": None
}

print("\n--- FINAL DECISION ---")
print(decision)

print("\n--- RESPONSE ENGINE ---")
result = engine.handle_decision(decision, packet)
print(result)

assert decision["action"] == "BLOCK"
assert result["status"] == "Block simulated"

print("\nTEST PASSED: Final decision connected to response engine.")
