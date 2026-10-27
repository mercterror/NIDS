from traffic_simulator.simulator import run_simulator
from integration.detection_pipeline import DetectionPipeline


simulation = run_simulator(1)

flow = simulation[0]
packet = flow["packets"][0]

pipeline = DetectionPipeline()

result = pipeline.analyze(
    packet,
    flow
)

print("\n" + "=" * 60)
print("COMBINED DETECTION TEST")
print("=" * 60)

print("\nRule Detection:")
print(f"Score       : {result['rule_detection']['score']}")
print(f"Suspicious  : {result['rule_detection']['is_suspicious']}")
print(f"Reasons     : {result['rule_detection']['reasons']}")

print("\nAI Detection:")
print(f"Prediction  : {result['ai_detection']['label']}")
print(
    f"Confidence  : "
    f"{result['ai_detection']['confidence']:.4f}"
)

print("=" * 60)

print("\nFinal Decision:")
print(f"Verdict     : {result['final_verdict']}")
print(f"Action      : {result['action']}")