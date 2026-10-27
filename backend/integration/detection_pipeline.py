from detection_engine.detector import analyze_packet
from integration.traffic_adapter import TrafficAdapter
from ml.feature_extractor import FeatureExtractor
from ml.predictor import NIDSPredictor
from integration.final_decision import make_final_decision


class DetectionPipeline:

    def __init__(self):
        self.adapter = TrafficAdapter()
        self.feature_extractor = FeatureExtractor()
        self.predictor = NIDSPredictor()

    def analyze(self, packet, flow):

        # Rule-based detection
        rule_result = analyze_packet(packet)

        # Adapt simulator data
        packet_data = self.adapter.adapt_packet(packet)
        flow_features = self.adapter.adapt_flow(flow)

        # Extract ML features
        features = self.feature_extractor.extract_features(
            packet_data,
            flow_features
        )

        # AI detection
        ai_result = self.predictor.predict(features)

        decision = make_final_decision(
            rule_result,
            ai_result
        )

        return {
            "packet": packet,

            "rule_detection": {
                "score": rule_result["score"],
                "is_suspicious": rule_result["is_suspicious"],
                "reasons": rule_result["reasons"]
            },

            "ai_detection": ai_result,

            "final_verdict": decision["final_verdict"],
            "action": decision["action"]
        }