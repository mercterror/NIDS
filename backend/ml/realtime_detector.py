import joblib
import pandas as pd
from backend.rules.rule_engine import RuleEngine

from backend.alerts.telegram_alert import TelegramAlert
from backend.database.database import IDSDatabase


class RealtimeDetector:

    def __init__(self):

        self.model = None
        self.label_encoder = None

        try:
            self.model = joblib.load(
                "models/nids_model.pkl"
            )

            self.label_encoder = joblib.load(
                "models/label_encoder.pkl"
            )

            print("[+] AI Model Loaded")

        except Exception as e:
            print(f"[MODEL LOAD ERROR] {e}")
            print("[!] Running in RULE-ONLY mode")

        # TELEGRAM ALERT SYSTEM
        self.telegram = TelegramAlert()

        # DATABASE
        self.db = IDSDatabase()



    # =========================
    # AI PREDICTION
    # =========================

    def ai_detection(self, features):
        if self.model is None:
            
            return None
        try:
            # CREATE DATAFRAME
            df = pd.DataFrame([features])

            # REMOVE NON-NUMERIC FIELDS
            drop_columns = ["timestamp", "src_ip", "dst_ip", "protocol"]

            for col in drop_columns:
                if col in df.columns:
                    df.drop(columns=[col], inplace=True)

            # PREDICTION
            prediction = self.model.predict(df)[0]
            confidence = max(self.model.predict_proba(df)[0]) * 100
            label = self.label_encoder.inverse_transform([prediction])[0]

            return {
                "prediction": label,
                "confidence": round(confidence, 2)
            }

        except Exception as e:
            print(f"[AI ERROR] {e}")
            return None

    # =========================
    # HYBRID DETECTION
    # =========================

    def detect_attack(self, features):
        # RULE ENGINE
        rule_result = self.rule_engine.detect(features)

        # AI ENGINE
        ai_result = self.ai_detection(features)

        # =========================
        # RULE DETECTED
        # =========================

        if rule_result["attack_detected"]:
            attack_data = {
                "timestamp": rule_result["timestamp"],
                "src_ip": features.get("src_ip"),
                "dst_ip": features.get("dst_ip"),
                "protocol": features.get("protocol"),
                "attack_type": rule_result["attack_type"],
                "severity": rule_result["severity"],
                "threat_score": rule_result["threat_score"],
                "confidence": rule_result["confidence"],
                "status": "detected"
            }

            # SAVE TO DATABASE
            self.db.insert_attack_log(attack_data)

            # SEND TELEGRAM ALERT
            self.telegram.send_attack_alert(attack_data)

            print(f"[ALERT] {attack_data['attack_type']}")
            return attack_data

        # =========================
        # AI DETECTED
        # =========================

        if ai_result:
            if ai_result["prediction"] != "normal":
                attack_data = {
                    "src_ip": features.get("src_ip"),
                    "dst_ip": features.get("dst_ip"),
                    "protocol": features.get("protocol"),
                    "attack_type": ai_result["prediction"],
                    "severity": "MEDIUM",
                    "threat_score": 75,
                    "confidence": ai_result["confidence"]
                }

                # SAVE TO DATABASE
                self.db.insert_attack_log(attack_data)

                # SEND ALERT
                self.telegram.send_attack_alert(attack_data)

                print(f"[AI ALERT] {attack_data['attack_type']}")
                return attack_data

        return None