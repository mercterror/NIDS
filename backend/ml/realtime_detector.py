import time

import joblib
import pandas as pd

from backend.rules.rule_engine import RuleEngine
from backend.alerts.telegram_alert import TelegramAlert
from backend.database.database import IDSDatabase


class RealtimeDetector:

    def __init__(self):
        self.model = None
        self.label_encoder = None

        # ==========================
        # LOAD AI MODEL
        # ==========================
        try:
            self.model = joblib.load("models/nids_model.pkl")
            self.label_encoder = joblib.load("models/label_encoder.pkl")
            print("[+] AI Model Loaded")
        except Exception as e:
            print(f"[MODEL LOAD ERROR] {e}")
            print("[!] Running in RULE-ONLY mode")

        # ==========================
        # RULE ENGINE
        # ==========================
        self.rule_engine = RuleEngine()

        # ==========================
        # TELEGRAM ALERT SYSTEM
        # ==========================
        self.telegram = TelegramAlert()

        # ==========================
        # DATABASE
        # ==========================
        self.db = IDSDatabase()

        # Deduplication tracking: maps attack_key -> last-seen timestamp
        self.last_attack = {}

    # ============================================================
    # IGNORE INVALID / LOCAL / IPv6 TRAFFIC
    # ============================================================
    def should_ignore(self, features):
        src = features.get("src_ip")
        dst = features.get("dst_ip")

        if src is None or dst is None:
            return True

        if features.get("protocol") is None:
            return True

        # Only ignore extremely small flows (both conditions met)
        if (
            features.get("packet_count", 0) <= 2
            and features.get("flow_duration", 0) < 0.5
        ):
            return True

        # Refinement 2: Extended local/broadcast/unspecified prefixes
        ignored_prefixes = [
            "0.",         # Unspecified address
            "127.",       # Localhost
            "169.254.",   # Link-local
            "224.",       # Multicast
            "239.",       # Multicast
            "255."        # Broadcast
        ]

        for prefix in ignored_prefixes:
            if src.startswith(prefix) or dst.startswith(prefix):
                return True

        # Explicitly ignore empty/unspecified addresses
        if src == "0.0.0.0" or dst == "0.0.0.0":
            return True

        # Ignore IPv6 traffic
        if ":" in src or ":" in dst:
            return True

        return False

    # ============================================================
    # RATE LIMIT DUPLICATE ALERTS
    # ============================================================
    def is_duplicate_attack(self, attack_key):
        current_time = time.time()

        # Remove entries older than 5 minutes
        expired = [
            key
            for key, timestamp in self.last_attack.items()
            if current_time - timestamp > 300
        ]

        for key in expired:
            del self.last_attack[key]

        # Ignore duplicate alerts for 60 seconds
        if attack_key in self.last_attack:
            if current_time - self.last_attack[attack_key] < 60:
                return True

        self.last_attack[attack_key] = current_time
        return False

    # ============================================================
    # AI DETECTION
    # ============================================================
    def ai_detection(self, features):
        if self.model is None:
            return None

        try:
            df = pd.DataFrame([features])

            # Remove fields not used by ML model
            drop_columns = ["timestamp", "src_ip", "dst_ip", "protocol"]

            for col in drop_columns:
                if col in df.columns:
                    df.drop(columns=[col], inplace=True)

            # Refinement 3: Fill missing feature values before prediction
            df = df.fillna(0)


            # Match exactly the columns used during training
            if hasattr(self.model, "feature_names_in_"):
                model_columns = list(self.model.feature_names_in_)

            # Add missing columns
            for column in model_columns:
                if column not in df.columns:
                    df[column] = 0

            # Remove extra columns and reorder
            df = df.reindex(columns=model_columns, fill_value=0)

            prediction = self.model.predict(df)[0]

            if hasattr(self.model, "predict_proba"):
                probs = self.model.predict_proba(df)[0]
                confidence = float(max(probs)) * 100
            else:
                confidence = 100.0

            label = self.label_encoder.inverse_transform([prediction])[0]

            return {
                "prediction": label,
                "confidence": round(confidence, 2)
            }

        except Exception as e:
            print(f"[AI ERROR] {e}")
            return None

    # ============================================================
    # HYBRID DETECTION
    # ============================================================
    def detect_attack(self, features):
        # 1. Ignore check
        if self.should_ignore(features):
            return None

        # 2. Rule Engine check
        rule_result = self.rule_engine.detect(features)

        if rule_result["attack_detected"]:
            # Refinement 4: Consistent use of .get()
            attack_data = {
                "timestamp": rule_result.get("timestamp"),
                "src_ip": features.get("src_ip"),
                "dst_ip": features.get("dst_ip"),
                "protocol": features.get("protocol"),
                "attack_type": rule_result.get("attack_type"),
                "severity": rule_result.get("severity"),
                "threat_score": rule_result.get("threat_score"),
                "confidence": rule_result.get("confidence"),
                "status": "detected"
            }

            attack_key = (
                attack_data["src_ip"],
                attack_data["dst_ip"],
                attack_data["protocol"],
                attack_data["attack_type"]
            )

            if self.is_duplicate_attack(attack_key):
                return attack_data

            # Save attack
            try:
                self.db.insert_attack_log(attack_data)
            except Exception as e:
                print(f"[DB ERROR] {e}")

            # Telegram Alert
            try:
                self.telegram.send_attack_alert(attack_data)
            except Exception as e:
                print(f"[TELEGRAM ERROR] {e}")

            # Display alert banner
            self.rule_engine.display_alert(rule_result)

            print(
                f"[ALERT] {attack_data['attack_type']} | "
                f"{attack_data['src_ip']} -> {attack_data['dst_ip']}"
            )

            return attack_data

        # 3. AI Detection check
        ai_result = self.ai_detection(features)

        if ai_result is None:
            return None

        if (
            ai_result["prediction"] != "normal"
            and ai_result["confidence"] >= 97
        ):
            # Refinement 4: Consistent use of .get()
            attack_data = {
                "timestamp": features.get("timestamp"),
                "src_ip": features.get("src_ip"),
                "dst_ip": features.get("dst_ip"),
                "protocol": features.get("protocol"),
                "attack_type": ai_result.get("prediction"),
                "severity": "MEDIUM",
                "threat_score": 70,
                "confidence": ai_result.get("confidence"),
                "status": "detected"
            }

            attack_key = (
                attack_data["src_ip"],
                attack_data["dst_ip"],
                attack_data["protocol"],
                attack_data["attack_type"]
            )

            if self.is_duplicate_attack(attack_key):
                return attack_data

            # Database and Telegram calls
            try:
                self.db.insert_attack_log(attack_data)
            except Exception as e:
                print(f"[DB ERROR] {e}")

            try:
                self.telegram.send_attack_alert(attack_data)
            except Exception as e:
                print(f"[TELEGRAM ERROR] {e}")

            # AI attack console banner
            print("\n" + "=" * 60)
            print("AI MODEL DETECTED ATTACK")
            print("=" * 60)
            print(f"Attack      : {attack_data['attack_type']}")
            print(f"Confidence  : {attack_data['confidence']}%")
            print("=" * 60)

            print(
                f"[ALERT] {attack_data['attack_type']} | "
                f"{attack_data['src_ip']} -> {attack_data['dst_ip']}"
            )

            return attack_data

        # Refinement 1: Clean return without flooding console with normal traffic logs
        return None