import os
import joblib
import pandas as pd


class NIDSPredictor:

    def __init__(self):

        # ====================================================
        # MODEL PATH
        # ====================================================

        model_directory = os.path.join(
            os.path.dirname(__file__),
            "models"
        )

        model_path = os.path.join(
            model_directory,
            "nids_random_forest.pkl"
        )

        protocol_encoder_path = os.path.join(
            model_directory,
            "protocol_encoder.pkl"
        )

        label_encoder_path = os.path.join(
            model_directory,
            "label_encoder.pkl"
        )

        # ====================================================
        # LOAD MODEL
        # ====================================================

        self.model = joblib.load(
            model_path
        )

        self.protocol_encoder = joblib.load(
            protocol_encoder_path
        )

        self.label_encoder = joblib.load(
            label_encoder_path
        )

        # ====================================================
        # FEATURES USED DURING TRAINING
        # ====================================================

        self.feature_columns = [
            "src_port",
            "dst_port",
            "protocol",
            "packet_size",
            "ttl",
            "flow_duration",
            "packet_count",
            "byte_count",
            "packet_rate",
            "byte_rate",
            "unique_src_ports",
            "unique_dst_ports",
            "entropy_score",
            "inter_arrival_time",
            "syn_flag_count",
            "ack_flag_count",
            "fin_flag_count",
            "rst_flag_count",
            "psh_flag_count",
            "urg_flag_count",
            "dns_query_count",
            "failed_connections",
            "arp_requests"
        ]

        print("[+] NIDS ML model loaded successfully.")


    # ========================================================
    # PREDICT TRAFFIC
    # ========================================================

    def predict(self, features):

        if features is None:
            return None

        # ----------------------------------------------------
        # Create dataframe
        # ----------------------------------------------------

        input_data = {}

        for column in self.feature_columns:

            input_data[column] = [
                features.get(
                    column,
                    0
                )
            ]

        input_df = pd.DataFrame(
            input_data
        )

        # ----------------------------------------------------
        # Encode protocol
        # ----------------------------------------------------

        input_df["protocol"] = (
            self.protocol_encoder.transform(
                input_df["protocol"]
            )
        )

        # ----------------------------------------------------
        # Make prediction
        # ----------------------------------------------------

        prediction = self.model.predict(
            input_df
        )[0]

        # ----------------------------------------------------
        # Convert prediction back to attack name
        # ----------------------------------------------------

        predicted_label = (
            self.label_encoder.inverse_transform(
                [prediction]
            )[0]
        )

        # ----------------------------------------------------
        # Prediction probabilities
        # ----------------------------------------------------

        probabilities = (
            self.model.predict_proba(
                input_df
            )[0]
        )

        confidence = float(
            max(probabilities)
        )

        return {
            "label": predicted_label,
            "confidence": confidence
        }