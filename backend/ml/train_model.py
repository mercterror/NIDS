import pandas as pd
import numpy as np
import joblib

from sklearn.ensemble import (
    RandomForestClassifier,
    IsolationForest
)

from sklearn.model_selection import (
    train_test_split
)

from sklearn.preprocessing import (
    LabelEncoder
)

from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix
)


class NIDSTrainer:

    def __init__(self):

        self.dataset_path = (
            "dataset/traffic_dataset.csv"
        )

        self.model_path = (
            "models/nids_model.pkl"
        )

        self.encoder_path = (
            "models/label_encoder.pkl"
        )

    def load_dataset(self):

        print("[+] Loading dataset...")

        df = pd.read_csv(
            self.dataset_path
        )

        print(
            f"[+] Dataset loaded:"
            f" {len(df)} rows"
        )

        return df

    def preprocess_data(self, df):

        print("[+] Preprocessing dataset...")

        # Remove unnecessary columns
        drop_columns = [
            "timestamp",
            "src_ip",
            "dst_ip",
            "protocol"
        ]

        df = df.drop(
            columns=drop_columns,
            errors="ignore"
        )

        # Fill missing values
        df = df.fillna(0)

        # Encode labels
        label_encoder = LabelEncoder()

        df["label"] = (
            label_encoder.fit_transform(
                df["label"]
            )
        )

        # Save encoder
        joblib.dump(
            label_encoder,
            self.encoder_path
        )

        print(
            "[+] Label encoder saved"
        )

        X = df.drop(
            columns=["label"]
        )

        y = df["label"]

        return X, y, label_encoder

    def train_random_forest(
        self,
        X_train,
        y_train
    ):

        print(
            "[+] Training Random Forest..."
        )

        model = RandomForestClassifier(
            n_estimators=100,
            max_depth=20,
            random_state=42,
            n_jobs=-1
        )

        model.fit(
            X_train,
            y_train
        )

        return model

    def train_isolation_forest(
        self,
        X_train
    ):

        print(
            "[+] Training Isolation Forest..."
        )

        iso_model = IsolationForest(
            contamination=0.05,
            random_state=42
        )

        iso_model.fit(X_train)

        return iso_model

    def evaluate_model(
        self,
        model,
        X_test,
        y_test,
        label_encoder
    ):

        print(
            "[+] Evaluating model..."
        )

        predictions = model.predict(
            X_test
        )

        accuracy = accuracy_score(
            y_test,
            predictions
        )

        print(
            f"\n[+] Accuracy: "
            f"{accuracy * 100:.2f}%"
        )

        print("\nClassification Report:\n")

        print(
            classification_report(
                y_test,
                predictions
            )
        )

        print("\nConfusion Matrix:\n")

        print(
            confusion_matrix(
                y_test,
                predictions
            )
        )

        self.show_feature_importance(
            model,
            X_test.columns
        )

    def show_feature_importance(
        self,
        model,
        feature_names
    ):

        print(
            "\n[+] Feature Importance:\n"
        )

        importance = (
            model.feature_importances_
        )

        features = sorted(
            zip(feature_names, importance),
            key=lambda x: x[1],
            reverse=True
        )

        for feature, score in features:

            print(
                f"{feature:<25}"
                f"{score:.4f}"
            )

    def save_model(self, model):

        joblib.dump(
            model,
            self.model_path
        )

        print(
            f"\n[+] Model saved:"
            f" {self.model_path}"
        )

    def run(self):

        # =========================
        # LOAD DATASET
        # =========================

        df = self.load_dataset()

        # =========================
        # PREPROCESS
        # =========================

        X, y, label_encoder = (
            self.preprocess_data(df)
        )

        # =========================
        # TRAIN TEST SPLIT
        # =========================

        X_train, X_test, y_train, y_test = (
            train_test_split(
                X,
                y,
                test_size=0.2,
                random_state=42
            )
        )

        print(
            f"[+] Training samples:"
            f" {len(X_train)}"
        )

        print(
            f"[+] Testing samples:"
            f" {len(X_test)}"
        )

        # =========================
        # RANDOM FOREST
        # =========================

        model = self.train_random_forest(
            X_train,
            y_train
        )

        # =========================
        # ISOLATION FOREST
        # =========================

        self.train_isolation_forest(
            X_train
        )

        # =========================
        # EVALUATION
        # =========================

        self.evaluate_model(
            model,
            X_test,
            y_test,
            label_encoder
        )

        # =========================
        # SAVE MODEL
        # =========================

        self.save_model(model)


if __name__ == "__main__":

    trainer = NIDSTrainer()

    trainer.run()
