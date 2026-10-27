import os
import pandas as pd

from predictor import NIDSPredictor


print("\n" + "=" * 60)
print("NIDS ML PREDICTOR VALIDATION")
print("=" * 60)


# Load predictor
predictor = NIDSPredictor()


# Locate dataset
dataset_path = os.path.join(
    os.path.dirname(__file__),
    "..",
    "dataset",
    "traffic_dataset.csv"
)


# Load dataset
df = pd.read_csv(dataset_path)

print(f"\nDataset rows: {len(df)}")


correct_predictions = 0
total_predictions = len(df)


# Validate every dataset row
for _, row in df.iterrows():

    features = row[predictor.feature_columns].to_dict()

    result = predictor.predict(features)

    if result["label"] == row["label"]:
        correct_predictions += 1


# Calculate accuracy
accuracy = correct_predictions / total_predictions


print("\n" + "=" * 60)
print("VALIDATION RESULT")
print("=" * 60)

print(f"\nCorrect predictions : {correct_predictions}")
print(f"Total predictions   : {total_predictions}")
print(f"Predictor accuracy  : {accuracy:.4f}")

print("\n" + "=" * 60)
print("PREDICTOR VALIDATION COMPLETED")
print("=" * 60)