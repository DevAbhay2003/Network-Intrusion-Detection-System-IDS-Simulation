"""
Model Evaluation and Confusion Matrix Reporting Script
Defensive Cybersecurity Engineering Project: Network Intrusion Detection System (IDS) Simulation

Produces rigorous statistical evaluation metrics and ASCII confusion matrices
comparing Supervised vs. Unsupervised IDS models.
"""

import os
import sys
from pathlib import Path

# Add project root to path for direct script execution
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import joblib
import pandas as pd
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.model_selection import train_test_split

from ml.train_model import prepare_feature_data


def evaluate_models(
    dataset_path: str = "data/network_traffic.csv",
    models_dir: str = "models",
    random_state: int = 42
):
    """
    Evaluates all saved models on a held-out test set and prints detailed reports.
    """
    df = pd.read_csv(dataset_path)
    X, y = prepare_feature_data(df)

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.20, random_state=random_state, stratify=y
    )

    models_path = Path(models_dir)
    scaler = joblib.load(models_path / "scaler.joblib")
    X_test_scaled = scaler.transform(X_test)

    models = {
        "Logistic Regression": joblib.load(models_path / "logistic_regression_ids.joblib"),
        "Random Forest Classifier": joblib.load(models_path / "random_forest_ids.joblib"),
        "Isolation Forest (Unsupervised)": joblib.load(models_path / "isolation_forest_ids.joblib"),
    }

    print("\n" + "=" * 70)
    print("      CYBERSECURITY IDS MACHINE LEARNING EVALUATION BENCHMARK      ")
    print("=" * 70)
    print(f"Total Test Set Records: {len(y_test)} (Normal: {(y_test == 0).sum()}, Suspicious: {(y_test == 1).sum()})\n")

    for name, model in models.items():
        if "Isolation" in name:
            preds_raw = model.predict(X_test_scaled)
            preds = (preds_raw == -1).astype(int)
        else:
            preds = model.predict(X_test_scaled)

        cm = confusion_matrix(y_test, preds)
        tn, fp, fn, tp = cm.ravel()

        print(f"--- Model: {name} ---")
        print(classification_report(y_test, preds, target_names=["NORMAL", "SUSPICIOUS"], digits=4))
        print("Confusion Matrix Breakdown:")
        print(f"  True Negatives  (TN) [Correctly identified Normal]    : {tn}")
        print(f"  False Positives (FP) [Normal falsely flagged as threat]: {fp}")
        print(f"  False Negatives (FN) [Missed intrusion threat]         : {fn}")
        print(f"  True Positives  (TP) [Correctly detected threat]       : {tp}")
        print("-" * 70)


if __name__ == "__main__":
    evaluate_models()
