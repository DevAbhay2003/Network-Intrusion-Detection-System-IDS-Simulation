"""
Machine Learning Model Training Pipeline for Network Intrusion Detection
Defensive Cybersecurity Engineering Project: Network Intrusion Detection System (IDS) Simulation

Trains and compares:
1. Supervised: Logistic Regression (interpretable linear baseline)
2. Supervised: Random Forest Classifier (non-linear ensemble tree model)
3. Unsupervised: Isolation Forest (outlier tree partitioning for novel anomalies)

Features:
- packet_count
- byte_count
- duration
- bytes_per_second
- packets_per_second
- connection_count
- failed_connection_count
- syn_count
- rst_count
- average_packet_size

Saves trained artifacts into `models/` directory.
"""

import json
import os
from pathlib import Path
from typing import Dict, Any, Tuple

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler


FEATURE_COLUMNS = [
    "packet_count",
    "byte_count",
    "duration",
    "bytes_per_second",
    "packets_per_second",
    "connection_count",
    "failed_connection_count",
    "syn_count",
    "rst_count",
    "average_packet_size",
]


def prepare_feature_data(df: pd.DataFrame) -> Tuple[pd.DataFrame, pd.Series]:
    """
    Computes derived rate metrics and prepares the feature matrix X and target y.
    """
    df_clean = df.copy()

    # Align duration column name
    if "duration_seconds" in df_clean.columns and "duration" not in df_clean.columns:
        df_clean["duration"] = df_clean["duration_seconds"]

    durations = df_clean["duration"].clip(lower=0.001)
    df_clean["bytes_per_second"] = df_clean["byte_count"] / durations
    df_clean["packets_per_second"] = df_clean["packet_count"] / durations
    df_clean["average_packet_size"] = df_clean["byte_count"] / df_clean["packet_count"].clip(lower=1)

    X = df_clean[FEATURE_COLUMNS].fillna(0.0)

    # Encode label: NORMAL -> 0, SUSPICIOUS -> 1
    y = (df_clean["label"] == "SUSPICIOUS").astype(int)

    return X, y


def train_models(
    dataset_path: str = "data/network_traffic.csv",
    output_dir: str = "models",
    random_state: int = 42
) -> Dict[str, Any]:
    """
    Loads dataset, trains models, evaluates metrics, and serializes trained models.
    """
    if not os.path.exists(dataset_path):
        raise FileNotFoundError(f"Dataset not found at {dataset_path}. Run generate_dataset.py first.")

    print(f"[*] Loading dataset from {dataset_path}...")
    df = pd.read_csv(dataset_path)

    X, y = prepare_feature_data(df)
    print(f"[+] Total samples: {len(X)} (Normal: {(y == 0).sum()}, Suspicious: {(y == 1).sum()})")

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.20, random_state=random_state, stratify=y
    )

    # Standardize features for numeric stability
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)

    results = {}
    models_to_save = {}

    # 1. Supervised: Logistic Regression
    print("\n[+] Training Supervised: Logistic Regression...")
    lr = LogisticRegression(max_iter=1000, random_state=random_state)
    lr.fit(X_train_scaled, y_train)
    y_pred_lr = lr.predict(X_test_scaled)
    cm_lr = confusion_matrix(y_test, y_pred_lr).tolist()

    results["Logistic Regression"] = {
        "type": "Supervised Linear",
        "accuracy": round(float(accuracy_score(y_test, y_pred_lr)), 4),
        "precision": round(float(precision_score(y_test, y_pred_lr, zero_division=0)), 4),
        "recall": round(float(recall_score(y_test, y_pred_lr, zero_division=0)), 4),
        "f1_score": round(float(f1_score(y_test, y_pred_lr, zero_division=0)), 4),
        "confusion_matrix": cm_lr,
    }
    models_to_save["logistic_regression_ids.joblib"] = lr

    # 2. Supervised: Random Forest Classifier
    print("[+] Training Supervised: Random Forest Classifier...")
    rf = RandomForestClassifier(n_estimators=100, max_depth=12, random_state=random_state, n_jobs=-1)
    rf.fit(X_train_scaled, y_train)
    y_pred_rf = rf.predict(X_test_scaled)
    cm_rf = confusion_matrix(y_test, y_pred_rf).tolist()

    results["Random Forest"] = {
        "type": "Supervised Ensemble Tree",
        "accuracy": round(float(accuracy_score(y_test, y_pred_rf)), 4),
        "precision": round(float(precision_score(y_test, y_pred_rf, zero_division=0)), 4),
        "recall": round(float(recall_score(y_test, y_pred_rf, zero_division=0)), 4),
        "f1_score": round(float(f1_score(y_test, y_pred_rf, zero_division=0)), 4),
        "confusion_matrix": cm_rf,
    }
    models_to_save["random_forest_ids.joblib"] = rf

    # 3. Unsupervised: Isolation Forest (trained on normal traffic to detect anomalies)
    print("[+] Training Unsupervised: Isolation Forest...")
    # Train Isolation Forest primarily on normal data (standard anomaly detection setup)
    X_train_normal = X_train_scaled[y_train == 0]
    iso = IsolationForest(contamination=0.10, random_state=random_state, n_jobs=-1)
    iso.fit(X_train_normal)

    # In sklearn Isolation Forest: 1 = normal, -1 = anomaly/suspicious
    iso_preds = iso.predict(X_test_scaled)
    y_pred_iso = (iso_preds == -1).astype(int)
    cm_iso = confusion_matrix(y_test, y_pred_iso).tolist()

    results["Isolation Forest"] = {
        "type": "Unsupervised Outlier Tree",
        "accuracy": round(float(accuracy_score(y_test, y_pred_iso)), 4),
        "precision": round(float(precision_score(y_test, y_pred_iso, zero_division=0)), 4),
        "recall": round(float(recall_score(y_test, y_pred_iso, zero_division=0)), 4),
        "f1_score": round(float(f1_score(y_test, y_pred_iso, zero_division=0)), 4),
        "confusion_matrix": cm_iso,
    }
    models_to_save["isolation_forest_ids.joblib"] = iso

    # Save artifacts
    out_path = Path(output_dir)
    out_path.mkdir(parents=True, exist_ok=True)

    joblib.dump(scaler, out_path / "scaler.joblib")
    for filename, model in models_to_save.items():
        joblib.dump(model, out_path / filename)

    metadata = {
        "feature_columns": FEATURE_COLUMNS,
        "evaluation_metrics": results,
        "train_samples": len(X_train),
        "test_samples": len(X_test),
    }

    with open(out_path / "model_metadata.json", "w") as f:
        json.dump(metadata, f, indent=2)

    print("\n" + "=" * 65)
    print("MODEL PERFORMANCE EVALUATION ON TEST SET (20% Split)")
    print("=" * 65)
    for name, m in results.items():
        print(f"Model: {name} ({m['type']})")
        print(f"  Accuracy : {m['accuracy'] * 100:.2f}%")
        print(f"  Precision: {m['precision'] * 100:.2f}%")
        print(f"  Recall   : {m['recall'] * 100:.2f}%")
        print(f"  F1 Score : {m['f1_score'] * 100:.2f}%")
        print(f"  Confusion Matrix (TN, FP / FN, TP):")
        print(f"    [[{m['confusion_matrix'][0][0]}, {m['confusion_matrix'][0][1]}],")
        print(f"     [{m['confusion_matrix'][1][0]}, {m['confusion_matrix'][1][1]}]]\n")

    print(f"[+] All models and scaler successfully saved to: {out_path.resolve()}")
    return results


if __name__ == "__main__":
    train_models()
