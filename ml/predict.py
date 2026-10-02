"""
Machine Learning Inference Engine for Intrusion Detection
Defensive Cybersecurity Engineering Project: Network Intrusion Detection System (IDS) Simulation

Provides real-time scoring and probability estimation on network flow features
using pre-trained models.
"""

import os
from pathlib import Path
from typing import Dict, Any, Optional

import joblib
import numpy as np


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


class MLPredictor:
    """
    Inference handler for loading trained ML models and classifying network flows.
    """

    def __init__(self, models_dir: str = "models", default_model: str = "random_forest_ids.joblib"):
        self.models_dir = Path(models_dir)
        self.scaler = None
        self.model = None
        self.model_name = default_model
        self.is_loaded = False
        self._load_artifacts()

    def _load_artifacts(self) -> None:
        """Loads scaler and classifier from disk if available."""
        scaler_path = self.models_dir / "scaler.joblib"
        model_path = self.models_dir / self.model_name

        if scaler_path.exists() and model_path.exists():
            try:
                self.scaler = joblib.load(scaler_path)
                self.model = joblib.load(model_path)
                self.is_loaded = True
            except Exception as e:
                print(f"[!] Warning: Could not load ML artifacts: {e}")
                self.is_loaded = False
        else:
            self.is_loaded = False

    def predict_flow(self, features: Dict[str, Any]) -> Dict[str, Any]:
        """
        Runs ML inference on extracted flow features.
        Returns:
        - prediction: "NORMAL" or "SUSPICIOUS"
        - suspicious_probability: float between 0.0 and 1.0
        - model_used: name of the model
        - is_available: bool indicating if ML model was loaded
        """
        if not self.is_loaded or self.model is None or self.scaler is None:
            return {
                "prediction": "UNAVAILABLE",
                "suspicious_probability": 0.0,
                "model_used": "None",
                "is_available": False,
            }

        # Assemble feature vector using DataFrame to preserve feature names
        import pandas as pd
        df_row = pd.DataFrame([{col: float(features.get(col, 0.0)) for col in FEATURE_COLUMNS}])
        X_scaled = self.scaler.transform(df_row)

        if hasattr(self.model, "predict_proba"):
            proba = self.model.predict_proba(X_scaled)[0]
            # proba[1] is the probability of class 1 (SUSPICIOUS)
            suspicious_prob = float(proba[1])
            pred_class = "SUSPICIOUS" if suspicious_prob >= 0.50 else "NORMAL"
        else:
            # For Isolation Forest: 1 = normal, -1 = anomaly
            raw_pred = self.model.predict(X_scaled)[0]
            score = self.model.decision_function(X_scaled)[0]
            pred_class = "SUSPICIOUS" if raw_pred == -1 else "NORMAL"
            # Normalize decision score roughly into [0, 1]
            suspicious_prob = float(1.0 / (1.0 + np.exp(score)))

        return {
            "prediction": pred_class,
            "suspicious_probability": round(suspicious_prob, 4),
            "model_used": self.model_name,
            "is_available": True,
        }
