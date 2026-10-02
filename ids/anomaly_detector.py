"""
Statistical Anomaly Detection Engine
Defensive Cybersecurity Engineering Project: Network Intrusion Detection System (IDS) Simulation

This module establishes historical behavioral baselines using normal traffic flows
and evaluates incoming flows using statistical deviations:
- Z-score (standard deviations from mean)
- Interquartile Range (IQR outlier detection)
- Standard Deviation & Variance
- Rolling Moving Baselines

Returns a calibrated 0–100 Anomaly Score with feature-level deviation breakdown.
"""

import math
from typing import Dict, Any, List, Optional
import numpy as np
import pandas as pd


# Default baseline fallbacks derived from normal traffic profiling
DEFAULT_BASELINES = {
    "packets_per_second": {"mean": 24.5, "std": 18.2, "q25": 10.0, "q75": 32.0, "iqr": 22.0},
    "bytes_per_second": {"mean": 18500.0, "std": 14200.0, "q25": 6000.0, "q75": 28000.0, "iqr": 22000.0},
    "connection_rate": {"mean": 2.1, "std": 1.4, "q25": 1.0, "q75": 3.0, "iqr": 2.0},
    "failure_ratio": {"mean": 0.01, "std": 0.04, "q25": 0.0, "q75": 0.0, "iqr": 0.02},
    "unique_destination_ports": {"mean": 1.05, "std": 0.25, "q25": 1.0, "q75": 1.0, "iqr": 0.1},
}


class AnomalyDetector:
    """
    Evaluates network flow deviation against established normal traffic baselines.
    """

    def __init__(self, baseline_df: Optional[pd.DataFrame] = None):
        self.baselines = DEFAULT_BASELINES.copy()
        self.history_window: List[Dict[str, float]] = []
        self.max_window_size = 500

        if baseline_df is not None and not baseline_df.empty:
            self.fit_baseline(baseline_df)

    def fit_baseline(self, df: pd.DataFrame) -> None:
        """
        Profiles normal traffic records to calculate mean, std, and IQR for key defense metrics.
        """
        normal_data = df[df["label"] == "NORMAL"] if "label" in df.columns else df

        if len(normal_data) < 10:
            return  # retain default fallbacks if insufficient data

        # Ensure derived metrics exist
        data = normal_data.copy()
        if "duration_seconds" in data.columns and "duration" not in data.columns:
            data["duration"] = data["duration_seconds"]

        durations = data["duration"].clip(lower=0.001)
        data["packets_per_second"] = data["packet_count"] / durations
        data["bytes_per_second"] = data["byte_count"] / durations
        data["connection_rate"] = data["connection_count"] / durations
        data["failure_ratio"] = (data["failed_connection_count"] / data["connection_count"].clip(lower=1)).clip(0, 1)
        if "unique_destination_ports" not in data.columns:
            data["unique_destination_ports"] = 1.0

        metrics = [
            "packets_per_second",
            "bytes_per_second",
            "connection_rate",
            "failure_ratio",
            "unique_destination_ports",
        ]

        for m in metrics:
            series = pd.to_numeric(data[m], errors="coerce").fillna(0.0)
            mean_val = float(series.mean())
            std_val = float(series.std()) if float(series.std()) > 1e-4 else 1.0
            q25 = float(series.quantile(0.25))
            q75 = float(series.quantile(0.75))
            iqr = max(q75 - q25, 0.001)

            self.baselines[m] = {
                "mean": round(mean_val, 3),
                "std": round(std_val, 3),
                "q25": round(q25, 3),
                "q75": round(q75, 3),
                "iqr": round(iqr, 3),
            }

    def calculate_anomaly_score(self, features: Dict[str, Any]) -> Dict[str, Any]:
        """
        Computes a normalized 0–100 anomaly score based on statistical deviation.

        Methodology:
        1. Calculates Z-score for each metric: z = |x - mean| / std
        2. Calculates IQR deviation: iqr_dist = max(0, (x - (Q75 + 1.5 * IQR)) / IQR)
        3. Blends Z-score and IQR outliers with defensive weighting
        4. Applies a non-linear sigmoid-like compression to scale into 0-100
        """
        metric_deviations: Dict[str, Any] = {}
        total_weighted_deviation = 0.0

        weights = {
            "connection_rate": 0.30,
            "failure_ratio": 0.25,
            "unique_destination_ports": 0.20,
            "packets_per_second": 0.15,
            "bytes_per_second": 0.10,
        }

        for metric, w in weights.items():
            val = float(features.get(metric, 0.0))
            base = self.baselines.get(metric, DEFAULT_BASELINES.get(metric))

            mean = base["mean"]
            std = max(base["std"], 0.001)
            q75 = base["q75"]
            iqr = max(base["iqr"], 0.001)

            # Z-Score: how many std deviations above normal
            z_score = max(0.0, (val - mean) / std)

            # IQR Upper Outlier bound: x > Q75 + 1.5 * IQR
            iqr_outlier_bound = q75 + 1.5 * iqr
            iqr_excess = max(0.0, (val - iqr_outlier_bound) / iqr)

            # Blended metric deviation
            metric_dev = 0.6 * z_score + 0.4 * iqr_excess

            metric_deviations[metric] = {
                "observed_value": round(val, 2),
                "baseline_mean": mean,
                "z_score": round(z_score, 2),
                "is_outlier": bool(val > iqr_outlier_bound),
                "metric_deviation": round(metric_dev, 2)
            }

            total_weighted_deviation += w * metric_dev

        # Update sliding history window for rolling tracking
        self.history_window.append({m: float(features.get(m, 0.0)) for m in weights})
        if len(self.history_window) > self.max_window_size:
            self.history_window.pop(0)

        # Scale into 0-100: A deviation of 3.0 (3 std devs) maps to ~75, 5+ maps to 90-100
        # Formula: 100 * (1 - exp(-0.45 * total_deviation))
        anomaly_score = 100.0 * (1.0 - math.exp(-0.45 * total_weighted_deviation))
        anomaly_score = max(0.0, min(100.0, round(anomaly_score, 2)))

        is_anomalous = anomaly_score >= 50.0

        return {
            "anomaly_score": anomaly_score,
            "is_anomalous": is_anomalous,
            "composite_deviation": round(total_weighted_deviation, 2),
            "feature_breakdown": metric_deviations,
            "explanation": (
                f"Statistical anomaly score: {anomaly_score:.1f}/100. "
                f"Observed composite deviation: {total_weighted_deviation:.2f} standard units."
                if is_anomalous else "Traffic statistical profile aligns with normal baseline behavior."
            )
        }
