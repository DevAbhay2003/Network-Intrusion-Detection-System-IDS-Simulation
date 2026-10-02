"""
Hybrid Risk Scoring Engine
Defensive Cybersecurity Engineering Project: Network Intrusion Detection System (IDS) Simulation

Combines:
1. Signature / Rule-Based Risk Score
2. Statistical Anomaly Detection Score
3. Optional Machine Learning Probability Score

Calculates a final weighted Risk Score (0–100) and assigns an actionable SOC Classification:
- 0–20:   NORMAL
- 21–40:  LOW RISK
- 41–60:  SUSPICIOUS
- 61–80:  HIGH RISK
- 81–100: CRITICAL INVESTIGATION
"""

from typing import Dict, Any, Optional, Tuple


class RiskEngine:
    """
    Computes unified hybrid risk scores and triage classifications.
    """

    DEFAULT_WEIGHTS_WITH_ML = {
        "rule": 0.40,
        "anomaly": 0.30,
        "ml": 0.30,
    }

    DEFAULT_WEIGHTS_NO_ML = {
        "rule": 0.60,
        "anomaly": 0.40,
        "ml": 0.0,
    }

    @staticmethod
    def classify_risk(score: float) -> Tuple[str, str]:
        """
        Maps a 0-100 risk score to a security classification and suggested action.
        """
        if score <= 20.0:
            return "NORMAL", "Routine traffic within baseline parameters. No action required."
        elif score <= 40.0:
            return "LOW RISK", "Minor baseline variance. Informational monitoring only."
        elif score <= 60.0:
            return "SUSPICIOUS", "Detectable anomaly or low-confidence signature match. Queued for SOC review."
        elif score <= 80.0:
            return "HIGH RISK", "High confidence signature or severe statistical anomaly. Active triage recommended."
        else:
            return "CRITICAL INVESTIGATION", "Multi-vector intrusion indicators detected. Immediate SOC containment required."

    def calculate_risk_score(
        self,
        rule_result: Dict[str, Any],
        anomaly_result: Dict[str, Any],
        ml_result: Optional[Dict[str, Any]] = None,
        custom_weights: Optional[Dict[str, float]] = None
    ) -> Dict[str, Any]:
        """
        Computes the composite risk score using weighted multi-method detection.

        Parameters:
        - rule_result: Output from RuleEngine.analyze_flow()
        - anomaly_result: Output from AnomalyDetector.calculate_anomaly_score()
        - ml_result: Optional output from ML predictor
        - custom_weights: Optional override dictionary of weights
        """
        rule_score = float(rule_result.get("rule_risk_score", 0.0))
        anomaly_score = float(anomaly_result.get("anomaly_score", 0.0))

        has_ml = ml_result is not None and "suspicious_probability" in ml_result
        ml_score = float(ml_result.get("suspicious_probability", 0.0) * 100.0) if has_ml else 0.0

        # Select appropriate weighting scheme
        if custom_weights:
            weights = custom_weights
        elif has_ml:
            weights = self.DEFAULT_WEIGHTS_WITH_ML
        else:
            weights = self.DEFAULT_WEIGHTS_NO_ML

        w_rule = weights.get("rule", 0.60 if not has_ml else 0.40)
        w_anom = weights.get("anomaly", 0.40 if not has_ml else 0.30)
        w_ml = weights.get("ml", 0.0 if not has_ml else 0.30)

        # Normalize weights to sum to 1.0
        total_w = w_rule + w_anom + (w_ml if has_ml else 0.0)
        if total_w > 0:
            w_rule /= total_w
            w_anom /= total_w
            w_ml /= total_w

        # If a CRITICAL or HIGH rule triggered, enforce a defensive minimum floor
        # to prevent a signature match from being suppressed by a gentle anomaly score
        min_floor = 0.0
        if rule_result.get("highest_severity") == "CRITICAL":
            min_floor = 75.0
        elif rule_result.get("highest_severity") == "HIGH":
            min_floor = 55.0

        if has_ml:
            composite = (w_rule * rule_score) + (w_anom * anomaly_score) + (w_ml * ml_score)
        else:
            composite = (w_rule * rule_score) + (w_anom * anomaly_score)

        final_score = max(composite, min_floor)
        final_score = max(0.0, min(100.0, round(final_score, 2)))

        classification, triage_action = self.classify_risk(final_score)

        return {
            "final_risk_score": final_score,
            "classification": classification,
            "triage_action": triage_action,
            "component_scores": {
                "rule_risk_score": round(rule_score, 2),
                "anomaly_score": round(anomaly_score, 2),
                "ml_score": round(ml_score, 2) if has_ml else None,
            },
            "applied_weights": {
                "rule_weight": round(w_rule, 2),
                "anomaly_weight": round(w_anom, 2),
                "ml_weight": round(w_ml, 2) if has_ml else 0.0,
            },
            "is_actionable": final_score >= 40.0
        }
