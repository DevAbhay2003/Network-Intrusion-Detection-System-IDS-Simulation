"""
Core IDS Orchestration Service
Defensive Cybersecurity Engineering Project: Network Intrusion Detection System (IDS) Simulation

Integrates:
- Feature Extractor
- Rule / Signature Engine
- Statistical Anomaly Detector
- Machine Learning Inference
- Hybrid Risk Scorer
- Alert Generation Engine
- Alert Correlation Engine
- Database Persistence
"""

import json
import os
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, Optional, List

import pandas as pd
from sqlalchemy.orm import Session

from ids.feature_extractor import extract_network_features
from ids.rule_engine import RuleEngine
from ids.anomaly_detector import AnomalyDetector
from ids.risk_engine import RiskEngine
from ids.alert_engine import AlertEngine
from ids.correlation import AlertCorrelationEngine
from ml.predict import MLPredictor
from backend.models.db_models import NetworkFlow, Alert, ModelResult, Rule


class IDSService:
    """
    Central orchestration service managing the defensive IDS pipeline.
    """

    def __init__(self, data_path: str = "data/network_traffic.csv"):
        self.data_path = Path(data_path)
        self.rule_engine = RuleEngine()
        self.risk_engine = RiskEngine()
        self.alert_engine = AlertEngine()
        self.correlation_engine = AlertCorrelationEngine(time_window_seconds=60)
        self.ml_predictor = MLPredictor(models_dir="models")

        # Initialize Anomaly Detector with historical baseline if available
        baseline_df = None
        if self.data_path.exists():
            try:
                baseline_df = pd.read_csv(self.data_path)
            except Exception as e:
                print(f"[!] Warning: Could not read baseline file: {e}")

        self.anomaly_detector = AnomalyDetector(baseline_df=baseline_df)

    def process_flow(self, raw_flow: Dict[str, Any], db: Session) -> Dict[str, Any]:
        """
        Executes complete defensive intrusion detection pipeline on an incoming flow.

        Pipeline Stages:
        1. Feature Extraction & Defensive Validation
        2. Signature / Rule Matching
        3. Statistical Deviation & Anomaly Scoring
        4. Machine Learning Inference (Supervised/Unsupervised)
        5. Multi-vector Hybrid Risk Scoring
        6. Security Alert Generation & Correlation
        7. Database Persistence
        """
        # Ensure unique flow_id and timestamp
        if not raw_flow.get("flow_id"):
            raw_flow["flow_id"] = f"FLOW-{uuid.uuid4().hex[:8].upper()}"
        if not raw_flow.get("timestamp"):
            raw_flow["timestamp"] = datetime.now(timezone.utc).isoformat()

        # 1. Feature Extraction
        features = extract_network_features(raw_flow)

        # 2. Rule-Based Evaluation
        rule_result = self.rule_engine.analyze_flow(features)

        # 3. Statistical Anomaly Detection
        anomaly_result = self.anomaly_detector.calculate_anomaly_score(features)

        # 4. Optional Machine Learning Inference
        ml_result = self.ml_predictor.predict_flow(features)

        # 5. Hybrid Risk Scoring
        risk_result = self.risk_engine.calculate_risk_score(
            rule_result=rule_result,
            anomaly_result=anomaly_result,
            ml_result=ml_result if ml_result.get("is_available") else None
        )

        final_risk = risk_result["final_risk_score"]
        classification = risk_result["classification"]

        # 6. Alert Generation
        alert_data = self.alert_engine.evaluate_and_generate_alert(
            features=features,
            rule_result=rule_result,
            anomaly_result=anomaly_result,
            risk_result=risk_result,
            ml_result=ml_result
        )

        # 7. Alert Correlation
        incident_summary = None
        if alert_data:
            incident_summary = self.correlation_engine.correlate_alert(alert_data)

        # 8. Database Persistence
        # Check if flow already exists
        existing_flow = db.query(NetworkFlow).filter(NetworkFlow.flow_id == features["flow_id"]).first()
        if not existing_flow:
            flow_entity = NetworkFlow(
                flow_id=features["flow_id"],
                timestamp=features["timestamp"],
                source_ip=features["source_ip"],
                destination_ip=features["destination_ip"],
                source_port=features["source_port"],
                destination_port=features["destination_port"],
                protocol=features["protocol"],
                packet_count=features["packet_count"],
                byte_count=features["byte_count"],
                duration=features["duration"],
                risk_score=final_risk,
                classification=classification,
                scenario_type=raw_flow.get("scenario_type", "NORMAL_CUSTOM"),
            )
            db.add(flow_entity)
            db.flush()

        saved_alert = None
        if alert_data:
            alert_entity = Alert(
                alert_id=alert_data["alert_id"],
                flow_id=features["flow_id"],
                rule_id=alert_data["rule_id"],
                alert_type=alert_data["alert_type"],
                severity=alert_data["severity"],
                description=alert_data["description"],
                risk_score=final_risk,
                status=alert_data["status"],
                created_at=alert_data["created_at"],
                source_ip=alert_data["source_ip"],
                destination_ip=alert_data["destination_ip"],
                source_port=alert_data["source_port"],
                destination_port=alert_data["destination_port"],
                protocol=alert_data["protocol"],
            )
            db.add(alert_entity)
            saved_alert = alert_data

        # Persist ML results if available
        if ml_result.get("is_available"):
            ml_entity = ModelResult(
                flow_id=features["flow_id"],
                model_name=ml_result["model_used"],
                prediction=ml_result["prediction"],
                score=ml_result["suspicious_probability"],
                created_at=datetime.now(timezone.utc).isoformat(),
            )
            db.add(ml_entity)

        try:
            db.commit()
        except Exception as e:
            db.rollback()
            print(f"[!] Database error on commit: {e}")

        return {
            "status": "PROCESSED",
            "flow_id": features["flow_id"],
            "risk_score": final_risk,
            "classification": classification,
            "rule_result": rule_result,
            "anomaly_result": anomaly_result,
            "ml_result": ml_result,
            "alert_generated": bool(saved_alert is not None),
            "alert": saved_alert,
            "incident": incident_summary,
        }

    def seed_initial_rules_if_empty(self, db: Session) -> None:
        """Seeds the database rules table with default detection signatures if empty."""
        count = db.query(Rule).count()
        if count == 0:
            for rule_id, r in self.rule_engine.rules.items():
                db_rule = Rule(
                    rule_id=r["rule_id"],
                    rule_name=r["name"],
                    description=r["description"],
                    severity=r["severity"],
                    threshold=json.dumps(r.get("thresholds", {})),
                    enabled=r.get("enabled", True),
                )
                db.add(db_rule)
            db.commit()


# Singleton service instance
ids_service = IDSService()
