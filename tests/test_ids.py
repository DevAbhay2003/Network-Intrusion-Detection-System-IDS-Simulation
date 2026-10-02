"""
Automated Test Suite for Network Intrusion Detection System (IDS) Simulation
Defensive Cybersecurity Engineering Project

Contains 30 Comprehensive Test Scenarios verifying:
- Safe Traffic Flow Processing (TCP, UDP, DNS, HTTPS)
- Threat Pattern Recognition (Rate Floods, Failed Connections, Probing, SYN-Heavy, Volume Spikes)
- Defensive Input Validation and Edge Case Handling (IPs, Ports, Protocols, Zero Duration)
- IDS Engine Pipelines (Features, Signatures, Statistical Anomalies, ML Inference, Risk, Alerts, Correlation)
- Database Persistence, API Endpoints, and SOC Investigation Workflows
"""

import os
import sys
from datetime import datetime, timezone
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

# Ensure project root is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from ids.feature_extractor import (
    extract_network_features,
    validate_ip_address,
    validate_port,
    validate_protocol,
)
from ids.rule_engine import RuleEngine
from ids.anomaly_detector import AnomalyDetector
from ids.risk_engine import RiskEngine
from ids.alert_engine import AlertEngine
from ids.correlation import AlertCorrelationEngine
from ml.predict import MLPredictor
from backend.database import Base
from backend.models.db_models import NetworkFlow, Alert, Rule, IncidentNote
from backend.services.ids_service import IDSService
from backend.app import app


# Test database setup (in-memory SQLite)
TEST_ENGINE = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=TEST_ENGINE)


@pytest.fixture(scope="module")
def test_db():
    Base.metadata.create_all(bind=TEST_ENGINE)
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()
        Base.metadata.drop_all(bind=TEST_ENGINE)


@pytest.fixture(scope="module")
def api_client():
    return TestClient(app)


# -------------------------------------------------------------
# TEST CASES 1 TO 4: NORMAL FLOW PROCESSING
# -------------------------------------------------------------

def test_01_normal_tcp_flow():
    """TEST-01: Valid normal TCP web browsing flow should be classified as NORMAL/LOW RISK."""
    flow = {
        "flow_id": "TEST-01",
        "source_ip": "192.0.2.15",
        "destination_ip": "198.51.100.20",
        "source_port": 51234,
        "destination_port": 80,
        "protocol": "TCP",
        "packet_count": 25,
        "byte_count": 18000,
        "duration_seconds": 2.5,
        "connection_count": 2,
        "failed_connection_count": 0,
        "syn_count": 2,
        "rst_count": 0,
    }
    feats = extract_network_features(flow)
    rule_eng = RuleEngine()
    anom_eng = AnomalyDetector()
    risk_eng = RiskEngine()

    r_res = rule_eng.analyze_flow(feats)
    a_res = anom_eng.calculate_anomaly_score(feats)
    k_res = risk_eng.calculate_risk_score(r_res, a_res)

    assert feats["is_valid"] is True
    assert r_res["triggers_found"] is False
    assert k_res["final_risk_score"] < 40.0
    assert k_res["classification"] in ["NORMAL", "LOW RISK"]


def test_02_normal_udp_flow():
    """TEST-02: Normal UDP flow should process without signature errors."""
    flow = {
        "flow_id": "TEST-02",
        "source_ip": "192.0.2.22",
        "destination_ip": "198.51.100.30",
        "source_port": 50111,
        "destination_port": 123,
        "protocol": "UDP",
        "packet_count": 4,
        "byte_count": 320,
        "duration_seconds": 0.1,
        "connection_count": 1,
        "failed_connection_count": 0,
        "syn_count": 0,
        "rst_count": 0,
    }
    feats = extract_network_features(flow)
    assert feats["protocol"] == "UDP"
    assert feats["is_valid"] is True


def test_03_normal_dns_flow():
    """TEST-03: Normal DNS traffic (port 53 UDP) should have baseline risk."""
    flow = {
        "flow_id": "TEST-03",
        "source_ip": "192.0.2.10",
        "destination_ip": "198.51.100.53",
        "source_port": 53200,
        "destination_port": 53,
        "protocol": "UDP",
        "packet_count": 2,
        "byte_count": 140,
        "duration_seconds": 0.05,
        "connection_count": 1,
        "failed_connection_count": 0,
        "syn_count": 0,
        "rst_count": 0,
    }
    feats = extract_network_features(flow)
    rule_res = RuleEngine().analyze_flow(feats)
    assert rule_res["triggers_found"] is False


def test_04_normal_https_flow():
    """TEST-04: Standard port 443 HTTPS flow should produce no security alert."""
    flow = {
        "flow_id": "TEST-04",
        "source_ip": "192.0.2.14",
        "destination_ip": "198.51.100.44",
        "source_port": 49200,
        "destination_port": 443,
        "protocol": "TCP",
        "packet_count": 30,
        "byte_count": 24000,
        "duration_seconds": 3.0,
        "connection_count": 2,
        "failed_connection_count": 0,
        "syn_count": 2,
        "rst_count": 0,
    }
    feats = extract_network_features(flow)
    r_res = RuleEngine().analyze_flow(feats)
    a_res = AnomalyDetector().calculate_anomaly_score(feats)
    k_res = RiskEngine().calculate_risk_score(r_res, a_res)
    alert = AlertEngine().evaluate_and_generate_alert(feats, r_res, a_res, k_res)
    assert alert is None


# -------------------------------------------------------------
# TEST CASES 5 TO 9: DEFENSIVE THREAT PATTERN DETECTION
# -------------------------------------------------------------

def test_05_high_connection_rate():
    """TEST-05: Excessive connection rate must trigger rule IDS-001."""
    flow = {
        "flow_id": "TEST-05",
        "source_ip": "192.0.2.50",
        "destination_ip": "198.51.100.10",
        "source_port": 55555,
        "destination_port": 80,
        "protocol": "TCP",
        "packet_count": 400,
        "byte_count": 80000,
        "duration_seconds": 1.0,
        "connection_count": 50,  # 50 conns/sec > 25 threshold
        "failed_connection_count": 0,
        "syn_count": 50,
        "rst_count": 0,
    }
    feats = extract_network_features(flow)
    r_res = RuleEngine().analyze_flow(feats)
    matched_ids = [m["rule_id"] for m in r_res["matched_rules"]]
    assert "IDS-001" in matched_ids
    assert r_res["highest_severity"] == "HIGH"


def test_06_repeated_failed_connections():
    """TEST-06: Repeated failed connections must trigger rule IDS-002."""
    flow = {
        "flow_id": "TEST-06",
        "source_ip": "192.0.2.55",
        "destination_ip": "198.51.100.22",
        "source_port": 49100,
        "destination_port": 22,
        "protocol": "TCP",
        "packet_count": 40,
        "byte_count": 3000,
        "duration_seconds": 4.0,
        "connection_count": 20,
        "failed_connection_count": 18,  # failure ratio 0.9 > 0.5
        "syn_count": 20,
        "rst_count": 18,
    }
    feats = extract_network_features(flow)
    r_res = RuleEngine().analyze_flow(feats)
    matched_ids = [m["rule_id"] for m in r_res["matched_rules"]]
    assert "IDS-002" in matched_ids


def test_07_multi_port_pattern():
    """TEST-07: Flow contacting high port count must trigger rule IDS-003."""
    flow = {
        "flow_id": "TEST-07",
        "source_ip": "192.0.2.60",
        "destination_ip": "198.51.100.99",
        "source_port": 50000,
        "destination_port": 80,
        "protocol": "TCP",
        "packet_count": 60,
        "byte_count": 4000,
        "duration_seconds": 2.0,
        "connection_count": 30,
        "unique_destination_ports": 25,  # > 15 threshold
        "failed_connection_count": 20,
        "syn_count": 30,
        "rst_count": 20,
    }
    feats = extract_network_features(flow)
    r_res = RuleEngine().analyze_flow(feats)
    matched_ids = [m["rule_id"] for m in r_res["matched_rules"]]
    assert "IDS-003" in matched_ids


def test_08_syn_heavy_pattern():
    """TEST-08: High SYN flag proportion must trigger rule IDS-004."""
    flow = {
        "flow_id": "TEST-08",
        "source_ip": "192.0.2.70",
        "destination_ip": "198.51.100.80",
        "source_port": 52000,
        "destination_port": 8080,
        "protocol": "TCP",
        "packet_count": 50,
        "byte_count": 3200,
        "duration_seconds": 1.5,
        "connection_count": 40,
        "failed_connection_count": 10,
        "syn_count": 45,  # syn_ratio = 45/50 = 0.90 > 0.70
        "rst_count": 5,
    }
    feats = extract_network_features(flow)
    r_res = RuleEngine().analyze_flow(feats)
    matched_ids = [m["rule_id"] for m in r_res["matched_rules"]]
    assert "IDS-004" in matched_ids


def test_09_high_traffic_volume():
    """TEST-09: Abnormally large byte volume must trigger rule IDS-006."""
    flow = {
        "flow_id": "TEST-09",
        "source_ip": "192.0.2.80",
        "destination_ip": "198.51.100.90",
        "source_port": 53000,
        "destination_port": 443,
        "protocol": "TCP",
        "packet_count": 5000,
        "byte_count": 2500000,  # 2.5 MB > 500 KB threshold
        "duration_seconds": 5.0,
        "connection_count": 5,
        "failed_connection_count": 0,
        "syn_count": 5,
        "rst_count": 0,
    }
    feats = extract_network_features(flow)
    r_res = RuleEngine().analyze_flow(feats)
    matched_ids = [m["rule_id"] for m in r_res["matched_rules"]]
    assert "IDS-006" in matched_ids


# -------------------------------------------------------------
# TEST CASES 10 TO 16: INPUT VALIDATION & DEFENSIVE ERROR HANDLING
# -------------------------------------------------------------

def test_10_invalid_source_ip():
    """TEST-10: Malformed source IP must be caught during feature validation."""
    flow = {
        "flow_id": "TEST-10",
        "source_ip": "999.999.999.999",  # Invalid IPv4
        "destination_ip": "198.51.100.1",
        "source_port": 1024,
        "destination_port": 80,
    }
    feats = extract_network_features(flow)
    assert feats["is_valid"] is False
    assert any("source IP" in err for err in feats["validation_errors"])


def test_11_invalid_destination_ip():
    """TEST-11: Malformed destination IP must be caught during feature validation."""
    flow = {
        "flow_id": "TEST-11",
        "source_ip": "192.0.2.1",
        "destination_ip": "not_an_ip",
        "source_port": 1024,
        "destination_port": 80,
    }
    feats = extract_network_features(flow)
    assert feats["is_valid"] is False
    assert any("destination IP" in err for err in feats["validation_errors"])


def test_12_invalid_source_port():
    """TEST-12: Source port > 65535 must fail validation."""
    assert validate_port(70000) is False
    flow = {
        "source_ip": "192.0.2.1",
        "destination_ip": "198.51.100.1",
        "source_port": 70000,
        "destination_port": 80,
    }
    feats = extract_network_features(flow)
    assert feats["is_valid"] is False


def test_13_invalid_destination_port():
    """TEST-13: Negative destination port must fail validation."""
    assert validate_port(-5) is False
    flow = {
        "source_ip": "192.0.2.1",
        "destination_ip": "198.51.100.1",
        "source_port": 1024,
        "destination_port": -5,
    }
    feats = extract_network_features(flow)
    assert feats["is_valid"] is False


def test_14_unsupported_protocol():
    """TEST-14: Unsupported protocol string must fail validation."""
    assert validate_protocol("BOGUS_PROTO") is False
    flow = {
        "source_ip": "192.0.2.1",
        "destination_ip": "198.51.100.1",
        "source_port": 1024,
        "destination_port": 80,
        "protocol": "BOGUS_PROTO",
    }
    feats = extract_network_features(flow)
    assert feats["is_valid"] is False


def test_15_missing_packet_count():
    """TEST-15: Missing packet_count must safely default to safe integer without crash."""
    flow = {
        "source_ip": "192.0.2.1",
        "destination_ip": "198.51.100.1",
        "source_port": 1024,
        "destination_port": 80,
        # packet_count omitted
    }
    feats = extract_network_features(flow)
    assert feats["packet_count"] == 0
    assert feats["average_packet_size"] == 0.0


def test_16_zero_duration():
    """TEST-16: Zero duration must not cause ZeroDivisionError in rate calculations."""
    flow = {
        "source_ip": "192.0.2.1",
        "destination_ip": "198.51.100.1",
        "source_port": 1024,
        "destination_port": 80,
        "duration_seconds": 0.0,
        "packet_count": 10,
        "byte_count": 5000,
        "connection_count": 1,
    }
    feats = extract_network_features(flow)
    assert feats["duration"] == 0.0
    assert feats["bytes_per_second"] > 0.0
    assert feats["packets_per_second"] > 0.0


# -------------------------------------------------------------
# TEST CASES 17 TO 22: IDS ENGINE COMPONENTS & CORRELATION
# -------------------------------------------------------------

def test_17_feature_extraction():
    """TEST-17: Feature extractor should compute all 15 derived security metrics."""
    flow = {
        "flow_id": "FEAT-TEST",
        "source_ip": "192.0.2.10",
        "destination_ip": "198.51.100.20",
        "source_port": 49152,
        "destination_port": 443,
        "protocol": "TCP",
        "packet_count": 20,
        "byte_count": 10000,
        "duration_seconds": 2.0,
        "connection_count": 4,
        "failed_connection_count": 1,
        "syn_count": 4,
        "rst_count": 1,
        "unique_destination_ports": 1,
        "unique_destination_ips": 1,
    }
    feats = extract_network_features(flow)
    assert feats["bytes_per_second"] == 5000.0
    assert feats["packets_per_second"] == 10.0
    assert feats["average_packet_size"] == 500.0
    assert feats["failure_ratio"] == 0.25
    assert feats["syn_ratio"] == 0.20
    assert feats["connection_rate"] == 2.0


def test_18_rule_detection():
    """TEST-18: Rule engine should evaluate rule thresholds correctly."""
    re = RuleEngine()
    test_feats = {
        "destination_port": 1337,  # Unusual port rule IDS-005
        "scenario_type": "UNUSUAL_PORT_ACTIVITY",
    }
    res = re.analyze_flow(test_feats)
    matched_ids = [m["rule_id"] for m in res["matched_rules"]]
    assert "IDS-005" in matched_ids
    assert res["triggers_found"] is True


def test_19_anomaly_score():
    """TEST-19: Anomaly detector must produce calibrated score between 0 and 100."""
    ad = AnomalyDetector()
    feats_normal = {"connection_rate": 2.0, "failure_ratio": 0.0, "unique_destination_ports": 1, "packets_per_second": 20.0, "bytes_per_second": 15000.0}
    feats_extreme = {"connection_rate": 80.0, "failure_ratio": 0.95, "unique_destination_ports": 50, "packets_per_second": 500.0, "bytes_per_second": 2000000.0}

    score_normal = ad.calculate_anomaly_score(feats_normal)["anomaly_score"]
    score_extreme = ad.calculate_anomaly_score(feats_extreme)["anomaly_score"]

    assert 0.0 <= score_normal <= 100.0
    assert 0.0 <= score_extreme <= 100.0
    assert score_extreme > score_normal


def test_20_risk_score():
    """TEST-20: Risk engine must produce weighted composite score and tier."""
    re = RiskEngine()
    rule_res = {"rule_risk_score": 75.0, "highest_severity": "HIGH"}
    anom_res = {"anomaly_score": 60.0}
    ml_res = {"suspicious_probability": 0.85, "is_available": True}

    res = re.calculate_risk_score(rule_res, anom_res, ml_res)
    assert 0.0 <= res["final_risk_score"] <= 100.0
    assert res["classification"] in ["SUSPICIOUS", "HIGH RISK", "CRITICAL INVESTIGATION"]


def test_21_alert_creation():
    """TEST-21: Alert engine must generate structured alert with ALT- id prefix."""
    ae = AlertEngine()
    feats = {"flow_id": "F-100", "source_ip": "192.0.2.1", "destination_ip": "198.51.100.1", "source_port": 1000, "destination_port": 80, "protocol": "TCP"}
    rule_res = {"matched_rules": [{"rule_id": "IDS-001", "name": "Excessive Connection Rate", "severity": "HIGH", "description": "Rate breach."}]}
    anom_res = {"is_anomalous": True, "anomaly_score": 65.0}
    risk_res = {"final_risk_score": 72.0, "classification": "HIGH RISK"}

    alert = ae.evaluate_and_generate_alert(feats, rule_res, anom_res, risk_res)
    assert alert is not None
    assert alert["alert_id"].startswith("ALT-")
    assert alert["severity"] == "HIGH"
    assert alert["status"] == "NEW"


def test_22_alert_correlation():
    """TEST-22: Consecutive alerts from same source within time window must group into single incident."""
    ce = AlertCorrelationEngine(time_window_seconds=60)
    now_iso = datetime.now(timezone.utc).isoformat()
    a1 = {"alert_id": "ALT-1", "source_ip": "192.0.2.99", "alert_type": "SYN_FLOOD", "timestamp": now_iso, "severity": "HIGH", "risk_score": 70.0}
    a2 = {"alert_id": "ALT-2", "source_ip": "192.0.2.99", "alert_type": "SYN_FLOOD", "timestamp": now_iso, "severity": "HIGH", "risk_score": 75.0}

    inc1 = ce.correlate_alert(a1)
    inc2 = ce.correlate_alert(a2)

    assert inc1["incident_id"] == inc2["incident_id"]
    assert inc2["alert_count"] == 2
    assert "ALT-1" in inc2["alert_ids"]
    assert "ALT-2" in inc2["alert_ids"]


# -------------------------------------------------------------
# TEST CASES 23 TO 26: SOC TRIAGE, PERSISTENCE & ANALYTICS
# -------------------------------------------------------------

def test_23_alert_status_update(test_db):
    """TEST-23: Alert status update from NEW to INVESTIGATING to RESOLVED."""
    alert = Alert(
        alert_id="ALT-STATUS-TEST",
        flow_id="FLOW-ST",
        rule_id="IDS-001",
        alert_type="Rate Breach",
        severity="HIGH",
        description="Testing status triage",
        risk_score=75.0,
        status="NEW",
        created_at=datetime.now(timezone.utc).isoformat(),
        source_ip="192.0.2.1",
        destination_ip="198.51.100.1",
    )
    test_db.add(alert)
    test_db.commit()

    # Update to INVESTIGATING
    alert.status = "INVESTIGATING"
    test_db.commit()
    assert test_db.query(Alert).filter(Alert.alert_id == "ALT-STATUS-TEST").first().status == "INVESTIGATING"

    # Update to RESOLVED
    alert.status = "RESOLVED"
    test_db.commit()
    assert test_db.query(Alert).filter(Alert.alert_id == "ALT-STATUS-TEST").first().status == "RESOLVED"


def test_24_analyst_note(test_db):
    """TEST-24: Analyst note must attach to alert with author and timestamp."""
    note = IncidentNote(
        alert_id="ALT-STATUS-TEST",
        analyst_name="Tier 1 Analyst",
        note="Verified with network team: expected backup batch.",
        created_at=datetime.now(timezone.utc).isoformat(),
    )
    test_db.add(note)
    test_db.commit()

    saved = test_db.query(IncidentNote).filter(IncidentNote.alert_id == "ALT-STATUS-TEST").first()
    assert saved is not None
    assert "expected backup batch" in saved.note


def test_25_database_storage(test_db):
    """TEST-25: Ingested NetworkFlow record commits and retrieves from database."""
    flow = NetworkFlow(
        flow_id="FLOW-DB-TEST",
        timestamp=datetime.now(timezone.utc).isoformat(),
        source_ip="192.0.2.40",
        destination_ip="198.51.100.40",
        source_port=50000,
        destination_port=443,
        protocol="TCP",
        packet_count=15,
        byte_count=12000,
        duration=1.5,
        risk_score=15.0,
        classification="NORMAL",
    )
    test_db.add(flow)
    test_db.commit()

    retrieved = test_db.query(NetworkFlow).filter(NetworkFlow.flow_id == "FLOW-DB-TEST").first()
    assert retrieved is not None
    assert retrieved.source_ip == "192.0.2.40"
    assert retrieved.classification == "NORMAL"


def test_26_dashboard_statistics(api_client):
    """TEST-26: Dashboard statistics endpoint must return valid numeric totals."""
    res = api_client.get("/api/dashboard/stats")
    assert res.status_code == 200
    data = res.json()
    assert "total_flows" in data
    assert "normal_flows" in data
    assert "suspicious_flows" in data
    assert "open_alerts" in data
    assert "average_risk_score" in data


# -------------------------------------------------------------
# TEST CASES 27 TO 30: ML, API, EDGE CASES & DUPLICATES
# -------------------------------------------------------------

def test_27_ml_prediction():
    """TEST-27: ML predictor produces class prediction and probability from trained models."""
    predictor = MLPredictor(models_dir="models")
    if not predictor.is_loaded:
        pytest.skip("ML artifacts not loaded")

    features = {
        "packet_count": 500,
        "byte_count": 100000,
        "duration": 1.0,
        "bytes_per_second": 100000.0,
        "packets_per_second": 500.0,
        "connection_count": 60,
        "failed_connection_count": 20,
        "syn_count": 50,
        "rst_count": 10,
        "average_packet_size": 200.0,
    }
    pred = predictor.predict_flow(features)
    assert pred["prediction"] in ["NORMAL", "SUSPICIOUS"]
    assert 0.0 <= pred["suspicious_probability"] <= 1.0


def test_28_api_validation(api_client):
    """TEST-28: Flow input with invalid port or protocol must return HTTP 422 Unprocessable Entity."""
    invalid_payload = {
        "source_ip": "192.0.2.1",
        "destination_ip": "198.51.100.1",
        "source_port": 99999,  # Port > 65535
        "destination_port": 80,
        "protocol": "TCP",
    }
    res = api_client.post("/api/flows", json=invalid_payload)
    assert res.status_code == 422


def test_29_empty_dataset():
    """TEST-29: Anomaly detector must handle empty baseline DataFrame gracefully with defaults."""
    import pandas as pd
    ad = AnomalyDetector(baseline_df=pd.DataFrame())
    score = ad.calculate_anomaly_score({"connection_rate": 2.0})["anomaly_score"]
    assert 0.0 <= score <= 100.0


def test_30_duplicate_event_handling(test_db):
    """TEST-30: Processing flow with duplicate flow_id must not crash the service."""
    service = IDSService()
    flow = {
        "flow_id": "FLOW-DUPE-01",
        "source_ip": "192.0.2.15",
        "destination_ip": "198.51.100.20",
        "source_port": 50000,
        "destination_port": 443,
        "protocol": "TCP",
        "packet_count": 10,
        "byte_count": 5000,
        "duration_seconds": 1.0,
    }

    # Ingest twice
    r1 = service.process_flow(flow, test_db)
    r2 = service.process_flow(flow, test_db)

    assert r1["status"] == "PROCESSED"
    assert r2["status"] == "PROCESSED"
