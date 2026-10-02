"""
SOC Dashboard Analytics and Metrics Endpoints
Defensive Cybersecurity Engineering Project: Network Intrusion Detection System (IDS) Simulation
"""

from typing import Dict, Any, List
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import func, desc

from backend.database import get_db
from backend.models.db_models import NetworkFlow, Alert
from backend.models.schemas import DashboardStats


router = APIRouter(prefix="/api/dashboard", tags=["SOC Dashboard"])


@router.get("/stats", response_model=DashboardStats)
def get_dashboard_stats(db: Session = Depends(get_db)):
    """
    Returns high-level SOC key metrics for top summary cards.
    """
    total_flows = db.query(NetworkFlow).count()
    normal_flows = db.query(NetworkFlow).filter(NetworkFlow.classification == "NORMAL").count()
    suspicious_flows = total_flows - normal_flows

    open_alerts = db.query(Alert).filter(Alert.status.in_(["NEW", "INVESTIGATING"])).count()
    critical_alerts = db.query(Alert).filter(Alert.severity == "CRITICAL", Alert.status != "RESOLVED").count()

    avg_risk = db.query(func.avg(NetworkFlow.risk_score)).scalar() or 0.0

    return DashboardStats(
        total_flows=total_flows,
        normal_flows=normal_flows,
        suspicious_flows=suspicious_flows,
        open_alerts=open_alerts,
        critical_alerts=critical_alerts,
        average_risk_score=round(float(avg_risk), 2),
    )


@router.get("/traffic")
def get_traffic_series(limit: int = 30, db: Session = Depends(get_db)):
    """
    Returns time-series throughput points (packets and bytes) for recent flows.
    """
    flows = db.query(NetworkFlow).order_by(desc(NetworkFlow.id)).limit(limit).all()
    # Reverse to chronological order
    flows = flows[::-1]

    labels = []
    packet_data = []
    byte_data = []
    risk_data = []

    for f in flows:
        t_label = f.timestamp.split("T")[-1][:8] if "T" in f.timestamp else f.timestamp[:8]
        labels.append(t_label)
        packet_data.append(f.packet_count)
        byte_data.append(f.byte_count)
        risk_data.append(round(f.risk_score, 1))

    return {
        "labels": labels,
        "packets": packet_data,
        "bytes": byte_data,
        "risks": risk_data,
    }


@router.get("/alerts-breakdown")
def get_alerts_breakdown(db: Session = Depends(get_db)):
    """
    Returns distributions of alerts by severity level and top alert rule types.
    """
    # By Severity
    sev_rows = db.query(Alert.severity, func.count(Alert.id)).group_by(Alert.severity).all()
    severities = {"INFO": 0, "LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}
    for sev, cnt in sev_rows:
        if sev in severities:
            severities[sev] = cnt

    # By Alert Type
    type_rows = db.query(Alert.alert_type, func.count(Alert.id)).group_by(Alert.alert_type).order_by(desc(func.count(Alert.id))).limit(6).all()
    types_dict = {t: cnt for t, cnt in type_rows}

    return {
        "by_severity": severities,
        "by_type": types_dict,
    }


@router.get("/protocols")
def get_protocol_distribution(db: Session = Depends(get_db)):
    """
    Returns count and percentage of flows by network transport protocol.
    """
    rows = db.query(NetworkFlow.protocol, func.count(NetworkFlow.id)).group_by(NetworkFlow.protocol).all()
    return {proto: cnt for proto, cnt in rows}


@router.get("/ports")
def get_port_distribution(db: Session = Depends(get_db)):
    """
    Returns distribution of top destination service ports contacted.
    """
    rows = db.query(NetworkFlow.destination_port, func.count(NetworkFlow.id)).group_by(NetworkFlow.destination_port).order_by(desc(func.count(NetworkFlow.id))).limit(8).all()
    return {f"Port {port}": cnt for port, cnt in rows}


@router.get("/top-sources")
def get_top_sources(db: Session = Depends(get_db)):
    """
    Returns top source IP addresses generating alerts for SOC threat triage.
    """
    rows = db.query(Alert.source_ip, func.count(Alert.id)).group_by(Alert.source_ip).order_by(desc(func.count(Alert.id))).limit(6).all()
    return [{"source_ip": ip, "alert_count": cnt} for ip, cnt in rows]


@router.get("/risk-distribution")
def get_risk_distribution(db: Session = Depends(get_db)):
    """
    Returns counts of flows categorized across standardized defense risk tiers.
    """
    tiers = {
        "NORMAL (0-20)": db.query(NetworkFlow).filter(NetworkFlow.risk_score <= 20).count(),
        "LOW RISK (21-40)": db.query(NetworkFlow).filter(NetworkFlow.risk_score > 20, NetworkFlow.risk_score <= 40).count(),
        "SUSPICIOUS (41-60)": db.query(NetworkFlow).filter(NetworkFlow.risk_score > 40, NetworkFlow.risk_score <= 60).count(),
        "HIGH RISK (61-80)": db.query(NetworkFlow).filter(NetworkFlow.risk_score > 60, NetworkFlow.risk_score <= 80).count(),
        "CRITICAL (81-100)": db.query(NetworkFlow).filter(NetworkFlow.risk_score > 80).count(),
    }
    return tiers
