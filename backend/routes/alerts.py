"""
Security Alerts and Incident Management Endpoints
Defensive Cybersecurity Engineering Project: Network Intrusion Detection System (IDS) Simulation
"""

from datetime import datetime, timezone
from typing import List, Optional, Dict, Any
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session
from sqlalchemy import desc

from backend.database import get_db
from backend.models.db_models import Alert, IncidentNote, NetworkFlow
from backend.models.schemas import AlertResponse, AlertStatusUpdate, IncidentNoteCreate, IncidentNoteResponse
from backend.services.ids_service import ids_service
from ids.alert_engine import get_recommended_investigation_steps
from backend.utils.validators import sanitize_text


router = APIRouter(prefix="/api/alerts", tags=["Security Alerts"])


@router.get("", response_model=List[AlertResponse])
def get_alerts(
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    severity: Optional[str] = Query(None, description="INFO, LOW, MEDIUM, HIGH, CRITICAL"),
    status: Optional[str] = Query(None, description="NEW, INVESTIGATING, RESOLVED, FALSE_POSITIVE"),
    search: Optional[str] = Query(None, description="Filter by IP address or alert type"),
    db: Session = Depends(get_db)
):
    """
    Returns security alerts ordered by most recent detection.
    """
    query = db.query(Alert).order_by(desc(Alert.id))

    if severity:
        query = query.filter(Alert.severity == severity.strip().upper())
    if status:
        query = query.filter(Alert.status == status.strip().upper())
    if search:
        s = f"%{search.strip()}%"
        query = query.filter(
            (Alert.source_ip.like(s)) |
            (Alert.destination_ip.like(s)) |
            (Alert.alert_type.like(s)) |
            (Alert.rule_id.like(s))
        )

    alerts = query.offset(offset).limit(limit).all()
    return alerts


@router.get("/incidents/correlated")
def get_correlated_incidents():
    """
    Returns all correlated security incident clusters.
    """
    incidents = ids_service.correlation_engine.get_all_incidents()
    return incidents


@router.get("/{alert_id}")
def get_alert_detail(alert_id: str, db: Session = Depends(get_db)):
    """
    Retrieves complete security event investigation dossier for a specific alert,
    including linked flow records, investigation SOP recommendations, and analyst notes.
    """
    alert = db.query(Alert).filter(Alert.alert_id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail=f"Alert {alert_id} not found.")

    flow = db.query(NetworkFlow).filter(NetworkFlow.flow_id == alert.flow_id).first()
    notes = db.query(IncidentNote).filter(IncidentNote.alert_id == alert_id).order_by(IncidentNote.note_id).all()

    investigation_steps = get_recommended_investigation_steps(alert.alert_type, alert.severity)

    return {
        "alert_id": alert.alert_id,
        "flow_id": alert.flow_id,
        "rule_id": alert.rule_id,
        "alert_type": alert.alert_type,
        "severity": alert.severity,
        "risk_score": alert.risk_score,
        "status": alert.status,
        "created_at": alert.created_at,
        "source_ip": alert.source_ip,
        "destination_ip": alert.destination_ip,
        "source_port": alert.source_port,
        "destination_port": alert.destination_port,
        "protocol": alert.protocol,
        "description": alert.description,
        "flow_details": {
            "packet_count": flow.packet_count if flow else None,
            "byte_count": flow.byte_count if flow else None,
            "duration": flow.duration if flow else None,
            "scenario_type": flow.scenario_type if flow else None,
            "classification": flow.classification if flow else None,
        },
        "investigation_steps": investigation_steps,
        "notes": [
            {
                "note_id": n.note_id,
                "analyst_name": n.analyst_name,
                "note": n.note,
                "created_at": n.created_at
            } for n in notes
        ]
    }


@router.put("/{alert_id}/status")
def update_alert_status(alert_id: str, payload: AlertStatusUpdate, db: Session = Depends(get_db)):
    """
    Updates the lifecycle triage status of an alert (NEW -> INVESTIGATING -> RESOLVED or FALSE_POSITIVE).
    """
    alert = db.query(Alert).filter(Alert.alert_id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail=f"Alert {alert_id} not found.")

    old_status = alert.status
    alert.status = payload.status
    db.commit()

    return {
        "alert_id": alert_id,
        "previous_status": old_status,
        "current_status": alert.status,
        "updated_at": datetime.now(timezone.utc).isoformat(),
    }


@router.post("/{alert_id}/notes", response_model=IncidentNoteResponse, status_code=status.HTTP_201_CREATED)
def add_incident_note(alert_id: str, note_in: IncidentNoteCreate, db: Session = Depends(get_db)):
    """
    Attaches a defensive investigation finding or resolution justification note to an alert.
    """
    alert = db.query(Alert).filter(Alert.alert_id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail=f"Alert {alert_id} not found.")

    clean_note = sanitize_text(note_in.note)
    now_str = datetime.now(timezone.utc).isoformat()

    note_entity = IncidentNote(
        alert_id=alert_id,
        analyst_name=sanitize_text(note_in.analyst_name or "SOC Analyst"),
        note=clean_note,
        created_at=now_str
    )

    db.add(note_entity)
    db.commit()
    db.refresh(note_entity)

    return note_entity
