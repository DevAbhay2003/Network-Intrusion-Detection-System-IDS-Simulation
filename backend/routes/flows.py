"""
Network Flow Ingestion and Query Endpoints
Defensive Cybersecurity Engineering Project: Network Intrusion Detection System (IDS) Simulation
"""

from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session
from sqlalchemy import desc

from backend.database import get_db
from backend.models.db_models import NetworkFlow, Alert, IncidentNote, ModelResult
from backend.models.schemas import FlowInput, FlowResponse, IngestionResult
from backend.services.ids_service import ids_service
from backend.utils.validators import validate_network_endpoint


router = APIRouter(prefix="/api/flows", tags=["Network Flows"])


@router.post("", response_model=IngestionResult, status_code=status.HTTP_201_CREATED)
def ingest_flow(flow_in: FlowInput, db: Session = Depends(get_db)):
    """
    Ingests an individual network flow record, executes the defensive IDS inspection pipeline,
    generates alerts if risk thresholds are exceeded, and persists records to the database.
    """
    valid_src, err_src = validate_network_endpoint(flow_in.source_ip, flow_in.source_port)
    if not valid_src:
        raise HTTPException(status_code=422, detail=f"Source validation failed: {err_src}")

    valid_dst, err_dst = validate_network_endpoint(flow_in.destination_ip, flow_in.destination_port)
    if not valid_dst:
        raise HTTPException(status_code=422, detail=f"Destination validation failed: {err_dst}")

    flow_dict = flow_in.model_dump()
    result = ids_service.process_flow(flow_dict, db)

    return IngestionResult(
        status=result["status"],
        flow_id=result["flow_id"],
        risk_score=result["risk_score"],
        classification=result["classification"],
        alert_generated=result["alert_generated"],
        alert=result["alert"]
    )


@router.get("", response_model=List[FlowResponse])
def get_flows(
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    classification: Optional[str] = Query(None, description="NORMAL, LOW RISK, SUSPICIOUS, HIGH RISK, CRITICAL INVESTIGATION"),
    protocol: Optional[str] = Query(None, description="TCP, UDP, ICMP"),
    search: Optional[str] = Query(None, description="Search source or destination IP"),
    db: Session = Depends(get_db)
):
    """
    Retrieves ingested network flow records ordered by most recent timestamp.
    Supports filtering by classification, protocol, and IP search.
    """
    query = db.query(NetworkFlow).order_by(desc(NetworkFlow.id))

    if classification:
        query = query.filter(NetworkFlow.classification == classification.strip().upper())
    if protocol:
        query = query.filter(NetworkFlow.protocol == protocol.strip().upper())
    if search:
        s = f"%{search.strip()}%"
        query = query.filter((NetworkFlow.source_ip.like(s)) | (NetworkFlow.destination_ip.like(s)))

    flows = query.offset(offset).limit(limit).all()
    return flows


@router.get("/{flow_id}", response_model=FlowResponse)
def get_flow_by_id(flow_id: str, db: Session = Depends(get_db)):
    """
    Retrieves flow record details by unique flow identifier.
    """
    flow = db.query(NetworkFlow).filter(NetworkFlow.flow_id == flow_id).first()
    if not flow:
        raise HTTPException(status_code=404, detail=f"Flow record {flow_id} not found.")
    return flow


@router.post("/reset", status_code=status.HTTP_200_OK)
def reset_database(db: Session = Depends(get_db)):
    """
    Defensive testing utility: clears flows, alerts, and notes for fresh demonstration runs.
    """
    db.query(IncidentNote).delete()
    db.query(Alert).delete()
    db.query(ModelResult).delete()
    db.query(NetworkFlow).delete()
    db.commit()
    return {"message": "Database successfully reset for fresh simulation."}
