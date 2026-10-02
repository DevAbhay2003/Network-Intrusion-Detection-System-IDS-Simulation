"""
Signature Detection Rule Management Endpoints
Defensive Cybersecurity Engineering Project: Network Intrusion Detection System (IDS) Simulation
"""

import json
from typing import List, Dict, Any
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from backend.database import get_db
from backend.models.db_models import Rule
from backend.models.schemas import RuleResponse, RuleUpdateRequest
from backend.services.ids_service import ids_service


router = APIRouter(prefix="/api/rules", tags=["IDS Detection Rules"])


@router.get("", response_model=List[RuleResponse])
def get_rules(db: Session = Depends(get_db)):
    """
    Returns all configured detection signatures, operational status, and thresholds.
    """
    ids_service.seed_initial_rules_if_empty(db)
    db_rules = db.query(Rule).all()

    response = []
    for r in db_rules:
        th = {}
        try:
            th = json.loads(r.threshold) if r.threshold else {}
        except Exception:
            th = {}

        response.append(RuleResponse(
            rule_id=r.rule_id,
            rule_name=r.rule_name,
            description=r.description,
            severity=r.severity,
            threshold=th,
            enabled=r.enabled,
        ))

    return response


@router.put("/{rule_id}", response_model=RuleResponse)
def update_rule(rule_id: str, payload: RuleUpdateRequest, db: Session = Depends(get_db)):
    """
    Updates rule parameters or toggles enabled/disabled state for detection tuning.
    """
    rule = db.query(Rule).filter(Rule.rule_id == rule_id).first()
    if not rule:
        raise HTTPException(status_code=404, detail=f"Rule {rule_id} not found.")

    engine_updates: Dict[str, Any] = {}

    if payload.rule_name is not None:
        rule.rule_name = payload.rule_name
        engine_updates["name"] = payload.rule_name
    if payload.description is not None:
        rule.description = payload.description
        engine_updates["description"] = payload.description
    if payload.severity is not None:
        rule.severity = payload.severity
        engine_updates["severity"] = payload.severity
    if payload.enabled is not None:
        rule.enabled = payload.enabled
        engine_updates["enabled"] = payload.enabled
    if payload.threshold is not None:
        rule.threshold = json.dumps(payload.threshold)
        engine_updates["thresholds"] = payload.threshold

    db.commit()
    db.refresh(rule)

    # Sync with in-memory RuleEngine instance
    ids_service.rule_engine.update_rule(rule_id, engine_updates)

    th = json.loads(rule.threshold) if rule.threshold else {}
    return RuleResponse(
        rule_id=rule.rule_id,
        rule_name=rule.rule_name,
        description=rule.description,
        severity=rule.severity,
        threshold=th,
        enabled=rule.enabled,
    )
