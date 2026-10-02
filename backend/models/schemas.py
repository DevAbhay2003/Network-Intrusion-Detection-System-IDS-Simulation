"""
Pydantic Schemas for Request Validation and Response Serialization
Defensive Cybersecurity Engineering Project: Network Intrusion Detection System (IDS) Simulation
"""

from typing import Dict, List, Optional, Any
from pydantic import BaseModel, Field, field_validator


class FlowInput(BaseModel):
    flow_id: Optional[str] = None
    timestamp: Optional[str] = None
    source_ip: str = Field(..., description="IPv4 or IPv6 address")
    destination_ip: str = Field(..., description="IPv4 or IPv6 address")
    source_port: int = Field(..., ge=1, le=65535)
    destination_port: int = Field(..., ge=1, le=65535)
    protocol: str = Field(default="TCP")
    packet_count: int = Field(default=1, ge=0)
    byte_count: int = Field(default=64, ge=0)
    duration_seconds: Optional[float] = Field(default=1.0, ge=0.0)
    duration: Optional[float] = Field(default=None, ge=0.0)
    connection_count: Optional[int] = Field(default=1, ge=0)
    failed_connection_count: Optional[int] = Field(default=0, ge=0)
    syn_count: Optional[int] = Field(default=1, ge=0)
    rst_count: Optional[int] = Field(default=0, ge=0)
    scenario_type: Optional[str] = "NORMAL_CUSTOM"

    @field_validator("protocol")
    @classmethod
    def validate_proto(cls, v: str) -> str:
        proto = v.strip().upper()
        if proto not in ["TCP", "UDP", "ICMP"]:
            raise ValueError("Protocol must be TCP, UDP, or ICMP")
        return proto


class FlowResponse(BaseModel):
    id: int
    flow_id: str
    timestamp: str
    source_ip: str
    destination_ip: str
    source_port: int
    destination_port: int
    protocol: str
    packet_count: int
    byte_count: int
    duration: float
    risk_score: float
    classification: str
    scenario_type: str

    class Config:
        from_attributes = True


class IncidentNoteCreate(BaseModel):
    note: str = Field(..., min_length=1, max_length=2000)
    analyst_name: Optional[str] = "SOC Analyst"


class IncidentNoteResponse(BaseModel):
    note_id: int
    alert_id: str
    analyst_name: str
    note: str
    created_at: str

    class Config:
        from_attributes = True


class AlertResponse(BaseModel):
    id: int
    alert_id: str
    flow_id: str
    rule_id: str
    alert_type: str
    severity: str
    description: str
    risk_score: float
    status: str
    created_at: str
    source_ip: str
    destination_ip: str
    source_port: int
    destination_port: int
    protocol: str
    notes: List[IncidentNoteResponse] = []

    class Config:
        from_attributes = True


class AlertStatusUpdate(BaseModel):
    status: str = Field(..., description="NEW, INVESTIGATING, RESOLVED, or FALSE_POSITIVE")

    @field_validator("status")
    @classmethod
    def validate_status(cls, v: str) -> str:
        s = v.strip().upper()
        if s not in ["NEW", "INVESTIGATING", "RESOLVED", "FALSE_POSITIVE"]:
            raise ValueError("Status must be NEW, INVESTIGATING, RESOLVED, or FALSE_POSITIVE")
        return s


class RuleResponse(BaseModel):
    rule_id: str
    rule_name: str
    description: str
    severity: str
    threshold: Dict[str, Any]
    enabled: bool


class RuleUpdateRequest(BaseModel):
    rule_name: Optional[str] = None
    description: Optional[str] = None
    severity: Optional[str] = None
    enabled: Optional[bool] = None
    threshold: Optional[Dict[str, Any]] = None


class DashboardStats(BaseModel):
    total_flows: int
    normal_flows: int
    suspicious_flows: int
    open_alerts: int
    critical_alerts: int
    average_risk_score: float


class IngestionResult(BaseModel):
    status: str
    flow_id: str
    risk_score: float
    classification: str
    alert_generated: bool
    alert: Optional[Dict[str, Any]] = None
