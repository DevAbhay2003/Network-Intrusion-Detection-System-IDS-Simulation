"""
Simulation Management Endpoints
Defensive Cybersecurity Engineering Project: Network Intrusion Detection System (IDS) Simulation
"""

from typing import Optional
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from backend.services.simulator_service import simulation_manager


router = APIRouter(prefix="/api/simulation", tags=["Traffic Simulation"])


class SimulationStartRequest(BaseModel):
    mode: Optional[str] = "mixed"  # "normal" or "mixed"
    speed: Optional[str] = "fast"  # "slow" or "fast"


class ScenarioTriggerRequest(BaseModel):
    scenario_type: str


@router.get("/status")
def get_status():
    """Returns status of real-time traffic simulation."""
    return simulation_manager.get_status()


@router.post("/start")
def start_simulation(payload: SimulationStartRequest):
    """Starts continuous background synthetic traffic generation."""
    success = simulation_manager.start(mode=payload.mode or "mixed", speed=payload.speed or "fast")
    if not success:
        return {"message": "Simulation is already running.", "status": simulation_manager.get_status()}
    return {"message": f"Simulation started in {payload.mode.upper()} mode.", "status": simulation_manager.get_status()}


@router.post("/stop")
def stop_simulation():
    """Stops continuous background synthetic traffic generation."""
    success = simulation_manager.stop()
    return {"message": "Simulation stopped." if success else "Simulation was not running.", "status": simulation_manager.get_status()}


@router.post("/trigger-scenario")
def trigger_scenario(payload: ScenarioTriggerRequest):
    """
    On-demand injection of a specific defensive traffic scenario (e.g. HIGH_CONNECTION_RATE,
    REPEATED_FAILED_CONNECTIONS, MULTI_PORT_PROBING_PATTERN, SYN_HEAVY_PATTERN, HIGH_TRAFFIC_VOLUME,
    NORMAL_WEB, NORMAL_DNS).
    """
    valid_scenarios = [
        "NORMAL_WEB",
        "NORMAL_DNS",
        "NORMAL_SSH",
        "NORMAL_EMAIL",
        "NORMAL_DATABASE",
        "HIGH_CONNECTION_RATE",
        "REPEATED_FAILED_CONNECTIONS",
        "MULTI_PORT_PROBING_PATTERN",
        "SYN_HEAVY_PATTERN",
        "UNUSUAL_PORT_ACTIVITY",
        "HIGH_TRAFFIC_VOLUME"
    ]

    sc = payload.scenario_type.strip().upper()
    if sc not in valid_scenarios:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid scenario type '{sc}'. Valid options: {', '.join(valid_scenarios)}"
        )

    result = simulation_manager.trigger_scenario(sc)
    return {
        "scenario": sc,
        "result": result
    }
