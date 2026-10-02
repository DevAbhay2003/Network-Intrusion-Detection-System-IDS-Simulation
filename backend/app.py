"""
Network Intrusion Detection System (IDS) Simulation - Application Entry Point
Defensive Cybersecurity Engineering Project

FastAPI Application hosting:
- REST APIs for Flow Ingestion, Alerts, Rules, and Dashboard Analytics
- In-process Background Simulation Engine
- Static Frontend SOC Analyst Dashboard & Event Investigation UI
"""

import os
from pathlib import Path
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse

from backend.database import engine, Base, SessionLocal
from backend.models import db_models
from backend.services.ids_service import ids_service
from backend.routes import flows, alerts, rules, dashboard, simulation


# Initialize Database Tables
Base.metadata.create_all(bind=engine)

# Seed Initial Signatures
with SessionLocal() as db_session:
    ids_service.seed_initial_rules_if_empty(db_session)

app = FastAPI(
    title="Network Intrusion Detection System (IDS) Simulation",
    description="Defensive Cybersecurity IDS Simulation with Hybrid Detection, Risk Scoring, and SOC Analytics",
    version="1.0.0",
)

# CORS Middleware for safe local development
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include API Routers
app.include_router(flows.router)
app.include_router(alerts.router)
app.include_router(rules.router)
app.include_router(dashboard.router)
app.include_router(simulation.router)

# Mount Static Assets and Dashboard Frontend
FRONTEND_DIR = Path(__file__).resolve().parent.parent / "frontend"
STATIC_DIR = FRONTEND_DIR / "static"
STATIC_DIR.mkdir(parents=True, exist_ok=True)

app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


@app.get("/api/health", tags=["Health"])
def health_check():
    """Health check endpoint for container / monitoring verification."""
    return {
        "status": "healthy",
        "service": "Network Intrusion Detection System (IDS)",
        "models_loaded": ids_service.ml_predictor.is_loaded,
        "rules_count": len(ids_service.rule_engine.rules),
    }


@app.get("/", tags=["Dashboard UI"])
def serve_dashboard():
    """Serves the primary SOC Analyst Interactive Dashboard."""
    index_path = FRONTEND_DIR / "templates" / "index.html"
    if index_path.exists():
        return FileResponse(index_path)
    return {"message": "SOC Dashboard interface loading. Template file not found."}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("backend.app:app", host="127.0.0.1", port=8000, reload=True)
