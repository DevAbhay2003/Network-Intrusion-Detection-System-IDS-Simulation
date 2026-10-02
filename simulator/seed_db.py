"""
Database Seeding Script for Instant Demonstration
Defensive Cybersecurity Engineering Project: Network Intrusion Detection System (IDS) Simulation

Ingests a representative slice of synthetic flows into the SQLite database,
generating real alerts, notes, and metrics so the SOC dashboard displays live analytics immediately.
"""

import os
import sys
from pathlib import Path
import pandas as pd

# Add project root to sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from backend.database import SessionLocal
from backend.services.ids_service import ids_service
from backend.models.db_models import IncidentNote, Alert


def seed_database(num_records: int = 150):
    data_file = Path("data/network_traffic.csv")
    if not data_file.exists():
        print("[!] Generating synthetic dataset first...")
        from simulator.generate_dataset import generate_dataset
        generate_dataset()

    print(f"[*] Loading sample of {num_records} flow records for database seeding...")
    df = pd.read_csv(data_file)
    sample_df = df.head(num_records)

    db = SessionLocal()
    try:
        # Seed rules
        ids_service.seed_initial_rules_if_empty(db)

        ingested_count = 0
        alert_count = 0

        for _, row in sample_df.iterrows():
            flow_dict = row.to_dict()
            res = ids_service.process_flow(flow_dict, db)
            ingested_count += 1
            if res.get("alert_generated"):
                alert_count += 1

        print(f"[+] Successfully seeded {ingested_count} flows and generated {alert_count} alerts.")

        # Add a sample analyst investigation note to one alert
        sample_alert = db.query(Alert).first()
        if sample_alert:
            sample_alert.status = "INVESTIGATING"
            note = IncidentNote(
                alert_id=sample_alert.alert_id,
                analyst_name="Tier-1 Analyst (Shift Lead)",
                note="Initial triage: Verified source IP against internal documentation subnets. Escalated to Tier-2 for endpoint validation.",
                created_at=sample_alert.created_at,
            )
            db.add(note)
            db.commit()
            print(f"[+] Attached demonstration investigation note to {sample_alert.alert_id}.")

    finally:
        db.close()


if __name__ == "__main__":
    seed_database()
