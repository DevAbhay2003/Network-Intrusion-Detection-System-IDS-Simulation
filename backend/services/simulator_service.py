"""
Background Traffic Simulation Service
Defensive Cybersecurity Engineering Project: Network Intrusion Detection System (IDS) Simulation

Manages in-process synthetic traffic generation so the IDS can be demonstrated
in near-real-time without requiring multiple separate shell windows.
"""

import threading
import time
from datetime import datetime, timezone
from typing import Dict, Any, Optional

from simulator.generate_dataset import generate_flow_record
from backend.database import SessionLocal
from backend.services.ids_service import ids_service


class SimulationManager:
    """
    Controls background simulation thread and scenario triggering.
    """

    def __init__(self):
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self.mode = "mixed"
        self.speed = "fast"
        self.total_generated = 0
        self.last_flow_time = None
        self._lock = threading.Lock()

    def is_running(self) -> bool:
        return self._running

    def get_status(self) -> Dict[str, Any]:
        return {
            "running": self._running,
            "mode": self.mode,
            "speed": self.speed,
            "total_generated": self.total_generated,
            "last_flow_time": self.last_flow_time,
        }

    def start(self, mode: str = "mixed", speed: str = "fast") -> bool:
        with self._lock:
            if self._running:
                return False
            self.mode = mode.lower()
            self.speed = speed.lower()
            self._running = True
            self._thread = threading.Thread(target=self._run_loop, daemon=True)
            self._thread.start()
            return True

    def stop(self) -> bool:
        with self._lock:
            if not self._running:
                return False
            self._running = False
            return True

    def trigger_scenario(self, scenario_type: str) -> Dict[str, Any]:
        """
        Immediately generates and processes a single specific scenario flow on demand.
        """
        now = datetime.now(timezone.utc)
        self.total_generated += 1
        record = generate_flow_record(scenario_type, now, self.total_generated)
        record["timestamp"] = now.isoformat()

        db = SessionLocal()
        try:
            result = ids_service.process_flow(record, db)
            self.last_flow_time = now.isoformat()
            return result
        finally:
            db.close()

    def _run_loop(self):
        """Thread worker loop generating continuous flows."""
        from simulator.traffic_simulator import NetworkTrafficSimulator
        sim = NetworkTrafficSimulator(mode=self.mode, speed=self.speed)
        interval = 0.8 if self.speed == "fast" else 2.5

        while self._running:
            flow = sim.generate_flow_event()
            db = SessionLocal()
            try:
                ids_service.process_flow(flow, db)
                self.total_generated += 1
                self.last_flow_time = flow["timestamp"]
            except Exception as e:
                print(f"[!] Simulation background error: {e}")
            finally:
                db.close()

            time.sleep(interval)


# Global instance
simulation_manager = SimulationManager()
