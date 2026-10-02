"""
Real-Time Network Flow Traffic Simulator
Defensive Cybersecurity Engineering Project: Network Intrusion Detection System (IDS) Simulation

Continuously generates safe synthetic network flow records representing normal
workstation/server communications and defensive threat detection scenarios.
Strictly emits DATA records using RFC 5737 documentation IP prefixes.
Does NOT transmit raw network packets or touch live networks.

CLI Options:
  --mode [normal | mixed]     Traffic mode (mixed includes synthetic threat patterns)
  --speed [slow | fast]       Generation rate (slow: 2.5s interval, fast: 0.5s interval)
  --target-url URL            Optional backend endpoint to post flows (default: http://127.0.0.1:8000/api/flows)
  --count N                   Stop after N flows (0 for infinite continuous streaming)
"""

import argparse
import json
import os
import random
import sys
import time
from datetime import datetime, timezone
from typing import Dict, Any, Generator

# Add project root to sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import requests
from simulator.generate_dataset import generate_flow_record


NORMAL_SCENARIOS = [
    ("NORMAL_WEB", 0.45),
    ("NORMAL_DNS", 0.25),
    ("NORMAL_SSH", 0.10),
    ("NORMAL_EMAIL", 0.10),
    ("NORMAL_DATABASE", 0.10),
]

MIXED_SCENARIOS = [
    ("NORMAL_WEB", 0.35),
    ("NORMAL_DNS", 0.20),
    ("NORMAL_SSH", 0.05),
    ("NORMAL_EMAIL", 0.05),
    ("NORMAL_DATABASE", 0.05),
    ("HIGH_CONNECTION_RATE", 0.06),
    ("REPEATED_FAILED_CONNECTIONS", 0.06),
    ("MULTI_PORT_PROBING_PATTERN", 0.06),
    ("SYN_HEAVY_PATTERN", 0.05),
    ("UNUSUAL_PORT_ACTIVITY", 0.04),
    ("HIGH_TRAFFIC_VOLUME", 0.03),
]


class NetworkTrafficSimulator:
    """
    Generates and optionally dispatches synthetic network flow events.
    """

    def __init__(self, mode: str = "mixed", speed: str = "fast", target_url: str = "http://127.0.0.1:8000/api/flows"):
        self.mode = mode.lower()
        self.speed = speed.lower()
        self.target_url = target_url
        self.interval = 0.5 if self.speed == "fast" else 2.0
        self.flow_counter = 0

    def get_next_scenario(self) -> str:
        """Selects scenario based on configured simulation mode."""
        scenarios = MIXED_SCENARIOS if self.mode == "mixed" else NORMAL_SCENARIOS
        names, weights = zip(*scenarios)
        return random.choices(names, weights=weights, k=1)[0]

    def generate_flow_event(self) -> Dict[str, Any]:
        """Creates a single real-time timestamped flow record."""
        self.flow_counter += 1
        scenario = self.get_next_scenario()
        now = datetime.now(timezone.utc)
        record = generate_flow_record(scenario, now, self.flow_counter)
        record["timestamp"] = now.isoformat()
        return record

    def stream_flows(self, max_count: int = 0) -> Generator[Dict[str, Any], None, None]:
        """Generator yielding flow events at configured speed interval."""
        generated = 0
        while True:
            flow = self.generate_flow_event()
            yield flow
            generated += 1
            if max_count > 0 and generated >= max_count:
                break
            time.sleep(self.interval)

    def run_simulation(self, max_count: int = 0, send_http: bool = True) -> None:
        """Runs the continuous generation loop with optional HTTP dispatch."""
        print(f"[*] Starting Network Flow Simulator [Mode: {self.mode.upper()}, Speed: {self.speed.upper()}]")
        print(f"[*] Target Endpoint: {self.target_url if send_http else 'Console Print Only'}")
        print("[*] Press Ctrl+C to terminate simulation safely.\n")

        for flow in self.stream_flows(max_count=max_count):
            flow_summary = (
                f"[{flow['timestamp'][:19]}] {flow['flow_id']} | "
                f"{flow['source_ip']}:{flow['source_port']} -> "
                f"{flow['destination_ip']}:{flow['destination_port']} "
                f"({flow['protocol']}) | {flow['scenario_type']} | {flow['label']}"
            )
            print(f"-> {flow_summary}")

            if send_http and self.target_url:
                try:
                    resp = requests.post(self.target_url, json=flow, timeout=1.5)
                    if resp.status_code == 201:
                        data = resp.json()
                        risk = data.get("risk_score", 0.0)
                        alert = data.get("alert")
                        if alert:
                            print(f"   [!] ALERT GENERATED: {alert['alert_id']} | {alert['alert_type']} | Severity: {alert['severity']} | Risk: {risk}/100")
                except requests.RequestException:
                    # Endpoint unavailable; continue streaming locally
                    pass


def main():
    parser = argparse.ArgumentParser(description="Synthetic Network Traffic Flow Simulator for IDS")
    parser.add_argument("--mode", choices=["normal", "mixed"], default="mixed", help="Traffic distribution mode")
    parser.add_argument("--speed", choices=["slow", "fast"], default="fast", help="Flow emission speed")
    parser.add_argument("--target-url", default="http://127.0.0.1:8000/api/flows", help="Backend IDS ingestion endpoint")
    parser.add_argument("--count", type=int, default=0, help="Total flows to emit (0 for continuous)")
    parser.add_argument("--no-http", action="store_true", help="Do not send HTTP POST requests (console only)")

    args = parser.parse_args()

    sim = NetworkTrafficSimulator(
        mode=args.mode,
        speed=args.speed,
        target_url=None if args.no_http else args.target_url
    )

    try:
        sim.run_simulation(max_count=args.count, send_http=not args.no_http)
    except KeyboardInterrupt:
        print("\n[+] Simulation terminated by user.")


if __name__ == "__main__":
    main()
