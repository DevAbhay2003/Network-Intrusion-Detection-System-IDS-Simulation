"""
Synthetic Network Traffic Dataset Generator
Defensive Cybersecurity Engineering Project: Network Intrusion Detection System (IDS) Simulation

This module generates safe, synthetic network flow records strictly using
RFC 5737 documentation/reserved IP address blocks:
- 192.0.2.0/24   (TEST-NET-1)
- 198.51.100.0/24 (TEST-NET-2)
- 203.0.113.0/24  (TEST-NET-3)

No real packets are transmitted. All entries represent statistical flow records
modeled for intrusion detection training, baseline calculation, and anomaly detection.
"""

import os
import random
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, List, Any

import pandas as pd


# RFC 5737 Reserved Documentation IP Pools
SRC_IP_POOL = [f"192.0.2.{i}" for i in range(10, 60)]
DST_IP_POOL = [f"198.51.100.{i}" for i in range(10, 50)]
DMZ_IP_POOL = [f"203.0.113.{i}" for i in range(5, 25)]

# Standard Safe Services / Ports
SERVICE_PORTS = {
    "HTTP": 80,
    "HTTPS": 443,
    "DNS": 53,
    "SSH": 22,
    "SMTP": 25,
    "IMAPS": 993,
    "POSTGRES": 5432,
    "MYSQL": 3306,
    "RDP": 3389,
}

UNUSUAL_PORTS = [1337, 4444, 5555, 6667, 31337, 44444]


def generate_flow_record(
    scenario_type: str,
    base_time: datetime,
    flow_index: int
) -> Dict[str, Any]:
    """
    Generates a single synthetic flow record based on scenario parameters.
    """
    flow_id = f"FLOW-{flow_index:06d}"
    timestamp = (base_time + timedelta(seconds=flow_index * random.uniform(0.1, 1.5))).isoformat()

    # Default baseline initialization
    protocol = "TCP"
    src_ip = random.choice(SRC_IP_POOL)
    dst_ip = random.choice(DST_IP_POOL)
    src_port = random.randint(49152, 65535)
    dst_port = 443
    packet_count = random.randint(5, 50)
    duration_seconds = round(random.uniform(0.5, 10.0), 3)
    connection_count = random.randint(1, 4)
    failed_connection_count = 0
    syn_count = 1
    rst_count = 0
    byte_count = packet_count * random.randint(200, 1400)
    label = "NORMAL"

    if scenario_type == "NORMAL_WEB":
        dst_port = random.choice([80, 443])
        protocol = "TCP"
        packet_count = random.randint(10, 80)
        byte_count = packet_count * random.randint(400, 1450)
        duration_seconds = round(random.uniform(0.2, 5.0), 3)
        connection_count = random.randint(1, 5)
        failed_connection_count = 0
        syn_count = connection_count
        rst_count = 0
        label = "NORMAL"

    elif scenario_type == "NORMAL_DNS":
        dst_port = 53
        protocol = "UDP"
        packet_count = random.randint(2, 4)
        byte_count = packet_count * random.randint(60, 180)
        duration_seconds = round(random.uniform(0.01, 0.2), 3)
        connection_count = 1
        failed_connection_count = 0
        syn_count = 0
        rst_count = 0
        label = "NORMAL"

    elif scenario_type == "NORMAL_SSH":
        dst_port = 22
        protocol = "TCP"
        packet_count = random.randint(30, 200)
        byte_count = packet_count * random.randint(100, 500)
        duration_seconds = round(random.uniform(5.0, 120.0), 3)
        connection_count = 1
        failed_connection_count = 0
        syn_count = 1
        rst_count = 0
        label = "NORMAL"

    elif scenario_type == "NORMAL_EMAIL":
        dst_port = random.choice([25, 993])
        protocol = "TCP"
        packet_count = random.randint(12, 60)
        byte_count = packet_count * random.randint(300, 1200)
        duration_seconds = round(random.uniform(1.0, 15.0), 3)
        connection_count = random.randint(1, 3)
        failed_connection_count = 0
        syn_count = connection_count
        rst_count = 0
        label = "NORMAL"

    elif scenario_type == "NORMAL_DATABASE":
        dst_port = random.choice([5432, 3306])
        dst_ip = random.choice(DMZ_IP_POOL)
        protocol = "TCP"
        packet_count = random.randint(20, 150)
        byte_count = packet_count * random.randint(500, 1300)
        duration_seconds = round(random.uniform(0.5, 30.0), 3)
        connection_count = random.randint(1, 6)
        failed_connection_count = 0
        syn_count = connection_count
        rst_count = 0
        label = "NORMAL"

    # --- SUSPICIOUS SCENARIOS (DATA PATTERNS ONLY) ---
    elif scenario_type == "HIGH_CONNECTION_RATE":
        # Simulates an abnormally bursty flow rate from a single host
        dst_port = random.choice([80, 443, 8080])
        protocol = "TCP"
        packet_count = random.randint(150, 600)
        connection_count = random.randint(35, 120)
        duration_seconds = round(random.uniform(0.5, 2.0), 3)
        byte_count = packet_count * random.randint(150, 700)
        failed_connection_count = random.randint(2, 10)
        syn_count = connection_count
        rst_count = random.randint(1, 5)
        label = "SUSPICIOUS"

    elif scenario_type == "REPEATED_FAILED_CONNECTIONS":
        # Simulates authentication brute-force pattern or rejected sessions
        dst_port = random.choice([22, 3389, 21, 23])
        protocol = "TCP"
        connection_count = random.randint(15, 50)
        failed_connection_count = random.randint(12, connection_count)
        packet_count = connection_count * 2
        byte_count = packet_count * random.randint(60, 120)
        duration_seconds = round(random.uniform(1.0, 8.0), 3)
        syn_count = connection_count
        rst_count = failed_connection_count
        label = "SUSPICIOUS"

    elif scenario_type == "MULTI_PORT_PROBING_PATTERN":
        # Simulates sequential destination port probing pattern (e.g. reconnaissance pattern)
        dst_port = random.randint(1, 65535)
        protocol = "TCP"
        connection_count = random.randint(20, 80)
        failed_connection_count = random.randint(15, connection_count)
        packet_count = connection_count * 2
        byte_count = packet_count * 64
        duration_seconds = round(random.uniform(0.5, 3.0), 3)
        syn_count = connection_count
        rst_count = failed_connection_count
        label = "SUSPICIOUS"

    elif scenario_type == "SYN_HEAVY_PATTERN":
        # Simulates high ratio of SYN packets with minimal data / high RSTs
        dst_port = random.choice([80, 443, 8080])
        protocol = "TCP"
        connection_count = random.randint(40, 150)
        syn_count = connection_count
        rst_count = random.randint(20, connection_count)
        packet_count = syn_count + rst_count
        byte_count = packet_count * 60
        duration_seconds = round(random.uniform(0.2, 2.0), 3)
        failed_connection_count = rst_count
        label = "SUSPICIOUS"

    elif scenario_type == "UNUSUAL_PORT_ACTIVITY":
        # Simulates communication on non-standard high ports commonly flagged in SOCs
        dst_port = random.choice(UNUSUAL_PORTS)
        protocol = "TCP"
        packet_count = random.randint(10, 45)
        byte_count = packet_count * random.randint(100, 900)
        duration_seconds = round(random.uniform(0.5, 12.0), 3)
        connection_count = random.randint(2, 8)
        failed_connection_count = random.randint(0, 2)
        syn_count = connection_count
        rst_count = 0
        label = "SUSPICIOUS"

    elif scenario_type == "HIGH_TRAFFIC_VOLUME":
        # Simulates unexpected volumetric exfiltration or large data transfer spike
        dst_port = random.choice([443, 8443, 9000])
        protocol = "TCP"
        packet_count = random.randint(2000, 8000)
        byte_count = packet_count * random.randint(1200, 1460)
        duration_seconds = round(random.uniform(2.0, 10.0), 3)
        connection_count = random.randint(5, 20)
        failed_connection_count = 0
        syn_count = connection_count
        rst_count = 0
        label = "SUSPICIOUS"

    # Compute average packet size safely
    avg_pkt_size = round(byte_count / max(packet_count, 1), 2)

    return {
        "flow_id": flow_id,
        "timestamp": timestamp,
        "source_ip": src_ip,
        "destination_ip": dst_ip,
        "source_port": src_port,
        "destination_port": dst_port,
        "protocol": protocol,
        "packet_count": packet_count,
        "byte_count": byte_count,
        "duration_seconds": duration_seconds,
        "connection_count": connection_count,
        "failed_connection_count": failed_connection_count,
        "syn_count": syn_count,
        "rst_count": rst_count,
        "average_packet_size": avg_pkt_size,
        "label": label,
        "scenario_type": scenario_type,
    }


def generate_dataset(
    num_records: int = 6000,
    output_path: str = "data/network_traffic.csv",
    seed: int = 42
) -> pd.DataFrame:
    """
    Generates a balanced dataset of at least `num_records` (default 6,000)
    containing normal and suspicious defensive test scenarios.
    """
    random.seed(seed)
    base_time = datetime.now(timezone.utc) - timedelta(days=2)

    normal_scenarios = [
        ("NORMAL_WEB", 0.35),
        ("NORMAL_DNS", 0.20),
        ("NORMAL_SSH", 0.05),
        ("NORMAL_EMAIL", 0.05),
        ("NORMAL_DATABASE", 0.05),
    ]

    suspicious_scenarios = [
        ("HIGH_CONNECTION_RATE", 0.06),
        ("REPEATED_FAILED_CONNECTIONS", 0.06),
        ("MULTI_PORT_PROBING_PATTERN", 0.06),
        ("SYN_HEAVY_PATTERN", 0.05),
        ("UNUSUAL_PORT_ACTIVITY", 0.04),
        ("HIGH_TRAFFIC_VOLUME", 0.03),
    ]

    all_scenarios = normal_scenarios + suspicious_scenarios
    scenario_names, scenario_weights = zip(*all_scenarios)

    records = []
    print(f"[*] Generating {num_records} synthetic network flow records...")

    for i in range(1, num_records + 1):
        chosen_scenario = random.choices(scenario_names, weights=scenario_weights, k=1)[0]
        record = generate_flow_record(chosen_scenario, base_time, i)
        records.append(record)

    df = pd.DataFrame(records)

    # Ensure output directory exists
    out_dir = Path(output_path).parent
    out_dir.mkdir(parents=True, exist_ok=True)

    df.to_csv(output_path, index=False)
    print(f"[+] Dataset successfully generated and saved to: {output_path}")
    print(f"[+] Summary of Record Labels:\n{df['label'].value_counts(normalize=True).round(3) * 100}%")
    print(f"[+] Scenario Distribution:\n{df['scenario_type'].value_counts()}")

    return df


if __name__ == "__main__":
    generate_dataset()
