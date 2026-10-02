"""
Network Feature Engineering Module
Defensive Cybersecurity Engineering Project: Network Intrusion Detection System (IDS) Simulation

This module extracts derived behavioral and volumetric features from raw network
flow records. It handles edge cases including zero-division, missing fields,
invalid ports, malformed IP addresses, and unsupported protocols.
"""

import ipaddress
import math
from typing import Dict, Any, List, Optional


VALID_PROTOCOLS = {"TCP", "UDP", "ICMP"}


def validate_ip_address(ip_str: str) -> bool:
    """
    Validates if an IP string is a valid IPv4 or IPv6 address.
    """
    if not ip_str or not isinstance(ip_str, str):
        return False
    try:
        ipaddress.ip_address(ip_str.strip())
        return True
    except ValueError:
        return False


def validate_port(port: Any) -> bool:
    """
    Validates if a port is an integer in the valid range 1 to 65535.
    """
    try:
        p = int(port)
        return 1 <= p <= 65535
    except (TypeError, ValueError):
        return False


def validate_protocol(protocol: str) -> bool:
    """
    Validates whether the protocol is recognized (TCP, UDP, ICMP).
    """
    if not protocol or not isinstance(protocol, str):
        return False
    return protocol.strip().upper() in VALID_PROTOCOLS


def extract_network_features(raw_flow: Dict[str, Any]) -> Dict[str, Any]:
    """
    Extracts derived cyber-defense statistical and behavioral metrics from a raw flow record.

    Derived Features:
    - packet_count: Total packets in flow
    - byte_count: Total bytes transferred
    - duration: Flow duration in seconds (min 0.001 to prevent zero-division)
    - bytes_per_second: Volumetric throughput rate
    - packets_per_second: Transmission frequency
    - average_packet_size: byte_count / packet_count
    - connection_count: Total connection attempts
    - failed_connection_count: Total rejected/failed attempts
    - failure_ratio: failed_connection_count / connection_count
    - syn_count: TCP SYN packet count
    - rst_count: TCP RST packet count
    - syn_ratio: syn_count / max(packet_count, 1)
    - unique_destination_ports: Count of distinct target ports (default 1 for single flow)
    - unique_destination_ips: Count of distinct target IPs (default 1 for single flow)
    - connection_rate: connection_count / duration
    - is_valid: Boolean indicating whether validation checks passed
    - validation_errors: List of validation anomalies if any
    """
    validation_errors: List[str] = []

    # 1. IP Validation
    src_ip = raw_flow.get("source_ip", "")
    dst_ip = raw_flow.get("destination_ip", "")
    if not validate_ip_address(src_ip):
        validation_errors.append(f"Invalid or malformed source IP: {src_ip}")
    if not validate_ip_address(dst_ip):
        validation_errors.append(f"Invalid or malformed destination IP: {dst_ip}")

    # 2. Port Validation
    src_port = raw_flow.get("source_port", 0)
    dst_port = raw_flow.get("destination_port", 0)
    if not validate_port(src_port):
        validation_errors.append(f"Invalid source port: {src_port}")
    if not validate_port(dst_port):
        validation_errors.append(f"Invalid destination port: {dst_port}")

    # 3. Protocol Validation
    proto = str(raw_flow.get("protocol", "TCP")).strip().upper()
    if not validate_protocol(proto):
        validation_errors.append(f"Unsupported or invalid protocol: {proto}")

    # 4. Safe Numerical Parsing with Defaults
    def safe_int(val: Any, default: int = 0) -> int:
        try:
            return max(0, int(val))
        except (TypeError, ValueError):
            return default

    def safe_float(val: Any, default: float = 0.0) -> float:
        try:
            v = float(val)
            return default if (math.isnan(v) or math.isinf(v)) else max(0.0, v)
        except (TypeError, ValueError):
            return default

    packet_count = safe_int(raw_flow.get("packet_count", 0))
    byte_count = safe_int(raw_flow.get("byte_count", 0))

    raw_duration = raw_flow.get("duration_seconds", raw_flow.get("duration", 0.0))
    duration = safe_float(raw_duration, default=0.0)

    connection_count = safe_int(raw_flow.get("connection_count", 1))
    failed_connection_count = safe_int(raw_flow.get("failed_connection_count", 0))
    syn_count = safe_int(raw_flow.get("syn_count", 0))
    rst_count = safe_int(raw_flow.get("rst_count", 0))

    # Multi-entity aggregations (if flow is aggregated or standalone)
    unique_dst_ports = safe_int(raw_flow.get("unique_destination_ports", 1))
    unique_dst_ips = safe_int(raw_flow.get("unique_destination_ips", 1))

    # 5. Prevent Zero Division for Rates & Ratios
    effective_duration = max(duration, 0.001)

    bytes_per_second = round(byte_count / effective_duration, 2)
    packets_per_second = round(packet_count / effective_duration, 2)
    connection_rate = round(connection_count / effective_duration, 2)

    avg_packet_size = round(byte_count / max(packet_count, 1), 2)
    failure_ratio = round(failed_connection_count / max(connection_count, 1), 4)
    failure_ratio = min(1.0, failure_ratio)

    syn_ratio = round(syn_count / max(packet_count, 1), 4)
    syn_ratio = min(1.0, syn_ratio)

    is_valid = len(validation_errors) == 0

    return {
        "flow_id": raw_flow.get("flow_id", "FLOW-UNKNOWN"),
        "timestamp": raw_flow.get("timestamp", ""),
        "source_ip": src_ip,
        "destination_ip": dst_ip,
        "source_port": safe_int(src_port),
        "destination_port": safe_int(dst_port),
        "protocol": proto,
        "packet_count": packet_count,
        "byte_count": byte_count,
        "duration": duration,
        "bytes_per_second": bytes_per_second,
        "packets_per_second": packets_per_second,
        "average_packet_size": avg_packet_size,
        "connection_count": connection_count,
        "failed_connection_count": failed_connection_count,
        "failure_ratio": failure_ratio,
        "syn_count": syn_count,
        "rst_count": rst_count,
        "syn_ratio": syn_ratio,
        "unique_destination_ports": unique_dst_ports,
        "unique_destination_ips": unique_dst_ips,
        "connection_rate": connection_rate,
        "is_valid": is_valid,
        "validation_errors": validation_errors,
    }
