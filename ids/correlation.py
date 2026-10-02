"""
Alert Correlation Engine
Defensive Cybersecurity Engineering Project: Network Intrusion Detection System (IDS) Simulation

This module groups related alerts into coherent Security Incidents to prevent
SOC analyst alert fatigue. Groups alerts by Source IP, Alert Type/Family, and Time Window.

Conceptual Hierarchy:
- Security Event: A raw observation or recorded network flow record.
- Security Alert: A threshold-breaching or signature-matching detection requiring attention.
- Security Incident: A correlated cluster of related alerts indicating a sustained threat pattern.
"""

from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
import dateutil.parser


class AlertCorrelationEngine:
    """
    Correlates individual alerts into consolidated SOC security incidents.
    """

    def __init__(self, time_window_seconds: int = 60):
        self.time_window_seconds = time_window_seconds
        self.incidents: Dict[str, Dict[str, Any]] = {}
        self._incident_counter = 5000

    def _parse_time(self, time_str: str) -> datetime:
        """Parses ISO timestamp string safely into UTC datetime."""
        try:
            dt = dateutil.parser.isoparse(time_str)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
        except Exception:
            return datetime.now(timezone.utc)

    def correlate_alert(self, alert: Dict[str, Any]) -> Dict[str, Any]:
        """
        Correlates a single incoming alert into an active incident or creates a new incident.
        Returns the associated Incident summary.
        """
        src_ip = alert.get("source_ip", "0.0.0.0")
        alert_type = alert.get("alert_type", "GENERIC_ALERT")
        alert_time = self._parse_time(alert.get("timestamp", datetime.now(timezone.utc).isoformat()))

        # Correlation key: source IP + alert type
        key = f"{src_ip}::{alert_type}"

        if key in self.incidents:
            incident = self.incidents[key]
            last_seen = self._parse_time(incident["last_seen"])
            diff_seconds = abs((alert_time - last_seen).total_seconds())

            if diff_seconds <= self.time_window_seconds:
                # Add alert to existing active incident
                incident["alert_count"] += 1
                incident["alert_ids"].append(alert["alert_id"])
                incident["flow_ids"].append(alert.get("flow_id", ""))
                incident["last_seen"] = alert_time.isoformat()
                incident["max_risk_score"] = max(incident["max_risk_score"], alert.get("risk_score", 0.0))

                # Escalate severity if repeated
                if incident["alert_count"] >= 5 and incident["severity"] != "CRITICAL":
                    incident["severity"] = "HIGH"
                if incident["alert_count"] >= 15:
                    incident["severity"] = "CRITICAL"

                return incident

        # Otherwise, initiate a new incident cluster
        self._incident_counter += 1
        incident_id = f"INC-{self._incident_counter}"

        new_incident = {
            "incident_id": incident_id,
            "correlation_key": key,
            "source_ip": src_ip,
            "alert_type": alert_type,
            "first_seen": alert_time.isoformat(),
            "last_seen": alert_time.isoformat(),
            "alert_count": 1,
            "alert_ids": [alert["alert_id"]],
            "flow_ids": [alert.get("flow_id", "")],
            "severity": alert.get("severity", "MEDIUM"),
            "max_risk_score": alert.get("risk_score", 0.0),
            "status": "OPEN",
            "summary": f"Aggregated {alert_type} activity originating from {src_ip}."
        }

        self.incidents[key] = new_incident
        return new_incident

    def correlate_alerts(self, alerts: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Batch correlates a list of alerts and returns the list of consolidated incidents.
        """
        # Sort chronologically
        sorted_alerts = sorted(
            alerts,
            key=lambda a: self._parse_time(a.get("timestamp", datetime.now(timezone.utc).isoformat()))
        )

        for alert in sorted_alerts:
            self.correlate_alert(alert)

        return list(self.incidents.values())

    def get_all_incidents(self) -> List[Dict[str, Any]]:
        """Returns all correlated incidents."""
        return list(self.incidents.values())
