"""
Alert Generation Engine
Defensive Cybersecurity Engineering Project: Network Intrusion Detection System (IDS) Simulation

This module handles the transformation of actionable risk events into structured
SOC alerts formatted with standard severity rankings, triage recommendations,
and status workflows (NEW, INVESTIGATING, RESOLVED, FALSE_POSITIVE).
"""

import uuid
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional


SEVERITY_LEVELS = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
VALID_STATUSES = ["NEW", "INVESTIGATING", "RESOLVED", "FALSE_POSITIVE"]


def get_recommended_investigation_steps(alert_type: str, severity: str) -> List[str]:
    """
    Returns defensive standard operating procedure (SOP) steps for Tier-1/Tier-2 SOC analysts.
    """
    common_steps = [
        "Review historical flow records for this source IP in the preceding 24 hours.",
        "Check local DNS and DHCP logs to identify the internal asset or hostname.",
        "Verify if the destination IP is an authorized internal server or external CDN/cloud endpoint.",
    ]

    type_specific = {
        "Excessive Connection Rate": [
            "Check host process telemetry (Sysmon/EDR) for automated batch scripts, curl loops, or runaway processes.",
            "Verify whether user was performing scheduled load testing or bulk operations.",
            "Examine firewall logs for perimeter connection throttling or dropped packets.",
        ],
        "Repeated Failed Connections": [
            "Inspect system authentication logs (e.g., Linux /var/log/auth.log or Windows Event ID 4625).",
            "Determine if repeated failures target a single username (brute-force) or multiple users (password spraying).",
            "Verify if service account passwords were recently rotated without updating background services.",
        ],
        "Multi-Port Probing Pattern": [
            "Review firewall deny logs across adjacent IP addresses to detect vertical or horizontal sweep behavior.",
            "Confirm whether authorized vulnerability scanning tools (Nessus, Qualys) were scheduled.",
            "Temporarily isolate or quarantine the offending workstation if unauthorized probing continues.",
        ],
        "SYN-Heavy Connection Behavior": [
            "Verify network segment health and check whether half-open connection queues are filling up.",
            "Review SYN-cookie activation stats on destination server or load balancer.",
            "Check whether host network interface or hypervisor shows packet loss or reset storms.",
        ],
        "Unusual Service-Port Activity": [
            "Review endpoint netstat / ss output to identify the specific binary listening or initiating the connection.",
            "Submit the listening binary hash to internal threat intelligence or safe sandbox for verification.",
            "Check whether the unusual port was provisioned for legitimate internal custom software.",
        ],
        "Abnormally High Traffic Volume": [
            "Verify whether legitimate backup synchronization, database replication, or OS updates are underway.",
            "Analyze data transfer direction (inbound ingress vs outbound egress).",
            "Cross-reference data loss prevention (DLP) alerts for potential exfiltration indicators.",
        ]
    }

    specific = type_specific.get(alert_type, [
        "Compare flow features against baseline statistics for that asset profile.",
        "Assess if new services or applications were recently deployed.",
    ])

    return common_steps + specific


class AlertEngine:
    """
    Generates structured security alerts from analyzed flows and risk calculations.
    """

    def __init__(self, alert_id_prefix: str = "ALT-"):
        self.prefix = alert_id_prefix
        self._counter = 10000

    def generate_alert_id(self) -> str:
        """Generates an incremental human-readable SOC alert identifier."""
        self._counter += 1
        return f"{self.prefix}{self._counter}"

    def evaluate_and_generate_alert(
        self,
        features: Dict[str, Any],
        rule_result: Dict[str, Any],
        anomaly_result: Dict[str, Any],
        risk_result: Dict[str, Any],
        ml_result: Optional[Dict[str, Any]] = None
    ) -> Optional[Dict[str, Any]]:
        """
        Generates an alert if the flow meets alerting criteria (risk_score >= 40 or rule match).
        Returns None if the flow is classified as benign normal traffic.
        """
        final_risk = risk_result.get("final_risk_score", 0.0)
        rules_matched = rule_result.get("matched_rules", [])
        is_anomalous = anomaly_result.get("is_anomalous", False)

        # Trigger condition: Actionable risk or signature hit or high anomaly
        if final_risk < 40.0 and len(rules_matched) == 0 and not is_anomalous:
            return None

        # Determine Primary Alert Title and Primary Rule
        if rules_matched:
            primary_rule = rules_matched[0]
            alert_type = primary_rule.get("name", "Signature Detection")
            rule_id = primary_rule.get("rule_id", "IDS-RULE")
            description = primary_rule.get("description", "Signature rule triggered.")
            severity = primary_rule.get("severity", "MEDIUM")
        elif is_anomalous:
            alert_type = "Statistical Behavioral Anomaly"
            rule_id = "ANOM-001"
            description = anomaly_result.get("explanation", "Substantial statistical variance detected.")
            severity = "HIGH" if final_risk >= 70.0 else "MEDIUM"
        else:
            alert_type = "Elevated Composite Network Risk"
            rule_id = "HYBRID-001"
            description = "Multi-factor threat detection score exceeded baseline."
            severity = "LOW"

        # Severity escalation based on final risk score
        if final_risk >= 80.0:
            severity = "CRITICAL"
        elif final_risk >= 65.0 and severity in ["INFO", "LOW", "MEDIUM"]:
            severity = "HIGH"

        now_str = datetime.now(timezone.utc).isoformat()
        alert_id = self.generate_alert_id()

        recommended_actions = get_recommended_investigation_steps(alert_type, severity)

        alert_record = {
            "alert_id": alert_id,
            "flow_id": features.get("flow_id", "FLOW-UNKNOWN"),
            "timestamp": features.get("timestamp", now_str),
            "created_at": now_str,
            "source_ip": features.get("source_ip", "0.0.0.0"),
            "destination_ip": features.get("destination_ip", "0.0.0.0"),
            "source_port": features.get("source_port", 0),
            "destination_port": features.get("destination_port", 0),
            "protocol": features.get("protocol", "TCP"),
            "rule_id": rule_id,
            "alert_type": alert_type,
            "severity": severity,
            "risk_score": final_risk,
            "classification": risk_result.get("classification", "SUSPICIOUS"),
            "description": description,
            "status": "NEW",
            "matched_rules": [r["rule_id"] for r in rules_matched],
            "anomaly_score": anomaly_result.get("anomaly_score", 0.0),
            "ml_probability": ml_result.get("suspicious_probability") if ml_result else None,
            "flow_metrics": {
                "packet_count": features.get("packet_count", 0),
                "byte_count": features.get("byte_count", 0),
                "duration": features.get("duration", 0.0),
                "connection_rate": features.get("connection_rate", 0.0),
                "failed_connection_count": features.get("failed_connection_count", 0),
                "failure_ratio": features.get("failure_ratio", 0.0),
                "syn_ratio": features.get("syn_ratio", 0.0),
            },
            "investigation_steps": recommended_actions,
            "analyst_notes": [],
        }

        return alert_record
