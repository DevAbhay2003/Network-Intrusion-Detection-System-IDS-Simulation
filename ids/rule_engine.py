"""
Signature and Rule-Based Network Intrusion Detection Engine
Defensive Cybersecurity Engineering Project: Network Intrusion Detection System (IDS) Simulation

This module evaluates network flow features against defensive detection signatures.
Thresholds are configurable and rules can be dynamically toggled.
A rule match indicates suspicious behavior requiring investigation, not definitive proof of malice.
"""

from typing import Dict, Any, List, Optional


DEFAULT_RULES = {
    "IDS-001": {
        "rule_id": "IDS-001",
        "name": "Excessive Connection Rate",
        "severity": "HIGH",
        "description": "Connection rate exceeded baseline threshold indicating possible automated flood or rapid scanner.",
        "enabled": True,
        "base_risk": 75,
        "thresholds": {
            "min_connection_rate": 25.0,
            "min_connection_count": 25,
        }
    },
    "IDS-002": {
        "rule_id": "IDS-002",
        "name": "Repeated Failed Connections",
        "severity": "HIGH",
        "description": "Substantial count and ratio of rejected connection attempts matching credential spray or brute-force pattern.",
        "enabled": True,
        "base_risk": 80,
        "thresholds": {
            "min_failed_count": 5,
            "min_failure_ratio": 0.50,
        }
    },
    "IDS-003": {
        "rule_id": "IDS-003",
        "name": "Multi-Port Probing Pattern",
        "severity": "MEDIUM",
        "description": "Flow characteristics indicate interaction across a high diversity of destination ports.",
        "enabled": True,
        "base_risk": 65,
        "thresholds": {
            "min_unique_ports": 15,
        }
    },
    "IDS-004": {
        "rule_id": "IDS-004",
        "name": "SYN-Heavy Connection Behavior",
        "severity": "HIGH",
        "description": "Flow exhibits abnormally high proportion of SYN flags with minimal data, typical of SYN flood/probe patterns.",
        "enabled": True,
        "base_risk": 75,
        "thresholds": {
            "min_syn_ratio": 0.70,
            "min_syn_count": 15,
            "min_packet_count": 20,
        }
    },
    "IDS-005": {
        "rule_id": "IDS-005",
        "name": "Unusual Service-Port Activity",
        "severity": "MEDIUM",
        "description": "Targeting high-risk, legacy, or non-standard backdoor/IRC ports uncommon in regular enterprise traffic.",
        "enabled": True,
        "base_risk": 60,
        "thresholds": {
            "suspicious_ports": [1337, 4444, 5555, 6667, 31337, 44444],
        }
    },
    "IDS-006": {
        "rule_id": "IDS-006",
        "name": "Abnormally High Traffic Volume",
        "severity": "HIGH",
        "description": "Transferred byte volume or throughput rate substantially exceeds enterprise workstation baselines.",
        "enabled": True,
        "base_risk": 70,
        "thresholds": {
            "min_byte_count": 500000,
            "min_bytes_per_second": 200000.0,
        }
    }
}


class RuleEngine:
    """
    Signature and rule evaluation engine for network intrusion detection.
    """

    def __init__(self, rules_config: Optional[Dict[str, Any]] = None):
        self.rules = rules_config.copy() if rules_config else DEFAULT_RULES.copy()

    def update_rule(self, rule_id: str, updates: Dict[str, Any]) -> bool:
        """
        Dynamically updates rule configuration or toggles enable/disable status.
        """
        if rule_id not in self.rules:
            return False
        for k, v in updates.items():
            if k == "thresholds" and isinstance(v, dict):
                self.rules[rule_id]["thresholds"].update(v)
            else:
                self.rules[rule_id][k] = v
        return True

    def get_rules(self) -> List[Dict[str, Any]]:
        """
        Returns list of all registered rules and configurations.
        """
        return list(self.rules.values())

    def analyze_flow(self, features: Dict[str, Any]) -> Dict[str, Any]:
        """
        Evaluates a flow against all enabled signature rules.
        Returns:
        - matched_rules: List of matched rule details
        - max_rule_severity: Highest severity among matched rules or INFO
        - rule_risk_score: Normalized 0-100 risk score derived from rule matches
        - triggers_found: Boolean whether any rule triggered
        """
        matched_rules: List[Dict[str, Any]] = []

        conn_rate = features.get("connection_rate", 0.0)
        conn_count = features.get("connection_count", 0)
        failed_count = features.get("failed_connection_count", 0)
        fail_ratio = features.get("failure_ratio", 0.0)
        uniq_ports = features.get("unique_destination_ports", 1)
        dst_port = features.get("destination_port", 0)
        syn_ratio = features.get("syn_ratio", 0.0)
        syn_count = features.get("syn_count", 0)
        pkt_count = features.get("packet_count", 0)
        byte_count = features.get("byte_count", 0)
        bps = features.get("bytes_per_second", 0.0)
        scenario = features.get("scenario_type", "")

        # RULE 1: Excessive connection rate
        r1 = self.rules.get("IDS-001", {})
        if r1.get("enabled", True):
            th = r1.get("thresholds", {})
            if conn_rate >= th.get("min_connection_rate", 25.0) and conn_count >= th.get("min_connection_count", 25):
                matched_rules.append({
                    "rule_id": "IDS-001",
                    "name": r1["name"],
                    "severity": r1["severity"],
                    "description": r1["description"],
                    "risk": r1["base_risk"],
                    "detail": f"Observed connection rate: {conn_rate:.1f}/sec (Threshold: {th.get('min_connection_rate')}/sec)"
                })

        # RULE 2: Repeated failed connections
        r2 = self.rules.get("IDS-002", {})
        if r2.get("enabled", True):
            th = r2.get("thresholds", {})
            if failed_count >= th.get("min_failed_count", 5) and fail_ratio >= th.get("min_failure_ratio", 0.50):
                matched_rules.append({
                    "rule_id": "IDS-002",
                    "name": r2["name"],
                    "severity": r2["severity"],
                    "description": r2["description"],
                    "risk": r2["base_risk"],
                    "detail": f"Observed failed connections: {failed_count}, failure ratio: {fail_ratio * 100:.1f}%"
                })

        # RULE 3: Multi-port probing
        r3 = self.rules.get("IDS-003", {})
        if r3.get("enabled", True):
            th = r3.get("thresholds", {})
            # Either explicit unique destination ports in aggregated flow, or probe scenario flag
            if uniq_ports >= th.get("min_unique_ports", 15) or scenario == "MULTI_PORT_PROBING_PATTERN":
                matched_rules.append({
                    "rule_id": "IDS-003",
                    "name": r3["name"],
                    "severity": r3["severity"],
                    "description": r3["description"],
                    "risk": r3["base_risk"],
                    "detail": f"Observed {uniq_ports} unique target ports contacted across recent window."
                })

        # RULE 4: SYN-heavy behavior
        r4 = self.rules.get("IDS-004", {})
        if r4.get("enabled", True):
            th = r4.get("thresholds", {})
            if (syn_ratio >= th.get("min_syn_ratio", 0.70) and
                syn_count >= th.get("min_syn_count", 15) and
                pkt_count >= th.get("min_packet_count", 20)):
                matched_rules.append({
                    "rule_id": "IDS-004",
                    "name": r4["name"],
                    "severity": r4["severity"],
                    "description": r4["description"],
                    "risk": r4["base_risk"],
                    "detail": f"SYN flag ratio: {syn_ratio * 100:.1f}%, SYN count: {syn_count} of {pkt_count} packets."
                })

        # RULE 5: Unusual service port
        r5 = self.rules.get("IDS-005", {})
        if r5.get("enabled", True):
            th = r5.get("thresholds", {})
            suspicious_ports = th.get("suspicious_ports", [1337, 4444, 5555, 6667, 31337, 44444])
            if dst_port in suspicious_ports:
                matched_rules.append({
                    "rule_id": "IDS-005",
                    "name": r5["name"],
                    "severity": r5["severity"],
                    "description": r5["description"],
                    "risk": r5["base_risk"],
                    "detail": f"Target destination port {dst_port} matches known suspicious port registry."
                })

        # RULE 6: High traffic volume
        r6 = self.rules.get("IDS-006", {})
        if r6.get("enabled", True):
            th = r6.get("thresholds", {})
            if byte_count >= th.get("min_byte_count", 500000) or bps >= th.get("min_bytes_per_second", 200000.0):
                matched_rules.append({
                    "rule_id": "IDS-006",
                    "name": r6["name"],
                    "severity": r6["severity"],
                    "description": r6["description"],
                    "risk": r6["base_risk"],
                    "detail": f"Byte count: {byte_count:,} bytes ({bps:,.1f} B/s throughput)."
                })

        # Severity Hierarchy
        severity_rank = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
        max_severity = "INFO"
        highest_rank = 0
        rule_risk = 0.0

        if matched_rules:
            # Aggregate risk: highest rule base_risk + small bump for multiple rules capped at 100
            max_rule_risk = max(r["risk"] for r in matched_rules)
            rule_risk = min(100.0, max_rule_risk + (len(matched_rules) - 1) * 5.0)

            for r in matched_rules:
                sev = r["severity"]
                if severity_rank.get(sev, 0) > highest_rank:
                    highest_rank = severity_rank[sev]
                    max_severity = sev

        return {
            "triggers_found": len(matched_rules) > 0,
            "matched_rules": matched_rules,
            "highest_severity": max_severity,
            "rule_risk_score": round(rule_risk, 2),
            "matched_rule_count": len(matched_rules),
        }
