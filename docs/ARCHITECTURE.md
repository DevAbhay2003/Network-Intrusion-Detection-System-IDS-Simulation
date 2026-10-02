# System Architecture & Technical Design

## Network Intrusion Detection System (IDS) Simulation

This document outlines the architectural blueprints, data flow pipelines, defensive design decisions, and database schemas implemented in this Network Intrusion Detection System simulation.

---

## 1. High-Level System Architecture

```text
┌────────────────────────────────────────────────────────┐
│             Synthetic Flow Record Sources              │
│  - Offline Dataset Generator (data/network_traffic.csv)│
│  - Real-Time Live Traffic Simulator (CLI / Web Daemon) │
└──────────────────────────┬─────────────────────────────┘
                           │ Network Flow JSON Event
                           ▼
┌────────────────────────────────────────────────────────┐
│                   IDS Ingestion Layer                  │
│  - Input Sanitation & IP/Port/Protocol Validation      │
│  - RFC 5737 Documentation Network Scope Enforcement    │
└──────────────────────────┬─────────────────────────────┘
                           │ Sanitized Flow Object
                           ▼
┌────────────────────────────────────────────────────────┐
│            Network Feature Extraction Engine           │
│  - Throughput Rates: Bytes/Sec, Packets/Sec            │
│  - Behavioral Ratios: Failure Ratio, SYN Ratio         │
│  - Volumetric Aggregations & Zero-Division Shields     │
└──────────────────────────┬─────────────────────────────┘
                           │ 15 Extracted Defensive Features
                           ▼
┌────────────────────────────────────────────────────────┐
│          Multi-Vector Hybrid Detection Engines         │
│  ┌─────────────────┐ ┌────────────────┐ ┌────────────┐ │
│  │ Signature Engine│ │Anomaly Detector│ │ ML Predict │ │
│  │ (IDS-001 - 006) │ │ (Z-Score & IQR)│ │  (RF / IF) │ │
│  └────────┬────────┘ └───────┬────────┘ └──────┬─────┘ │
└───────────┼──────────────────┼─────────────────┼───────┘
            │ Rule Risk        │ Anomaly Score   │ ML Prob
            └──────────────────┼─────────────────┘
                               ▼
┌────────────────────────────────────────────────────────┐
│              Hybrid Risk Scoring Engine                │
│  - Dynamic Weight Calibration (40% Rule/30% Anom/30% ML)│
│  - Defensive Severity Override Floors                  │
│  - Standardized Triage Tier (0-100 Score)              │
└──────────────────────────┬─────────────────────────────┘
                           │ Classified Security Event
                           ▼
┌────────────────────────────────────────────────────────┐
│               Security Alert Engine                    │
│  - Structured Alert Generation (ALT-xxxxx)             │
│  - Severity Assignment (INFO, LOW, MEDIUM, HIGH, CRIT) │
│  - Automated SOP Investigation Recommendations         │
└──────────────────────────┬─────────────────────────────┘
                           │ Actionable Security Alerts
                           ▼
┌────────────────────────────────────────────────────────┐
│             Alert Correlation Engine                   │
│  - Source IP & Alert Family Grouping                   │
│  - 60-Second Sliding Time-Window Clustering            │
│  - Security Incident Aggregation (INC-xxxx)            │
└──────────────────────────┬─────────────────────────────┘
                           │
             ┌─────────────┴─────────────┐
             ▼                           ▼
┌─────────────────────────┐ ┌─────────────────────────┐
│     SQLite Database     │ │   REST API & Web UI     │
│  - Flows, Alerts, Rules │ │  - Real-Time SOC Console│
│  - Analyst Audit Notes  │ │  - Interactive Charts   │
└─────────────────────────┘ └─────────────────────────┘
```

---

## 2. Pipeline Execution Stages

### Stage 1: Safe Flow Generation
All network telemetry originates from mathematical model distributions or RFC 5737 reserved documentation ranges (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`). No physical packets touch public networks.

### Stage 2: Feature Engineering & Defensive Sanitization
Input flows undergo type-safety validation via `ids.feature_extractor.extract_network_features`:
- Strict IPv4/IPv6 address parsing via `ipaddress`
- Port range assertions (`1 <= port <= 65535`)
- Protocol whitelist filtering (`TCP`, `UDP`, `ICMP`)
- Mathematical zero-division guards: `max(duration, 0.001)` prevents division errors on sub-millisecond flows.

### Stage 3: Tri-Vector Threat Evaluation
1. **Signature Engine (`ids.rule_engine.RuleEngine`)**: Evaluates deterministic conditions against operational baselines (e.g., connection rate > 25/sec, failed count >= 5 with failure ratio >= 0.50).
2. **Statistical Anomaly Engine (`ids.anomaly_detector.AnomalyDetector`)**: Compares traffic characteristics against Gaussian (Z-score) and non-parametric (Interquartile Range) baselines.
3. **Machine Learning Model (`ml.predict.MLPredictor`)**: Executes inference using a scikit-learn Random Forest classifier trained on 6,000 synthetic records, outputting a calibrated threat probability.

### Stage 4: Risk Scoring & Alert Generation
The hybrid risk engine calculates a unified score (0–100):
$$\text{Risk Score} = (0.40 \times \text{Rule Risk}) + (0.30 \times \text{Anomaly Score}) + (0.30 \times \text{ML Probability})$$
Events scoring $\ge 40.0$ generate structured SOC alerts complete with tactical investigation playbooks.

### Stage 5: Alert Correlation
The correlation engine groups repeated alerts from the same source host and alert category occurring within a 60-second window, consolidating them into an aggregated Incident entity to prevent analyst notification fatigue.

---

## 3. Database Schema Design

The relational SQLite schema enforces data integrity across 5 core entities:

```text
┌───────────────────────────┐         1:N         ┌───────────────────────────┐
│       network_flows       │────────────────────<│          alerts           │
├───────────────────────────┤                     ├───────────────────────────┤
│ PK  id                    │                     │ PK  id                    │
│ UK  flow_id               │                     │ UK  alert_id              │
│     timestamp             │                     │ FK  flow_id               │
│     source_ip             │                     │     rule_id               │
│     destination_ip        │                     │     alert_type            │
│     source_port           │                     │     severity              │
│     destination_port      │                     │     risk_score            │
│     protocol              │                     │     status                │
│     packet_count          │                     │     created_at            │
│     byte_count            │                     │     source_ip             │
│     duration              │                     │     destination_ip        │
│     risk_score            │                     └─────────────┬─────────────┘
│     classification        │                                   │ 1:N
│     scenario_type         │                                   ▼
└─────────────┬─────────────┘                     ┌───────────────────────────┐
              │ 1:N                               │      incident_notes       │
              ▼                                   ├───────────────────────────┤
┌───────────────────────────┐                     │ PK  note_id               │
│       model_results       │                     │ FK  alert_id              │
├───────────────────────────┤                     │     analyst_name          │
│ PK  result_id             │                     │     note                  │
│ FK  flow_id               │                     │     created_at            │
│     model_name            │                     └───────────────────────────┘
│     prediction            │
│     score                 │                     ┌───────────────────────────┐
│     created_at            │                     │           rules           │
└───────────────────────────┘                     ├───────────────────────────┤
                                                  │ PK  id                    │
                                                  │ UK  rule_id               │
                                                  │     rule_name             │
                                                  │     description           │
                                                  │     severity              │
                                                  │     threshold (JSON)      │
                                                  │     enabled (Boolean)     │
                                                  └───────────────────────────┘
```
