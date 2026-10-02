# Network Intrusion Detection System (IDS) Simulation

[![Python Version](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.110%2B-009688.svg)](https://fastapi.tiangolo.com/)
[![Tests](https://img.shields.io/badge/Tests-30%20Passed%20(100%25)-success.svg)](tests/test_ids.py)
[![Security Focus](https://img.shields.io/badge/Defense-Purely%20Defensive-emerald.svg)](#ethical-disclaimer)
[![MITRE ATT&CK](https://img.shields.io/badge/Mapping-MITRE%20ATT%26CK-orange.svg)](docs/MITRE_ATTACK_MAPPING.md)

An industry-oriented, defensive **Network Intrusion Detection System (IDS)** simulation featuring safe synthetic traffic modeling, tri-vector hybrid detection (signature matching, statistical anomalies, and machine learning), dynamic risk scoring, alert correlation, and an interactive Security Operations Center (SOC) investigation dashboard.

---

## Table of Contents
- [Overview](#overview)
- [Problem Statement](#problem-statement)
- [Objectives](#objectives)
- [Cybersecurity Relevance](#cybersecurity-relevance)
- [Core IDS Concepts](#core-ids-concepts)
- [System Architecture](#system-architecture)
- [Technology Stack](#technology-stack)
- [Synthetic Dataset](#synthetic-dataset)
- [Traffic Simulator](#traffic-simulator)
- [Feature Engineering](#feature-engineering)
- [Signature-Based Detection](#signature-based-detection)
- [Statistical Anomaly Detection](#statistical-anomaly-detection)
- [Machine Learning IDS](#machine-learning-ids)
- [Hybrid Detection Architecture](#hybrid-detection-architecture)
- [Risk Scoring & Triage](#risk-scoring--triage)
- [Alert Generation Engine](#alert-generation-engine)
- [Alert Correlation Engine](#alert-correlation-engine)
- [Interactive SOC Dashboard](#interactive-soc-dashboard)
- [Incident Investigation & Triage Workflow](#incident-investigation--triage-workflow)
- [REST API Reference](#rest-api-reference)
- [Installation Guide](#installation-guide)
- [Usage & Execution Instructions](#usage--execution-instructions)
- [Automated Testing Strategy](#automated-testing-strategy)
- [Security & Privacy Controls](#security--privacy-controls)
- [Experimental Results & Evaluation](#experimental-results--evaluation)
- [False Positives vs. False Negatives](#false-positives-vs-false-negatives)
- [Limitations](#limitations)
- [Future Defensive Improvements](#future-defensive-improvements)
- [Visual Screenshots & Proof Catalog](#visual-screenshots--proof-catalog)
- [Learning Outcomes](#learning-outcomes)
- [Ethical Disclaimer](#ethical-disclaimer)
- [Author & Acknowledgments](#author--acknowledgments)

---

## Overview

The **Network Intrusion Detection System (IDS) Simulation** is a comprehensive defensive cybersecurity engineering project designed to replicate the operational mechanics of an enterprise security monitoring platform. Operating entirely without specialized physical networking hardware, the system accepts or generates synthetic network flow records, evaluates each flow against multiple detection layers, assigns calibrated risk scores, aggregates alerts into actionable security incidents, and presents a real-time command console tailored for SOC Analysts and Defensive Engineers.

---

## Problem Statement

Educational and entry-level cybersecurity learners face significant hurdles when seeking practical, demonstrable experience with Intrusion Detection Systems:
1. **Infrastructure Barriers**: Enterprise appliances (e.g. Cisco Firepower, Palo Alto Networks) and dedicated packet-capture taps are inaccessible to independent students.
2. **Legal & Ethical Risks**: Capturing live campus/corporate networks or running active scans against external endpoints violates privacy policies, compliance mandates, and computer fraud statutes.
3. **Data Quality**: Public capture dumps (like KDD Cup 99) are heavily outdated and do not reflect contemporary flow structures or SOC workflows.

**Solution**: This project delivers an isolated, self-contained, and mathematically grounded **virtual flow simulation**. Network telemetry is modeled as structured flow data utilizing reserved documentation addresses (RFC 5737). No hostile packets are generated or transmitted, making the platform 100% safe, legal, and executable on any standard personal computer.

---

## Objectives

- **Generate Safe Telemetry**: Create balanced datasets ($\ge 5,000$ flow records) representing routine enterprise protocols alongside safe representations of suspicious activity.
- **Engineer Defensive Features**: Derive 15 behavioral and volumetric metrics with mathematical division-by-zero safeguards and strict input validation.
- **Implement Multi-Vector Detection**:
  - Deterministic signature rules (`IDS-001` through `IDS-006`).
  - Statistical anomaly detection (Z-Score and Interquartile Range outlier modeling).
  - Supervised and unsupervised machine learning models (Random Forest, Logistic Regression, Isolation Forest).
- **Calculate Calibrated Risk**: Combine multi-engine outputs into a normalized 0–100 risk score mapped to standard SOC priority tiers.
- **Prevent Alert Fatigue**: Implement an alert correlation engine grouping repetitive detections into coherent security incidents.
- **Deliver a SOC Dashboard**: Build a real-time web console with 8 interactive charts, quick scenario injection, rule tuning, and incident note tracking.
- **Validate through Testing**: Maintain an automated test suite containing 30 test scenarios with 100% pass verification.

---

## Cybersecurity Relevance

Intrusion detection is the bedrock of defensive telemetry across modern enterprises:
- **Security Operations Centers (SOC)**: Tier-1 and Tier-2 analysts depend on IDS sensors to identify early-stage reconnaissance and active threats.
- **Banking & Financial Services**: Regulatory standards (PCI-DSS, GLBA) mandate continuous network traffic inspection to protect cardholder and financial data.
- **Cloud Infrastructure & Managed Security Service Providers (MSSPs)**: Cloud providers monitor virtual flow logs (e.g. AWS VPC Flow Logs) to isolate multi-tenant threats.

### Relevant Career Roles
- **SOC Analyst (Tier 1 / Tier 2)**: Queue triage, event enrichment, alert verification, and initial incident containment.
- **Network Security Engineer**: Signature tuning, sensor deployment, perimeter defense, and flow monitoring.
- **Threat Detection Engineer**: Rule creation, behavioral baselining, and detection gap analysis.
- **Incident Responder**: Forensic timeline reconstruction and post-compromise root-cause analysis.

---

## Core IDS Concepts

### What is an IDS?
An **Intrusion Detection System (IDS)** is a defensive technology that monitors network traffic or system events for signs of policy violations, unauthorized access, or malicious activity, raising notifications when threats are detected.

### Why Organizations Deploy IDS
Firewalls permit authorized traffic (e.g. inbound TCP port 443), but cannot distinguish whether an authorized session carries benign user traffic or automated exploitation attempts. An IDS provides internal visibility, helping organizations detect threats that have bypassed perimeter firewalls.

### Terminology Comparison

| Concept | Simple Explanation | Technical Explanation |
|---|---|---|
| **Network Packet** | A single letter inside an envelope. | A formatted data unit containing Layer 3/4 headers (IP, TCP/UDP) and payload data. |
| **Network Flow** | The entire conversation between two parties. | An aggregated sequence of packets sharing a common 5-tuple (Src IP, Dst IP, Src Port, Dst Port, Protocol). |
| **Security Event** | An observable occurrence on the network. | A recorded timestamped state change or transaction within an audit log or flow sensor. |
| **Security Alert** | A notification that something looks wrong. | A triggered event where flow characteristics exceed an operational threshold or match a known signature. |
| **Security Incident** | A confirmed threat requiring active intervention. | A correlated collection of alerts and evidence indicating an active threat to organizational assets. |

### IDS vs. IPS
- **IDS (Detection)**: Passively monitors network streams and generates alerts. It does not alter, delay, or drop packets.
- **IPS (Prevention)**: Placed inline within the network path; can actively drop packets, reset TCP sessions, or block IP addresses at firewall interfaces.
*This project simulates an IDS to focus on monitoring, analysis, detection engineering, and SOC analyst triage.*

### NIDS vs. HIDS
- **NIDS (Network IDS)**: Placed at strategic network boundaries to monitor traffic passing across multiple hosts.
- **HIDS (Host IDS)**: Installed on individual endpoints (e.g. OSSEC, Wazuh) to monitor local system calls, registry changes, and file integrity.

---

## System Architecture

```text
┌────────────────────────────────────────────────────────┐
│             Synthetic Flow Record Sources              │
│  - Offline Dataset Generator (data/network_traffic.csv)│
│  - Real-Time Live Traffic Simulator (CLI / Web Daemon) │
└──────────────────────────┬─────────────────────────────┘
                           │ Raw Flow Record
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
│  - Rates: Bytes/Sec, Packets/Sec, Connection Rate      │
│  - Ratios: Failure Ratio, SYN Ratio                    │
│  - Volumetric Aggregations & Zero-Division Safeguards  │
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

## Technology Stack

- **Backend**: Python 3.10+, FastAPI, Uvicorn, Pydantic v2
- **Data & Numerics**: Pandas, NumPy
- **Machine Learning**: Scikit-Learn (Random Forest, Logistic Regression, Isolation Forest), Joblib
- **Database & Persistence**: SQLite, SQLAlchemy 2.0
- **Frontend Dashboard**: HTML5, CSS3 (SOC Dark Cyber Theme), Vanilla JavaScript, Chart.js 4.4
- **Testing**: Pytest, FastAPI TestClient

---

## Synthetic Dataset

The synthetic dataset generator (`simulator/generate_dataset.py`) produces **6,000 flow records** stored in `data/network_traffic.csv`. All IP addresses are strictly chosen from RFC 5737 documentation blocks:
- `192.0.2.0/24` (TEST-NET-1)
- `198.51.100.0/24` (TEST-NET-2)
- `203.0.113.0/24` (TEST-NET-3)

### Dataset Schema
`flow_id`, `timestamp`, `source_ip`, `destination_ip`, `source_port`, `destination_port`, `protocol`, `packet_count`, `byte_count`, `duration_seconds`, `connection_count`, `failed_connection_count`, `syn_count`, `rst_count`, `average_packet_size`, `label`, `scenario_type`.

### Scenario Composition
- **NORMAL (70.4%)**: `NORMAL_WEB`, `NORMAL_DNS`, `NORMAL_SSH`, `NORMAL_EMAIL`, `NORMAL_DATABASE`
- **SUSPICIOUS (29.6%)**: `HIGH_CONNECTION_RATE`, `REPEATED_FAILED_CONNECTIONS`, `MULTI_PORT_PROBING_PATTERN`, `SYN_HEAVY_PATTERN`, `UNUSUAL_PORT_ACTIVITY`, `HIGH_TRAFFIC_VOLUME`

---

## Traffic Simulator

`simulator/traffic_simulator.py` generates continuous flow events representing real-time network activity.
- Generates data records only (does not transmit physical network packets).
- **Modes**:
  - `--mode normal`: 100% legitimate traffic matching operational baselines.
  - `--mode mixed`: Realistic distribution of normal traffic with intermittent synthetic threat patterns.
- **Speed**:
  - `--speed fast`: Emits a flow every ~0.8 seconds.
  - `--speed slow`: Emits a flow every ~2.5 seconds.

---

## Feature Engineering

Located in `ids/feature_extractor.py`, this module extracts 15 derived features from raw flow records:

| Feature Name | Type | Cybersecurity Relevance |
|---|---|---|
| `packet_count` | Integer | Total packets exchanged in session. |
| `byte_count` | Integer | Total data volume transferred. |
| `duration` | Float | Session lifespan in seconds. |
| `bytes_per_second` | Float | Bandwidth throughput rate (flags volumetric exfiltration). |
| `packets_per_second` | Float | Packet transmission frequency (flags rapid probing or flooding). |
| `average_packet_size` | Float | byte_count / packet_count (distinguishes probe packets from large file transfers). |
| `connection_count` | Integer | Total session connection attempts within time window. |
| `failed_connection_count`| Integer | Total rejected / reset attempts. |
| `failure_ratio` | Float | failed_count / connection_count (indicators of brute-force or scanner drops). |
| `syn_count` | Integer | TCP SYN packets initiating handshakes. |
| `rst_count` | Integer | TCP RST packets terminating rejected connections. |
| `syn_ratio` | Float | syn_count / packet_count (flags half-open SYN flood patterns). |
| `unique_destination_ports`| Integer | Count of distinct target ports (detects horizontal/vertical port sweeps). |
| `unique_destination_ips` | Integer | Count of distinct target hosts. |
| `connection_rate` | Float | connection_count / duration (connection attempt velocity). |

### Edge-Case Handling
- **Division by Zero**: Safeguarded with `max(duration, 0.001)` and `max(packet_count, 1)`.
- **IP Address Validation**: Validated using Python's `ipaddress` library.
- **Port Ranges**: Enforced within $1 \le \text{port} \le 65535$.
- **Protocol Whitelisting**: Restricted to `TCP`, `UDP`, and `ICMP`.

---

## Signature-Based Detection

Located in `ids/rule_engine.py`, the signature engine evaluates deterministic thresholds:

- **`IDS-001` - Excessive Connection Rate**: Triggered when `connection_rate >= 25.0` conn/sec and `connection_count >= 25`.
- **`IDS-002` - Repeated Failed Connections**: Triggered when `failed_connection_count >= 5` and `failure_ratio >= 0.50`.
- **`IDS-003` - Multi-Port Probing Pattern**: Triggered when `unique_destination_ports >= 15`.
- **`IDS-004` - SYN-Heavy Connection Behavior**: Triggered when `syn_ratio >= 0.70`, `syn_count >= 15`, and `packet_count >= 20`.
- **`IDS-005` - Unusual Service-Port Activity**: Triggered when destination port matches high-risk ports (`1337`, `4444`, `5555`, `6667`, `31337`, `44444`).
- **`IDS-006` - Abnormally High Traffic Volume**: Triggered when `byte_count >= 500,000` or `bytes_per_second >= 200,000.0`.

*Note: A rule match indicates suspicious behavior requiring investigation; it does not automatically prove malicious activity.*

---

## Statistical Anomaly Detection

Located in `ids/anomaly_detector.py`, the engine calculates statistical deviations from normal baselines:
1. **Z-Score Calculation**: Evaluates standard deviations from the historical mean:
   $$z = \max\left(0, \frac{x - \mu}{\sigma}\right)$$
2. **Interquartile Range (IQR) Outlier Bound**: Quantifies how far an observation exceeds the 75th percentile:
   $$\delta_{\text{IQR}} = \max\left(0, \frac{x - (Q_{75} + 1.5 \times \text{IQR})}{\text{IQR}}\right)$$
3. **Calibrated Anomaly Score**: Blends metric deviations and compresses into a normalized 0–100 scale using an exponential saturation curve:
   $$S_{\text{anom}} = 100 \times \left(1 - e^{-0.45 \times D_{\text{total}}}\right)$$

---

## Machine Learning IDS

Located in `ml/train_model.py` and `ml/predict.py`:
- **Supervised Models**:
  - **Random Forest**: Ensemble tree model capturing non-linear feature interactions.
  - **Logistic Regression**: Interpretable linear classifier establishing a baseline.
- **Unsupervised Model**:
  - **Isolation Forest**: Tree partitioning algorithm trained strictly on normal data to detect outliers without labels.

### Evaluation Metrics (Evaluated on 1,200 Held-Out Records)

| Model | Accuracy | Precision | Recall | F1 Score | Confusion Matrix [TN, FP / FN, TP] |
|---|---|---|---|---|---|
| **Random Forest** | **99.00%** | **99.71%** | **96.90%** | **98.29%** | `[[844, 1], [11, 344]]` |
| **Logistic Regression** | 96.50% | 100.00% | 88.17% | 93.71% | `[[845, 0], [42, 313]]` |
| **Isolation Forest** | 89.83% | 78.77% | 89.86% | 83.95% | `[[759, 86], [36, 319]]` |

*Accuracy alone is insufficient in cybersecurity because normal traffic heavily outnumbers intrusions. Recall and precision are critical to measuring threat detection rate and false-alarm burden.*

---

## Hybrid Detection Architecture

Relying on a single detection paradigm creates blind spots:
- **Signatures** fail against zero-day or modified patterns.
- **Anomalies** generate false alarms during benign operational spikes.
- **Machine Learning** requires periodic retraining to mitigate concept drift.

By combining all three, the **Hybrid IDS** provides defense-in-depth:
$$\text{Composite Score} = (0.40 \times \text{Rule Risk}) + (0.30 \times \text{Anomaly Score}) + (0.30 \times \text{ML Probability})$$
*(If ML is disabled, weights dynamically adjust to 60% Rule and 40% Anomaly).*

---

## Risk Scoring & Triage

Located in `ids/risk_engine.py`, the final 0–100 risk score maps directly to actionable SOC classifications:
- **0–20 (NORMAL)**: Routine traffic within baseline parameters.
- **21–40 (LOW RISK)**: Minor variance. Informational logging only.
- **41–60 (SUSPICIOUS)**: Detectable anomaly or rule hit. Queued for SOC review.
- **61–80 (HIGH RISK)**: High-confidence signature match. Active triage recommended.
- **81–100 (CRITICAL INVESTIGATION)**: Multi-vector intrusion indicators. Immediate containment required.

---

## Alert Generation Engine

Located in `ids/alert_engine.py`:
- Generates structured security alerts (`ALT-xxxxx`) when risk score $\ge 40.0$ or a signature triggers.
- Assigns severity: `INFO`, `LOW`, `MEDIUM`, `HIGH`, or `CRITICAL`.
- Automatically populates defensive **Standard Operating Procedure (SOP)** checklists tailored to the specific detection type.

---

## Alert Correlation Engine

Located in `ids/correlation.py`:
- Groups repetitive alerts originating from the same source IP and alert family within a **60-second sliding time window**.
- Prevents alert fatigue by aggregating individual alerts into a consolidated **Security Incident** (`INC-xxxxx`).
- Automatically escalates incident severity to `HIGH` upon 5 occurrences and `CRITICAL` upon 15 occurrences.

---

## Interactive SOC Dashboard

Hosted locally at `http://127.0.0.1:8000`:
- **Top Metric Cards**: Total Flows, Normal Traffic, Suspicious Traffic, Open Alerts, Critical Alerts, and Average Risk Score.
- **8 Interactive Charts**:
  1. Network Traffic Throughput Over Time (Packets vs. KB)
  2. Traffic Classification (Normal vs. Suspicious Doughnut)
  3. Alerts by Severity Level (INFO to CRITICAL)
  4. Top Triggered Alert Types (Horizontal Bar)
  5. Protocol Distribution (TCP, UDP, ICMP Pie)
  6. Destination Service Port Distribution
  7. Top Source IPs Generating Alerts
  8. Risk Score Distribution Across 5 Defense Tiers
- **Real-Time Simulation Control Bar**: Start/Stop continuous simulation, adjust speed, and inject specific test scenarios on demand.
- **Alert Triage Queue**: Search and filter alerts by severity, status, or IP address.

---

## Incident Investigation & Triage Workflow

Clicking **"Investigate"** on any alert launches the Event Investigation Dossier:
1. **Dossier Overview**: Displays Source/Destination IP, Ports, Protocol, Rule ID, Severity, and Composite Risk.
2. **Flow Telemetry**: Packet counts, byte volume, duration, and scenario metadata.
3. **Defensive SOP Checklist**: Tailored step-by-step guidance (e.g. check authentication logs, verify backup windows, inspect EDR telemetry).
4. **Lifecycle State Machine**: Update status:
   $$\text{NEW} \longrightarrow \text{INVESTIGATING} \longrightarrow \text{RESOLVED}\quad\text{or}\quad\text{FALSE\_POSITIVE}$$
5. **Analyst Notes & Audit Trail**: Append timestamped investigation findings and closure justifications.

---

## REST API Reference

The backend exposes a fully documented REST API (interactive Swagger documentation available at `/docs`):

| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/api/flows` | Ingests a raw flow and executes the complete IDS detection pipeline. |
| `GET` | `/api/flows` | Queries flow history with pagination and search filters. |
| `GET` | `/api/alerts` | Queries security alerts filtered by severity and status. |
| `GET` | `/api/alerts/{id}` | Retrieves full investigation dossier, SOP recommendations, and notes. |
| `PUT` | `/api/alerts/{id}/status` | Updates alert triage status (`NEW`, `INVESTIGATING`, `RESOLVED`, `FALSE_POSITIVE`). |
| `POST` | `/api/alerts/{id}/notes` | Appends an analyst note to the investigation audit trail. |
| `GET` | `/api/rules` | Retrieves all detection rules, thresholds, and operational status. |
| `PUT` | `/api/rules/{id}` | Updates rule thresholds or toggles enabled/disabled state. |
| `GET` | `/api/dashboard/stats` | High-level metrics for summary cards. |
| `POST` | `/api/simulation/start` | Starts background continuous traffic simulation. |
| `POST` | `/api/simulation/stop` | Pauses background continuous traffic simulation. |
| `POST` | `/api/simulation/trigger-scenario` | Injects an isolated synthetic scenario on demand. |

---

## Installation Guide

### Prerequisites
- Python 3.10 or higher
- Git

### Step 1: Clone Repository
```bash
git clone https://github.com/your-username/Network-Intrusion-Detection-System-Simulation.git
cd Network-Intrusion-Detection-System-Simulation
```

### Step 2: Install Dependencies
```bash
pip install -r requirements.txt
```

### Step 3: Initialize Dataset & Train Machine Learning Models
```bash
# 1. Generate synthetic dataset (6,000 records)
python simulator/generate_dataset.py

# 2. Train and evaluate ML models (Random Forest, Logistic Regression, Isolation Forest)
python ml/train_model.py

# 3. Seed demonstration database records
python simulator/seed_db.py
```

---

## Usage & Execution Instructions

### Start the IDS Backend & SOC Dashboard
```bash
python -m uvicorn backend.app:app --host 127.0.0.1 --port 8000 --reload
```
Open your browser and navigate to:
```
http://127.0.0.1:8000
```

### Run the Standalone Traffic Simulator (Optional)
In a separate terminal:
```bash
# Mixed mode (normal traffic with intermittent threat patterns)
python simulator/traffic_simulator.py --mode mixed --speed fast

# Or console-only print mode (no HTTP requests)
python simulator/traffic_simulator.py --mode mixed --speed fast --no-http
```

---

## Automated Testing Strategy

The project contains **30 automated tests** in `tests/test_ids.py` covering:
- Safe Protocol Flows (TCP, UDP, DNS, HTTPS)
- Threat Signatures (Excessive Rates, Failed Connections, Port Probes, SYN-Heavy, Volume Spikes)
- Input Sanitization (Malformed IPs, Out-of-Range Ports, Invalid Protocols)
- Edge Cases (Zero Duration, Missing Fields, Duplicate Flow IDs)
- Alert Generation, Status State Machine, and Analyst Notes
- Database Persistence, API Contracts, and Dashboard Stats

### Run Test Suite
```bash
pytest tests/test_ids.py -v
```
**Result**: 30 passed in 4.51s (100% pass rate).

---

## Security & Privacy Controls

- **Synthetic Telemetry**: Only uses RFC 5737 documentation subnets (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`).
- **No Payload Storage**: Operates strictly on header metadata and statistical flow summaries, respecting privacy and compliance standards.
- **Input Sanitization**: User input and analyst notes are sanitized against script injection (XSS).
- **Environment Isolation**: Database and model paths are configurable via `.env`.

---

## Visual Screenshots & Proof Catalog

Refer to [screenshots/README.md](screenshots/README.md) for the complete 27-item visual proof catalog.

---

## Learning Outcomes

By completing and reviewing this project, you will understand:
- The fundamental mechanics of network flows (5-tuple aggregations) and traffic metrics.
- The differences and operational trade-offs between signature-based and anomaly-based detection.
- How to implement Z-score, IQR, and machine learning models for cyber anomaly detection.
- Why hybrid detection architectures provide defense-in-depth.
- How Tier-1 SOC analysts investigate alerts, document findings, and manage alert fatigue through correlation.

---

## Ethical Disclaimer

> [!IMPORTANT]
> **This project is designed exclusively for defensive cybersecurity education.**
> All suspicious network behavior is represented using synthetic data records or authorized, isolated local simulations. This project does **NOT** scan, probe, exploit, disrupt, flood, or attack public or third-party networks, nor does it provide tools to execute real-world malicious traffic.

---

## Author & Acknowledgments

- **Developed by**: Cybersecurity Engineering Student
- **Abhishek Basu — Embedded Systems Student GitHub: [DevAbhay2003](https://github.com/DevAbhay2003?tab=repositories) · LinkedIn: [Abhishek Basu](https://www.linkedin.com/in/abhishek-basu-68b1b1342/)**
- **Project Title**: Network Intrusion Detection System (IDS) Simulation
- **License**: MIT License
