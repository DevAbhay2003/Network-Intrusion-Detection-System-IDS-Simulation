# Network Intrusion Detection System (IDS) Simulation

## Comprehensive Technical Project Report

**Author:** Cybersecurity Engineering Student  
**Course:** Defensive Cybersecurity & Network Defense Engineering  
**Focus:** Network Security, Signature/Anomaly Detection, Risk Scoring, Machine Learning, SOC Monitoring  

---

### Abstract
Modern enterprise computer networks are subject to persistent, high-frequency, and sophisticated threat vectors ranging from automated scanning and brute-force credential stuffing to distributed denial-of-service and unauthorized volumetric data exfiltration. Conventional perimeter defenses alone are insufficient to guarantee network integrity. This project presents the design, mathematical formulation, implementation, and empirical evaluation of a **Defensive Network Intrusion Detection System (IDS)** simulation. Operating strictly within isolated and safe synthetic telemetry paradigms (utilizing RFC 5737 documentation address pools), the system executes a multi-vector hybrid inspection pipeline that synergizes deterministic signature/rule evaluation, Gaussian and non-parametric statistical anomaly modeling (Z-Score and Interquartile Range), and supervised and unsupervised machine learning algorithms (Random Forest, Logistic Regression, and Isolation Forest). An integrated Security Operations Center (SOC) web dashboard provides real-time telemetry analytics, interactive charts, threat correlation, and event investigation workflows, bridging academic computer networking fundamentals with real-world defensive security operations.

---

### 1. Introduction & Background
Intrusion Detection Systems (IDS) serve as essential defensive telemetry sensors within modern enterprise security architectures. While firewalls enforce boundary access-control policies, an IDS passively analyzes communication streams to detect malicious behaviors, reconnaissance patterns, and policy violations.

Network traffic consists of individual packets traversing network interfaces, aggregated logically into **network flows** (uniquely identified by the 5-tuple: Source IP, Destination IP, Source Port, Destination Port, and Protocol). Within a Security Operations Center (SOC), security events represent raw observations of interest, security alerts indicate threshold-breaching or signature-matching events requiring triage, and security incidents represent correlated collections of alerts requiring coordinated human investigation and containment.

---

### 2. Problem Statement & Educational Scope
Deploying physical intrusion detection hardware or capturing live network packets in an educational or laboratory setting presents logistical, ethical, and legal challenges:
1. Physical network infrastructure is rarely accessible to independent students.
2. Capturing and storing real payload data can violate user privacy and compliance mandates.
3. Conducting active scans or penetration exploits against unauthorized networks is strictly unethical and illegal.

To resolve these constraints, this project formulates a **complete virtual IDS simulation** that models network flow behaviors as structured statistical data records. All attack-like patterns (such as port sweeps, credential spraying, and SYN floods) are modeled exclusively through mathematical data representations using RFC 5737 documentation blocks (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`). This guarantees a safe, self-contained, reproducible, and defensive educational environment.

---

### 3. Objectives
The core engineering objectives achieved in this project include:
1. **Synthetic Telemetry Generation**: Generating balanced datasets ($\ge 5,000$ flow records) representing normal enterprise protocols (HTTPS, DNS, SSH, Email, Database) alongside defensive anomaly patterns.
2. **Robust Feature Engineering**: Extracting 15 volumetric and behavioral metrics while enforcing zero-division guards and strict input validation.
3. **Tri-Vector Hybrid Detection**:
   - Deterministic rule engine evaluating configurable signatures (IDS-001 through IDS-006).
   - Statistical anomaly detector computing continuous deviation scores (0–100) via Z-score and IQR.
   - Machine learning inference providing calibrated class probabilities.
4. **Weighted Risk Scoring & Triage**: Computing a normalized composite risk score (0–100) with calibrated categorization into 5 defense risk tiers.
5. **Alert Management & Correlation**: Generating structured alerts and clustering related alerts within a 60-second sliding window to mitigate SOC alert fatigue.
6. **SOC Dashboard & Investigation Workflow**: Developing an interactive dark-theme console with 8 real-time charts, SOP recommendations, and analyst audit note tracking.
7. **Automated Verification**: Implementing an automated test suite with 30 comprehensive unit and integration test scenarios achieving 100% pass rate.

---

### 4. System Architecture & Detection Pipeline

```text
Synthetic Flow Ingestion (RFC 5737 Scopes)
                   │
                   ▼
Feature Extractor (15 Derived Metrics & Zero-Div Safeguards)
                   │
    ┌──────────────┼──────────────┐
    ▼              ▼              ▼
Rule Engine   Anomaly Engine   ML Classifier
(IDS-001..6)  (Z-Score & IQR)  (Random Forest)
    │              │              │
    └──────────────┼──────────────┘
                   ▼
Hybrid Risk Engine (Weighted Scoring & Tier Classification)
                   │
                   ▼
Alert Engine (ALT-xxxxx & SOC SOP Recommendations)
                   │
                   ▼
Alert Correlation Engine (60s Window Aggregation -> INC-xxxx)
                   │
    ┌──────────────┴──────────────┐
    ▼                             ▼
SQLite Database Persistence   FastAPI & SOC Analytics Web UI
```

---

### 5. Mathematical & Methodological Formulation

#### 5.1 Network Feature Engineering
Given raw flow parameters (packet count $N_p$, byte count $N_b$, duration $t$, connection count $C$, failed connections $C_f$, SYN packets $N_{syn}$), the engine computes derived rates:
- **Bytes per Second**: $R_b = \frac{N_b}{\max(t, 0.001)}$
- **Packets per Second**: $R_p = \frac{N_p}{\max(t, 0.001)}$
- **Connection Rate**: $R_c = \frac{C}{\max(t, 0.001)}$
- **Failure Ratio**: $F_r = \min\left(1.0, \frac{C_f}{\max(C, 1)}\right)$
- **SYN Ratio**: $S_r = \min\left(1.0, \frac{N_{syn}}{\max(N_p, 1)}\right)$

#### 5.2 Statistical Anomaly Detection
For each monitored metric $x_i$, historical normal profiles establish mean $\mu_i$, standard deviation $\sigma_i$, and upper quartile $Q_{75, i}$ with Interquartile Range $\text{IQR}_i$.
1. **Z-Score Deviation**:
   $$z_i = \max\left(0, \frac{x_i - \mu_i}{\max(\sigma_i, 0.001)}\right)$$
2. **IQR Outlier Distance**:
   $$\delta_{\text{IQR}, i} = \max\left(0, \frac{x_i - (Q_{75, i} + 1.5 \times \text{IQR}_i)}{\max(\text{IQR}_i, 0.001)}\right)$$
3. **Composite Metric Deviation**:
   $$D_i = 0.60 z_i + 0.40 \delta_{\text{IQR}, i}$$
4. **Weighted Deviation**:
   $$D_{\text{total}} = \sum_{i} w_i D_i$$
5. **Calibrated Anomaly Score (0–100)**:
   $$S_{\text{anom}} = 100 \times \left(1 - e^{-0.45 \times D_{\text{total}}}\right)$$

#### 5.3 Hybrid Risk Scoring
The final threat risk combines multi-vector perspectives:
$$\text{Risk Score} = (w_r \times S_{\text{rule}}) + (w_a \times S_{\text{anom}}) + (w_{ml} \times 100 P_{\text{ml}})$$
Where $w_r = 0.40$, $w_a = 0.30$, and $w_{ml} = 0.30$ (normalized).

---

### 6. Experimental Results & Machine Learning Evaluation

The system was evaluated on a held-out test split (20%, 1,200 records: 845 Normal, 355 Suspicious) derived from the 6,000 synthetic dataset records:

| Model | Model Family | Accuracy | Precision | Recall | F1 Score | False Positives | False Negatives |
|---|---|---|---|---|---|---|---|
| **Random Forest** | Supervised Ensemble | **99.00%** | **99.71%** | **96.90%** | **98.29%** | **1** | 11 |
| **Logistic Regression**| Supervised Linear | 96.50% | 100.00% | 88.17% | 93.71% | 0 | 42 |
| **Isolation Forest** | Unsupervised Outlier Tree | 89.83% | 78.77% | 89.86% | 83.95% | 86 | 36 |

#### Key Cybersecurity Takeaways
1. **Supervised Random Forest** achieved outstanding precision (99.71%) and recall (96.90%), proving highly effective at recognizing known threat distributions.
2. **Unsupervised Isolation Forest** demonstrated the classic operational dilemma of anomaly-based detection: it detected novel outliers without requiring labels (89.86% recall), but produced 86 false positives, which would increase Tier-1 SOC alert triage volume in an enterprise environment.
3. **Why Accuracy Alone Is Insufficient**: In cybersecurity datasets, normal traffic heavily dominates threats. A naive model that classifies 100% of traffic as normal could achieve high accuracy while completely missing all intrusions (0% recall), leading to catastrophic security compromises.

---

### 7. Verification & Automated Test Results
The test suite in `tests/test_ids.py` verified 30 distinct scenarios covering:
- Normal protocol flows (TCP, UDP, DNS, HTTPS)
- Threat signatures (Rate bursts, brute-force patterns, port sweeps, SYN-floods, volume spikes)
- Input sanitation (malformed IPv4, negative/overflow ports, invalid protocols)
- Division-by-zero safety
- State transitions (NEW $\to$ INVESTIGATING $\to$ RESOLVED / FALSE_POSITIVE)
- Database persistence and REST API contract compliance

**Result:** 30 passed in 4.51 seconds (100% pass rate).

---

### 8. Limitations & Future Scope
- **Current Limitations**: The simulator operates on statistical flow summaries rather than full packet payload inspection (DPI).
- **Defensive Future Scope**:
  1. Integration with Suricata / Zeek JSON EVE logs.
  2. Ingestion of authorized offline `.pcap` capture files.
  3. SIEM webhook forwarding (Elasticsearch / Splunk).
  4. Real-time concept drift monitoring for ML model retraining.

---

### 9. Conclusion
This project successfully demonstrates the end-to-end architecture, defensive logic, mathematical modeling, and operational triage workflows of an enterprise Network Intrusion Detection System. By grounding the simulation in synthetic flow records and documentation IP pools, it provides an ethical, safe, and rigorous foundation for cybersecurity engineering education and portfolio demonstration.
