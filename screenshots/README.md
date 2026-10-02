# Project Visual Proof & Screenshot Checklist Guide

## Network Intrusion Detection System (IDS) Simulation

This directory contains visual evidence documenting each functional layer of the Network IDS Simulation project for GitHub, portfolio, and presentation verification.

---

### Screenshot Verification Catalog

| ID | Filename | Description | Verified Stage |
|---|---|---|---|
| 01 | `01_project_folder_structure.png` | Complete directory tree displaying modular packages | Workspace / Repo Root |
| 02 | `02_ids_system_architecture.png` | End-to-end architecture pipeline diagram | Documentation |
| 03 | `03_synthetic_dataset_preview.png` | First 25 rows of `data/network_traffic.csv` | Dataset Generator |
| 04 | `04_traffic_simulator_terminal.png` | Terminal running live continuous synthetic flow stream | Traffic Simulator |
| 05 | `05_normal_traffic_flow.png` | Terminal output showing normal HTTPS/DNS flow ingestion | Normal Flow Baseline |
| 06 | `06_suspicious_synthetic_traffic.png` | Terminal output showing flagged suspicious pattern | Threat Simulator |
| 07 | `07_feature_extraction_output.png` | Terminal / python debug inspecting 15 derived features | Feature Extractor |
| 08 | `08_signature_rule_triggered.png` | Rule engine match output with trigger evidence | Rule Engine |
| 09 | `09_statistical_anomaly_score.png` | Statistical anomaly breakdown showing Z-score & IQR | Anomaly Detector |
| 10 | `10_hybrid_risk_calculation.png` | Hybrid risk score output combining Rule, Anomaly, ML | Risk Engine |
| 11 | `11_security_alert_generated.png` | Generated `ALT-xxxxx` alert JSON structure | Alert Engine |
| 12 | `12_soc_dashboard_overview.png` | Primary dark-mode SOC web console with key cards | Frontend Dashboard |
| 13 | `13_traffic_over_time_chart.png` | Interactive Chart.js time-series throughput graph | Dashboard Analytics |
| 14 | `14_classification_donut_chart.png` | Normal vs Suspicious doughnut chart | Dashboard Analytics |
| 15 | `15_severity_distribution_chart.png`| Bar chart of alerts across INFO to CRITICAL | Dashboard Analytics |
| 16 | `16_top_alert_types_chart.png` | Horizontal bar chart of top triggered detection rules | Dashboard Analytics |
| 17 | `17_protocol_distribution_chart.png`| Pie chart of TCP, UDP, and ICMP proportions | Dashboard Analytics |
| 18 | `18_destination_port_chart.png` | Bar chart of service ports targeted | Dashboard Analytics |
| 19 | `19_top_source_ips_chart.png` | Top threat origins ranked by alert frequency | Threat Analytics |
| 20 | `20_risk_distribution_chart.png` | Histogram across the 5 defensive risk tiers | Risk Analytics |
| 21 | `21_alert_investigation_dossier.png`| Event investigation modal showing flow stats & SOP | Incident Triage |
| 22 | `22_analyst_notes_audit_trail.png` | Investigation drawer with appended analyst note | Incident Triage |
| 23 | `23_incident_status_update.png` | Status workflow changing to INVESTIGATING / RESOLVED | Case Management |
| 24 | `24_detection_rules_table.png` | Rule configuration management and toggle buttons | Rules Console |
| 25 | `25_ml_benchmark_evaluation.png` | Terminal output of precision, recall, and confusion matrix | ML Evaluation |
| 26 | `26_automated_tests_pass.png` | Terminal showing all 30 pytest test cases passing | Automated Testing |
| 27 | `27_api_interactive_docs.png` | FastAPI interactive Swagger UI at `/docs` | REST API |

---

### How to Capture & Update Proof Screenshots
1. Launch the backend: `python backend/app.py`
2. Open `http://127.0.0.1:8000` in your web browser.
3. Use your system screenshot utility (e.g. `Win + Shift + S` on Windows) to capture the designated regions.
4. Save the files into this `screenshots/` directory matching the designated filenames.
