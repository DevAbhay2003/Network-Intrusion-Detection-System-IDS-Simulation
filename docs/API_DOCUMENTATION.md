# REST API Documentation

## Network Intrusion Detection System (IDS) Simulation

This specification documents the defensive endpoints exposed by the IDS backend service (`http://127.0.0.1:8000`).

---

### Table of Endpoints

| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/api/flows` | Ingests a raw network flow and executes the IDS detection pipeline |
| `GET` | `/api/flows` | Returns ingested flow records with pagination and search filters |
| `GET` | `/api/flows/{flow_id}` | Retrieves detailed telemetry for a specific flow record |
| `POST` | `/api/flows/reset` | Resets database tables for fresh simulation runs |
| `GET` | `/api/alerts` | Returns generated security alerts with severity/status filters |
| `GET` | `/api/alerts/{alert_id}` | Returns complete investigation dossier, SOP recommendations, and notes |
| `PUT` | `/api/alerts/{alert_id}/status` | Updates alert triage status (`NEW`, `INVESTIGATING`, `RESOLVED`, `FALSE_POSITIVE`) |
| `POST` | `/api/alerts/{alert_id}/notes` | Appends an analyst investigation note to the audit trail |
| `GET` | `/api/alerts/incidents/correlated` | Returns correlated security incidents aggregated by source IP and time window |
| `GET` | `/api/rules` | Retrieves all signature rules, status, and thresholds |
| `PUT` | `/api/rules/{rule_id}` | Updates rule thresholds or toggles enabled/disabled state |
| `GET` | `/api/dashboard/stats` | High-level metrics for top summary cards |
| `GET` | `/api/dashboard/traffic` | Recent time-series throughput points (packets & bytes) |
| `GET` | `/api/dashboard/alerts-breakdown` | Alert distributions by severity level and rule type |
| `GET` | `/api/dashboard/protocols` | Flow counts grouped by transport protocol |
| `GET` | `/api/dashboard/ports` | Flow counts grouped by destination port |
| `GET` | `/api/dashboard/top-sources` | Top source IPs ranked by alert frequency |
| `GET` | `/api/dashboard/risk-distribution` | Flow counts across 5 defense risk tiers |
| `GET` | `/api/simulation/status` | Returns running state of in-process traffic simulator |
| `POST` | `/api/simulation/start` | Starts background continuous traffic simulation |
| `POST` | `/api/simulation/stop` | Pauses background continuous traffic simulation |
| `POST` | `/api/simulation/trigger-scenario` | Injects an isolated synthetic scenario on demand |
| `GET` | `/api/health` | Service health verification |

---

### Endpoint Specifications

#### 1. Ingest Network Flow
- **Endpoint**: `POST /api/flows`
- **Request Body (JSON)**:
```json
{
  "source_ip": "192.0.2.15",
  "destination_ip": "198.51.100.20",
  "source_port": 50123,
  "destination_port": 443,
  "protocol": "TCP",
  "packet_count": 25,
  "byte_count": 18000,
  "duration_seconds": 2.5,
  "connection_count": 2,
  "failed_connection_count": 0,
  "syn_count": 2,
  "rst_count": 0
}
```
- **Response `201 Created`**:
```json
{
  "status": "PROCESSED",
  "flow_id": "FLOW-A1B2C3D4",
  "risk_score": 14.5,
  "classification": "NORMAL",
  "alert_generated": false,
  "alert": null
}
```
- **Validation**: Fails with `422 Unprocessable Entity` if port $< 1$ or $> 65535$, protocol $\notin [\text{TCP}, \text{UDP}, \text{ICMP}]$, or IP address format is invalid.

---

#### 2. Update Alert Triage Status
- **Endpoint**: `PUT /api/alerts/{alert_id}/status`
- **Request Body (JSON)**:
```json
{
  "status": "INVESTIGATING"
}
```
- **Valid Status Values**: `NEW`, `INVESTIGATING`, `RESOLVED`, `FALSE_POSITIVE`
- **Response `200 OK`**:
```json
{
  "alert_id": "ALT-10021",
  "previous_status": "NEW",
  "current_status": "INVESTIGATING",
  "updated_at": "2026-10-02T10:45:00.000000Z"
}
```

---

#### 3. Append Analyst Investigation Note
- **Endpoint**: `POST /api/alerts/{alert_id}/notes`
- **Request Body (JSON)**:
```json
{
  "note": "Validated with DevOps: automated backup batch job triggered expected volumetric alert.",
  "analyst_name": "Tier-1 Analyst (Shift A)"
}
```
- **Response `201 Created`**:
```json
{
  "note_id": 4,
  "alert_id": "ALT-10021",
  "analyst_name": "Tier-1 Analyst (Shift A)",
  "note": "Validated with DevOps: automated backup batch job triggered expected volumetric alert.",
  "created_at": "2026-10-02T10:46:12.000000Z"
}
```
