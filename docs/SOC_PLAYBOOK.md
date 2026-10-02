# SOC Analyst Standard Operating Procedures (SOP) & Triage Playbook

## Network Intrusion Detection System (IDS) Simulation

This document defines standard defensive triage procedures for Tier-1 SOC analysts monitoring the Network IDS console.

---

## 1. Alert Triage Lifecycle

```text
[ Incoming Security Alert ] (Status: NEW)
            │
            ▼
[ Analyst Initial Triage ]
  - Verify IP Reputation (RFC 5737 internal test scope)
  - Examine Flow Telemetry (Packets, Volume, Duration, Flags)
  - Review Matched Rules & Anomaly Scores
            │
    ┌───────┴───────┐
    │ Change Status │
    ▼               ▼
[ INVESTIGATING ]  [ FALSE POSITIVE ]
    │                 - Document justification in Notes
    │                 - Flag rule threshold for tuning
    ▼
[ Deep Dive Context Review ]
  - Correlate with Endpoint Telemetry (Sysmon/EDR)
  - Inspect Authentication Logs
  - Verify Change Control / Maintenance Schedules
    │
    ▼
[ RESOLVED / CONTAINED ]
  - Apply host isolation if malicious
  - Append remediation summary to Case Notes
```

---

## 2. Tier-1 SOC Analyst Responsibilities

1. **Queue Hygiene**: Regularly monitor the Alerts Queue (`/api/alerts`) filtered by `CRITICAL` and `HIGH` severities.
2. **Initial Verification**: Check whether the source IP is an internal workstation, DMZ server, or legitimate automated maintenance system.
3. **Contextual Enrichment**:
   - For `REPEATED_FAILED_CONNECTIONS`: Cross-reference Active Directory or Linux `/var/log/auth.log` to determine whether a service account password expired.
   - For `HIGH_CONNECTION_RATE`: Check if the user is running an authorized benchmark or web scraping script.
   - For `HIGH_TRAFFIC_VOLUME`: Confirm whether an automated backup window was scheduled.
4. **Audit Trail Documentation**: Every status transition must include an analyst note detailing:
   - What evidence was examined
   - Who was contacted (e.g. System Administrator, User)
   - Reason for resolution or false-positive disposition

---

## 3. False Positive Mitigation & Rule Tuning

When legitimate activity repeatedly triggers alerts:
1. **Never simply disable a rule**: Toggling off a rule blinds the SOC to real threats.
2. **Adjust Baselines**: If legitimate developer builds regularly hit 30 connections/sec, update `IDS-001` threshold `min_connection_rate` to 40.0.
3. **Exclusion Lists**: Configure whitelists for authorized vulnerability scanner IPs or database replication hosts.
