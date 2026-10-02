# MITRE ATT&CK® Defensive Framework Mapping

## Network Intrusion Detection System (IDS) Simulation

In modern Security Operations Centers (SOCs), aligning alerts with the **MITRE ATT&CK** knowledge base provides standardized terminology, assists in hypothesis-driven threat hunting, informs incident response playbooks, and identifies detection coverage gaps.

---

### Crucial Defensive Caveat: Evidence vs. Assumption

> [!IMPORTANT]
> **A statistical anomaly or signature match does not automatically prove an adversarial tactic.**
> In defensive network monitoring, a single network flow record is an **indicator**, not definitive proof. For instance, high connection rates can be caused by benign enterprise backup scripts or misconfigured microservices just as easily as automated denial-of-service tools. A Tier-1 SOC analyst must correlate network telemetry with endpoint logs (EDR/Sysmon) and identity logs before formally attributing an incident to an ATT&CK technique.

---

### Defensive Detection Rule Alignment

| Rule ID | Detection Rule Name | Primary ATT&CK Tactic | Candidate ATT&CK Technique | Defensive Investigation Context |
|---|---|---|---|---|
| **IDS-001** | Excessive Connection Rate | **Impact** (TA0040) / **Discovery** (TA0007) | **Network Denial of Service** (`T1498`) or **Network Service Discovery** (`T1046`) | High-frequency connection bursts may represent automated network stress or rapid port sweeps. Analyst verifies source process and firewall egress rules. |
| **IDS-002** | Repeated Failed Connections | **Credential Access** (TA0006) | **Brute Force: Password Guessing** (`T1110.001`) / **Password Spraying** (`T1110.003`) | Flow shows elevated failed connection count and high failure ratio. Analyst checks SSH (`/var/log/auth.log`) or Windows Event ID 4625 for targeted usernames. |
| **IDS-003** | Multi-Port Probing Pattern | **Discovery** (TA0007) | **Network Service Discovery** (`T1046`) | Flow contacts high diversity of destination ports across an endpoint. Analyst verifies whether internal vulnerability scanners (Qualys/Nessus) were scheduled. |
| **IDS-004** | SYN-Heavy Connection Behavior | **Impact** (TA0040) / **Discovery** (TA0007) | **Direct Network Flood** (`T1498.001`) | Abnormally high ratio of SYN packets with no completion handshakes. Analyst examines host half-open connection queues and SYN-cookie activation. |
| **IDS-005** | Unusual Service-Port Activity | **Command and Control** (TA0011) | **Non-Standard Port** (`T1571`) | Traffic directed at ports historically linked to backdoor shells or unapproved IRC channels (e.g. 1337, 4444). Analyst inspects local process listening on socket (`netstat -ano`). |
| **IDS-006** | Abnormally High Traffic Volume | **Exfiltration** (TA0010) / **Collection** (TA0009) | **Exfiltration Over Alternative Protocol** (`T1048`) | Sustained volumetric egress spike exceeding workstation baselines. Analyst verifies whether scheduled database dumps or large file backups were authorized. |

---

### How ATT&CK Mapping Empowers the Defensive SOC

1. **Standardized Incident Documentation**: Allows Tier-1 and Tier-2 analysts to communicate severity and suspected adversary objectives using universal industry taxonomy.
2. **Hypothesis-Driven Threat Hunting**: If multiple `T1046` (Discovery) alerts trigger in a subnet, analysts proactively search for subsequent lateral movement (`T1021`) or privilege escalation.
3. **Detection Engineering Gap Analysis**: Comparing enabled rules against the ATT&CK Matrix highlights which stages of the cyber kill chain lack defensive sensors.
4. **Executive & Compliance Reporting**: Provides leadership with quantifiable metrics regarding organizational readiness against recognized adversary behaviors.
