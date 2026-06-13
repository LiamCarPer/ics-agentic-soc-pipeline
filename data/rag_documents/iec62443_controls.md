# IEC 62443 Security Controls for OT Network Anomaly Response

## Network Segmentation (SR 5.1)

The OT network is divided into security zones: Level 0 (Process), Level 1 (Basic Control), Level 2 (Supervisory Control), and Level 3 (Site Operations). The PLCs (172.21.0.x) reside in Level 1 and must only accept traffic from Level 2 HMI (172.22.0.10) and authorized engineering workstations (172.23.0.4). Any traffic from outside these zones, such as from 172.24.0.x, indicates a zone boundary violation and should trigger an alert. Firewall rules at the zone boundary should deny all traffic not originating from known-good IPs.

## Least Privilege and Role-Based Access Control (SR 1.4)

Modbus function codes map directly to privilege levels. Read functions (FC 3) are granted to monitoring roles (HMI). Write functions (FC 6, FC 16) are restricted to the engineering workstation role (eng-ws-01). No asset should have more privileges than necessary for its function. The detection pipeline flags any FC 6 or FC 16 from a non-authorized source as an unauthorized write anomaly.

## Modbus Protocol Deep Packet Inspection (SR 4.1)

The OT intrusion detection system should inspect Modbus TCP payloads for anomalous function codes, register addresses outside the expected range, and exception responses (FC 131). A scanning attack from an unrecognized IP will produce a burst of FC 131 exception responses as the attacker probes invalid register addresses. Deep packet inspection rules should rate-limit or block connections that generate more than 5 exception responses in a 60-second window.

## Anomaly Detection and Incident Response (SR 3.2)

The SOC must maintain an anomaly detection pipeline that combines unsupervised machine learning with rule-based thresholds. When an anomaly is detected, it should be enriched with asset context and historical incident data before escalation. The enrichment pipeline queries a vector database (ChromaDB) containing asset inventory, control standards, and past incident reports. The enriched alert is then presented to an LLM agent for report generation.

## Audit Logging and Continuous Monitoring (SR 6.1)

All Modbus transactions must be logged with source IP, destination IP, function code, timestamp, and register values. Logs are stored in a time-series database (InfluxDB) and retained for at least 90 days. The anomaly detection pipeline reads from the same log stream. Audit logs must be tamper-proof and accessible only to authorized SOC personnel.

## Engineering Workstation Hardening (SR 1.1)

The engineering workstation (172.23.0.4) must be hardened with application allowlisting, multi-factor authentication, and network-level access controls. It should only be accessible from the OT management network, not from the corporate IT network or directly from the internet. A compromise of the engineering workstation is a critical incident because it can issue write commands to any PLC.

## Incident Reporting and Escalation (SR 2.8)

Anomaly alerts must be escalated through a defined chain: Level 1 SOC Analyst (automated detection and triage), Level 2 OT Security Engineer (investigation and containment), Level 3 Engineering Manager (process impact assessment and recovery approval). Each alert must include: alert_id, affected asset IP, anomaly score, observed function codes, and a window of raw telemetry for investigation. SLAs: 5 minutes for initial triage, 30 minutes for containment decision.

## Secure Remote Access (SR 5.2)

Any remote access to the OT network must go through a jump host or bastion with session recording. Remote access sessions must use encrypted protocols and multi-factor authentication. The anomaly detection system should flag connections from IPs that are not in the allowlist (172.22.0.10, 172.23.0.4) as potentially unauthorized remote access attempts.
