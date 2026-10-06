# Splunk SOC Detection Lab

A hands-on SOC portfolio project focused on Windows security monitoring, Splunk SIEM, detection engineering, alerting, threat hunting, dashboarding, and incident investigation.

> **Lab scope:** All attack simulations and evidence in this repository were generated in a controlled lab environment. They demonstrate security telemetry and detection workflows; they do not represent a real-world compromise.

## Project Overview

This project demonstrates an analyst workflow from endpoint telemetry collection to detection, alerting, threat hunting, and incident investigation.

### Lab Architecture

```text
Windows Endpoint
├── Sysmon
├── Windows Security Events
├── PowerShell Script Block Logging
└── Splunk Universal Forwarder
          │
          │ TCP 9997
          ▼
   Splunk Enterprise
   ├── endpoint_sysmon
   ├── endpoint_security
   ├── SPL detections
   ├── Scheduled alerts
   ├── Threat hunting
   └── SOC Detection Dashboard
```

## Technologies

- Splunk Enterprise
- Splunk Universal Forwarder
- Sysmon
- Windows Security Event Logs
- PowerShell Script Block Logging
- Windows 11
- VirtualBox
- SPL
- MITRE ATT&CK

## Detection Engineering

| ID | Detection | Primary Telemetry | MITRE ATT&CK |
|---|---|---|---|
| D1 | Brute Force / Multiple Failed Logons | Security 4625 | T1110 — Brute Force |
| D2 | Suspicious PowerShell | Sysmon 1 + PowerShell 4104 | T1059.001 — PowerShell |
| D3 | Privilege Escalation via Group Modification | Security 4732 | T1098.007 — Additional Local or Domain Groups |
| D4 | PowerShell → CMD Process Relationship | Sysmon 1 | T1059.003 — Windows Command Shell |
| D5 | Scheduled Task Persistence | Security 4698 + Sysmon process creation | T1053.005 — Scheduled Task/Job: Scheduled Task |

Detailed SPL and detection logic are documented in [`detections/`](detections/).

## Threat Hunting

Five hypothesis-driven hunts were performed:

1. Encoded PowerShell
2. PowerShell spawning CMD
3. Scheduled task creation
4. Failed logons
5. Windows group modifications

See [`threat-hunting/hunts.md`](threat-hunting/hunts.md).

## Incident Investigations

### INC-001 — Brute Force

A controlled test generated three failed authentication attempts against `LabTestUser` within a five-minute window. Windows Security Event ID 4625 was collected and detected by D1.

### INC-002 — Suspicious PowerShell

A controlled PowerShell `-EncodedCommand` execution was captured by Sysmon Event ID 1 and PowerShell Event ID 4104, then detected by D2.

### INC-003 — Group Modification

A controlled test added `LabTestUser` to the local `Administrators` group. Windows Security Event ID 4732 recorded the membership change. The member SID was independently verified against `LabTestUser`.

Incident reports are available in [`incidents/`](incidents/).

## Dashboard

The **SOC Detection Dashboard** was built in Splunk Dashboard Studio and includes:

- Total Security Events
- Failed Logons
- Group Modifications
- Suspicious PowerShell
- Scheduled Tasks
- Windows Security Event Activity
- Security Events by Event ID
- Recent Security Events

See [`dashboards/dashboard.md`](dashboards/dashboard.md).

## MITRE ATT&CK Mapping

The project maps validated lab behaviors to ATT&CK techniques and sub-techniques. See [`mitre/attack-mapping.md`](mitre/attack-mapping.md).

## IOC Analysis

The IOC documentation records observable lab artifacts and explicitly distinguishes them from confirmed malicious indicators. See [`ioc-analysis/ioc-extraction-and-triage.md`](ioc-analysis/ioc-extraction-and-triage.md).

No external malicious IP address, domain, URL, file hash, or malware sample was established by the controlled tests.

## Project Structure

```text
splunk-soc-detection-lab/
├── README.md
├── PROJECT_STATUS.md
├── detections/
│   └── detections.md
├── incidents/
│   ├── INC-001-brute-force.md
│   ├── INC-002-suspicious-powershell.md
│   └── INC-003-group-modification.md
├── threat-hunting/
│   └── hunts.md
├── dashboards/
│   └── dashboard.md
├── mitre/
│   └── attack-mapping.md
└── ioc-analysis/
    └── ioc-extraction-and-triage.md
```

## What This Project Demonstrates

- Windows endpoint telemetry collection
- Splunk data ingestion and index organization
- SPL-based detection engineering
- Scheduled security alerts
- Threat hunting using endpoint and Windows security telemetry
- Dashboard development in Splunk Dashboard Studio
- Evidence-based incident investigation
- MITRE ATT&CK mapping
- IOC extraction and triage
- Documentation of controlled security testing
