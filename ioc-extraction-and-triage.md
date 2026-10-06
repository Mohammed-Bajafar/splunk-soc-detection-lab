# IOC Extraction and Triage

## Purpose

This document records the observable indicators collected from the controlled SOC lab incidents. These are lab observables, not confirmed malicious indicators.

## INC-001 — Brute Force

| Observable | Value | Context |
|---|---|---|
| Account | `LabTestUser` | Test account targeted by invalid credentials |
| Windows Event ID | `4625` | Failed logon |
| Source address | `::1` | IPv6 loopback observed in the successful D1 test |
| Detection threshold | `3 failures / 5 minutes` | D1 correlation logic |

**Triage:** The source was loopback because the test was performed locally. It should not be treated as an external attacker IP.

## INC-002 — Suspicious PowerShell

| Observable | Value | Context |
|---|---|---|
| Process | `powershell.exe` | Process creation observed by Sysmon |
| Command-line indicator | `-EncodedCommand` | Controlled PowerShell test |
| Windows Event ID | `1` | Sysmon process creation |
| PowerShell Event ID | `4104` | Script Block Logging |
| Timestamp | `2026-09-23 04:23:14` | Observed lab event |

The encoded command used in the test was:

```text
VwByAGkAdABlAC0ATwB1AHQAcAB1AHQAIABEADIAVAAgAFQARQBTAFQ=
```

**Triage:** `-EncodedCommand` is an analytic indicator that warrants investigation, but its presence alone does not prove malicious activity.

## INC-003 — Group Modification

| Observable | Value | Context |
|---|---|---|
| Actor | `hamod` | SubjectUserName in Event 4732 |
| Target group | `Administrators` | Local privileged group |
| Windows Event ID | `4732` | Security-enabled local group membership change |
| Member SID | `S-1-5-21-4089045705-3022718890-3416206102-1003` | Matched to `LabTestUser` |
| Timestamp | `2026-09-24 08:00:15` | Observed lab event |

**Triage:** The member name field was blank in the event, so the member SID was used to identify the affected account. The SID was independently verified as `LabTestUser`.

## D4 — Process-Lineage Validation Test

D4 was validated with a controlled `powershell.exe` process spawning `cmd.exe`.

| Observable | Value |
|---|---|
| Parent process | `powershell.exe` |
| Child process | `cmd.exe` |
| Telemetry | Sysmon Event ID 1 |

This is a behavioral indicator rather than a standalone IOC.

## D5 — Scheduled Task Validation Test

| Observable | Value | Context |
|---|---|---|
| Event ID | `4698` | Scheduled task created |
| Test task | `SOC-Lab-D5` / `SOC-Lab-D5-TEST` | Controlled lab tasks |
| Tool | `schtasks.exe` | Used to create the task |

These task names are test artifacts and should not be treated as malicious IOCs outside this lab.

## IOC Handling Notes

- No external malicious IP address, domain, URL, file hash, or malware sample was established by these tests.
- Loopback addresses (`127.0.0.1` / `::1`) are expected artifacts of local testing.
- Test usernames, task names, and command strings should be labeled as lab artifacts.
- In a real SOC investigation, candidate IOCs would be correlated with endpoint, network, identity, and threat-intelligence data before being classified as malicious.
