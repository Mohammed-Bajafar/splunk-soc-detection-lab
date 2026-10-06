# MITRE ATT&CK Mapping

This document maps the project's validated detections and controlled lab scenarios to MITRE ATT&CK techniques. The mapping is based on the behavior actually tested in the lab, not on assumptions about a real-world intrusion.

## Detection Mapping

| ID | Detection / Observed Behavior | Telemetry | ATT&CK Mapping | Notes |
|---|---|---|---|---|
| D1 | Multiple failed Windows logons | Security 4625 | T1110 — Brute Force | The lab generated repeated failed authentication attempts against `LabTestUser`. The exact test used repeated invalid credentials; this is consistent with the broader Brute Force technique. |
| D2 | PowerShell using `-EncodedCommand` | Sysmon Event ID 1 + PowerShell 4104 | T1059.001 — PowerShell | The controlled test executed `powershell.exe -EncodedCommand`. |
| D3 | User added to local Administrators group | Security 4732 | T1098.007 — Additional Local or Domain Groups | MITRE's current sub-technique specifically covers adding accounts to local/domain groups, including local Administrators on Windows. |
| D4 | PowerShell spawned `cmd.exe` | Sysmon Event ID 1 | T1059.003 — Windows Command Shell | The detection is a suspicious process-lineage analytic; the tested child process was `cmd.exe`, so the ATT&CK behavior mapping is Windows Command Shell. |
| D5 | Scheduled task creation | Security 4698 + Sysmon process creation | T1053.005 — Scheduled Task/Job: Scheduled Task | The lab created scheduled tasks with `schtasks.exe`. |

## Incident Mapping

### INC-001 — Brute Force

**Technique:** T1110 — Brute Force

The controlled activity generated three failed authentication attempts within a five-minute window. The evidence was captured as Windows Security Event ID 4625 and detected by D1.

### INC-002 — Suspicious PowerShell

**Technique:** T1059.001 — PowerShell

The controlled activity executed PowerShell with `-EncodedCommand`. Sysmon Event ID 1 recorded the process creation and PowerShell Event ID 4104 captured script-block telemetry.

### INC-003 — Group Modification

**Technique:** T1098.007 — Additional Local or Domain Groups

The controlled activity added `LabTestUser` to the local `Administrators` group. Security Event ID 4732 recorded the membership change. The member SID was verified separately as belonging to `LabTestUser`.

## Important Scope Note

These mappings describe the ATT&CK behaviors demonstrated by the lab. The tests were controlled and benign; the project does not claim that a real adversary compromised the endpoint.

## References

- MITRE ATT&CK T1110 — Brute Force
- MITRE ATT&CK T1059.001 — PowerShell
- MITRE ATT&CK T1059.003 — Windows Command Shell
- MITRE ATT&CK T1098.007 — Additional Local or Domain Groups
- MITRE ATT&CK T1053.005 — Scheduled Task/Job: Scheduled Task
