# INC-003 — Unauthorized Group Modification

## Summary
A controlled test removed and re-added `LabTestUser` to the local `Administrators` group. Windows Security Event ID `4732` recorded the membership change.

## Detection
**Detection:** D3 - Privilege Escalation via Group Modification  
**MITRE ATT&CK:** T1098 - Account Manipulation

```spl
index=endpoint_security "<EventID>4732</EventID>"
| rex field=_raw "<Data Name='SubjectUserName'>(?<Actor>[^<]+)"
| rex field=_raw "<Data Name='TargetUserName'>(?<TargetGroup>[^<]+)"
| rex field=_raw "<Data Name='MemberSid'>(?<MemberSID>[^<]+)"
| table _time host Actor TargetGroup MemberSID
| sort - _time
```

## Evidence
- Event ID: `4732`
- Actor: `hamod`
- Target group: `Administrators`
- Time: `2026-09-24 08:00:15`
- Member SID: `S-1-5-21-4089045705-3022718890-3416206102-1003`
- The SID was verified in PowerShell as belonging to `LabTestUser`.

## Simulation
```powershell
Remove-LocalGroupMember -Group "Administrators" -Member "LabTestUser"
Add-LocalGroupMember -Group "Administrators" -Member "LabTestUser"
```

## Analyst Interpretation
Membership changes to privileged local groups are important security events because they can grant elevated privileges. The member SID was used to identify the account when `MemberName` was not populated.

## Recommended Response
Confirm authorization, identify the actor and account, review nearby events, remove unauthorized privileged membership according to procedures, and investigate how the modification occurred.
