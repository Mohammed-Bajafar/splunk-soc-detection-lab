# INC-002 — Suspicious PowerShell

## Summary
A controlled PowerShell test using `-EncodedCommand` was executed. Sysmon process-creation telemetry and PowerShell Script Block Logging captured the activity.

## Detection
**Detection:** D2 - Suspicious PowerShell  
**MITRE ATT&CK:** T1059.001 - PowerShell

```spl
index=endpoint_sysmon "<EventID>1</EventID>"
| rex field=_raw "<Data Name='CommandLine'>(?<CommandLine>[^<]+)"
| search CommandLine="*-EncodedCommand*" OR CommandLine="*FromBase64String*" OR CommandLine="*Invoke-Expression*" OR CommandLine="*DownloadString*"
| table _time host CommandLine
| sort - _time
```

## Evidence
- Event ID: `1`
- Image: `powershell.exe`
- Indicator: `-EncodedCommand`
- Host: `Mohammed`
- Time: `2026-09-23 04:23:14`
- PowerShell Script Block Event ID: `4104`
- 4104 time: `2026-09-23 04:23:14.443`

## Simulation
```powershell
powershell.exe -EncodedCommand VwByAGkAdABlAC0ATwB1AHQAcAB1AHQAIABEADIAVAAgAFQARQBTAFQ=
```

## Analyst Interpretation
The test demonstrates correlation of endpoint process telemetry with PowerShell logging. Encoded PowerShell is a useful hunting indicator because it can make command-line activity less immediately readable.

## Recommended Response
Validate parent process and command line, review 4104 events, identify the user and host, search for related activity, and contain the endpoint if malicious activity is confirmed.
