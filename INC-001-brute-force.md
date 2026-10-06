# INC-001 — Brute Force / Multiple Failed Logons

## Summary
A controlled brute-force simulation was performed against the local Windows account `LabTestUser`. Three failed authentication attempts were generated within a five-minute window.

## Detection
**Detection:** D1 - Brute Force Multiple Failed Logons  
**MITRE ATT&CK:** T1110 - Brute Force

```spl
index=endpoint_security "<EventID>4625</EventID>"
| rex field=_raw "<Data Name='TargetUserName'>(?<User>[^<]+)"
| rex field=_raw "<Data Name='IpAddress'>(?<SourceIP>[^<]+)"
| bin _time span=5m
| stats count as FailedAttempts by _time User SourceIP
| where FailedAttempts >= 3
| sort - _time
```

## Evidence
- User: `LabTestUser`
- Failed attempts: `3`
- Source: `::1` (IPv6 loopback)
- Window: 5 minutes
- Windows Event ID: `4625`

## Simulation
```powershell
$Password = ConvertTo-SecureString "WrongPassword123!" -AsPlainText -Force
$Credential = New-Object System.Management.Automation.PSCredential(".\LabTestUser",$Password)
1..3 | ForEach-Object {
    Start-Process -FilePath "cmd.exe" -ArgumentList "/c","exit" -Credential $Credential -ErrorAction SilentlyContinue
}
```

## Analyst Interpretation
Repeated failed logons were aggregated into a short time window and detected as a brute-force pattern.

## Recommended Response
Validate the account and source, review surrounding authentication events, apply appropriate containment if unauthorized, and preserve relevant logs.
