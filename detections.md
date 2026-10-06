# Detection Engineering

## D1 — Brute Force Multiple Failed Logons
```spl
index=endpoint_security "<EventID>4625</EventID>"
| bin _time span=5m
| stats count as FailedAttempts by _time
| where FailedAttempts >= 3
```
MITRE ATT&CK: T1110

## D2 — Suspicious PowerShell
```spl
index=endpoint_sysmon "<EventID>1</EventID>"
| rex field=_raw "<Data Name='CommandLine'>(?<CommandLine>[^<]+)"
| search CommandLine="*-EncodedCommand*" OR CommandLine="*FromBase64String*" OR CommandLine="*Invoke-Expression*" OR CommandLine="*DownloadString*"
| table _time host CommandLine
```
MITRE ATT&CK: T1059.001

## D3 — Privilege Escalation via Group Modification
```spl
index=endpoint_security "<EventID>4732</EventID>"
| rex field=_raw "<Data Name='SubjectUserName'>(?<Actor>[^<]+)"
| rex field=_raw "<Data Name='TargetUserName'>(?<TargetGroup>[^<]+)"
| rex field=_raw "<Data Name='MemberSid'>(?<MemberSID>[^<]+)"
| table _time host Actor TargetGroup MemberSID
```
MITRE ATT&CK: T1098

## D4 — Suspicious Parent-Child Process
```spl
index=endpoint_sysmon "<EventID>1</EventID>"
| rex field=_raw "<Data Name='ParentImage'>(?<ParentImage>[^<]+)"
| rex field=_raw "<Data Name='Image'>(?<Image>[^<]+)"
| where (match(ParentImage,"(?i)winword\.exe$") AND match(Image,"(?i)powershell\.exe$")) OR (match(ParentImage,"(?i)excel\.exe$") AND match(Image,"(?i)powershell\.exe$")) OR (match(ParentImage,"(?i)outlook\.exe$") AND match(Image,"(?i)powershell\.exe$")) OR (match(ParentImage,"(?i)powershell\.exe$") AND match(Image,"(?i)cmd\.exe$")) OR (match(ParentImage,"(?i)w3wp\.exe$") AND match(Image,"(?i)(cmd|powershell)\.exe$"))
| table _time host ParentImage Image
```
MITRE ATT&CK: T1059

## D5 — Scheduled Task Persistence
```spl
index=endpoint_security "<EventID>4698</EventID>"
| rex field=_raw "<Data Name='TaskName'>(?<TaskName>[^<]+)"
| rex field=_raw "<Data Name='SubjectUserName'>(?<User>[^<]+)"
| table _time host User TaskName
```
MITRE ATT&CK: T1053.005
