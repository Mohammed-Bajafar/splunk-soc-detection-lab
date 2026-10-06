# Threat Hunting

## Hunt 1 — Encoded PowerShell
```spl
index=endpoint_sysmon "<EventID>1</EventID>"
| rex field=_raw "<Data Name='CommandLine'>(?<CommandLine>[^<]+)"
| search CommandLine="*-EncodedCommand*"
| table _time host CommandLine
```
Result: one real encoded-PowerShell event was observed during the controlled test.

## Hunt 2 — PowerShell → CMD
```spl
index=endpoint_sysmon "<EventID>1</EventID>"
| rex field=_raw "<Data Name='ParentImage'>(?<ParentImage>[^<]+)"
| rex field=_raw "<Data Name='Image'>(?<Image>[^<]+)"
| search ParentImage="*powershell.exe" Image="*cmd.exe"
| table _time host ParentImage Image
```
Result: two events were observed during testing.

## Hunt 3 — Scheduled Tasks
```spl
index=endpoint_security "<EventID>4698</EventID>"
| rex field=_raw "<Data Name='TaskName'>(?<TaskName>[^<]+)"
| rex field=_raw "<Data Name='SubjectUserName'>(?<User>[^<]+)"
| table _time host User TaskName
```
Result: two scheduled-task creation events were observed.

## Hunt 4 — Failed Logons
```spl
index=endpoint_security "<EventID>4625</EventID>"
| rex field=_raw "<Data Name='TargetUserName'>(?<User>[^<]+)"
| rex field=_raw "<Data Name='IpAddress'>(?<SourceIP>[^<]+)"
| stats count by host User SourceIP
| sort - count
```
Result: seven failed-logon events were observed in the investigated data.

## Hunt 5 — Group Modifications
```spl
index=endpoint_security "<EventID>4732</EventID>"
| rex field=_raw "<Data Name='SubjectUserName'>(?<Actor>[^<]+)"
| rex field=_raw "<Data Name='MemberName'>(?<Member>[^<]+)"
| rex field=_raw "<Data Name='TargetUserName'>(?<TargetGroup>[^<]+)"
| table _time host Actor Member TargetGroup
```
Result: three group-modification events were observed in the investigated data.
