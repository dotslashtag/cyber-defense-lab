# EVTX Hunter triage report

- **Inputs:** `op002-style-archives.json`
- **Events parsed:** 26 from 2 host(s): `WIN11-OPS01.soc.lab`, `Win10.soc.lab`
- **Time range (UTC):** 2026-09-28 08:00:00 → 2026-09-28 09:20:00
- **Findings:** 6 (2 high, 4 medium)

## Timeline of findings

| Time (UTC) | Host | Level | Finding | ATT&CK | Key evidence |
|---|---|---|---|---|---|
| 2026-09-28 09:10:05 | WIN11-OPS01.soc.lab | medium | Clustered Native Discovery Activity | T1033, T1082, T1016, T1057, T1087.001, T1087.002, T1018 | `9 events: NETSTAT.EXE, ROUTE.EXE, ipconfig.exe, net.exe, quser.exe, systeminfo.exe, tasklist.exe, whoami.exe` |
| 2026-09-28 09:12:00 | WIN11-OPS01.soc.lab | medium | Run/RunOnce Key Modified By Script Host Or LOLBin | T1547.001 | `HKU\S-1-5-21-1111111111-2222222222-3333333333-1105\Software\Microsoft\Windows\CurrentVersion\Run\OP002Persist` |
| 2026-09-28 09:15:00 | WIN11-OPS01.soc.lab | medium | PowerShell Launched With ExecutionPolicy Bypass | T1059.001 | `powershell.exe -ep bypass -nop -c "iex (gc C:\Users\Public\s.ps1 -raw)"` |
| 2026-09-28 09:15:10 | WIN11-OPS01.soc.lab | high | Rundll32 Spawned By PowerShell | T1218.011, T1059.001 | `rundll32.exe C:\Users\Public\helper.dll,Start` |
| 2026-09-28 09:16:30 | WIN11-OPS01.soc.lab | high | Defender Tamper Protection Blocked A Configuration Change | T1562.001 | `HKLM\SOFTWARE\Microsoft\Windows Defender\Real-Time Protection\DisableRealtimeMonitoring = 0x1` |
| 2026-09-28 09:20:00 | Win10.soc.lab | medium | Workstation-To-Workstation Network Logon | T1021.002, T1550.002, T1078 | `10.10.2.9` |

## Process tree around the findings

Ancestors and descendants of every process involved in a finding. ◀ marks the finding.

```text
(userinit.exe) [WIN11-OPS01.soc.lab]
  └─ 08:00:00 explorer.exe  C:\Windows\Explorer.EXE
     └─ 09:10:00 cmd.exe  "C:\Windows\system32\cmd.exe"
        ├─ 09:10:05 whoami.exe  whoami /all  ◀ Clustered Native Discovery Activity
        ├─ 09:10:09 systeminfo.exe  systeminfo  ◀ Clustered Native Discovery Activity
        ├─ 09:10:14 ipconfig.exe  ipconfig /all  ◀ Clustered Native Discovery Activity
        ├─ 09:10:18 net.exe  net user  ◀ Clustered Native Discovery Activity
        ├─ 09:10:22 net.exe  net localgroup administrators  ◀ Clustered Native Discovery Activity
        ├─ 09:10:27 tasklist.exe  tasklist /v  ◀ Clustered Native Discovery Activity
        ├─ 09:10:31 quser.exe  quser  ◀ Clustered Native Discovery Activity
        ├─ 09:10:35 ROUTE.EXE  route print  ◀ Clustered Native Discovery Activity
        ├─ 09:10:40 NETSTAT.EXE  netstat -ano  ◀ Clustered Native Discovery Activity
        ├─ 09:12:00 reg.exe  reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v OP002Persist /t REG_SZ /d C:\…  ◀ Run/RunOnce Key Modified By Script Host Or LOLBin
        └─ 09:15:00 powershell.exe  powershell.exe -ep bypass -nop -c "iex (gc C:\Users\Public\s.ps1 -raw)"  ◀ PowerShell Launched With ExecutionPolicy Bypass
           └─ 09:15:10 rundll32.exe  rundll32.exe C:\Users\Public\helper.dll,Start  ◀ Rundll32 Spawned By PowerShell
```

## Findings in detail

### 1. Clustered Native Discovery Activity

- **Level:** medium · **ATT&CK:** T1033, T1082, T1016, T1057, T1087.001, T1087.002, T1018 · **Rule ID:** `a5f6ee1a-bc24-488f-a50c-0261fc690e24`
- **Host:** `WIN11-OPS01.soc.lab` · **First event:** 2026-09-28 09:10:05 · **Events in window:** 9

- 2026-09-28 09:10:05 · EventID 1 · Image=`C:\Windows\System32\whoami.exe`, CommandLine=`whoami /all`, ParentImage=`C:\Windows\System32\cmd.exe` _(source: op002-style-archives.json:9)_
- 2026-09-28 09:10:09 · EventID 1 · Image=`C:\Windows\System32\systeminfo.exe`, CommandLine=`systeminfo`, ParentImage=`C:\Windows\System32\cmd.exe` _(source: op002-style-archives.json:10)_
- 2026-09-28 09:10:14 · EventID 1 · Image=`C:\Windows\System32\ipconfig.exe`, CommandLine=`ipconfig /all`, ParentImage=`C:\Windows\System32\cmd.exe` _(source: op002-style-archives.json:11)_
- 2026-09-28 09:10:18 · EventID 1 · Image=`C:\Windows\System32\net.exe`, CommandLine=`net user`, ParentImage=`C:\Windows\System32\cmd.exe` _(source: op002-style-archives.json:12)_
- 2026-09-28 09:10:22 · EventID 1 · Image=`C:\Windows\System32\net.exe`, CommandLine=`net localgroup administrators`, ParentImage=`C:\Windows\System32\cmd.exe` _(source: op002-style-archives.json:13)_
- 2026-09-28 09:10:27 · EventID 1 · Image=`C:\Windows\System32\tasklist.exe`, CommandLine=`tasklist /v`, ParentImage=`C:\Windows\System32\cmd.exe` _(source: op002-style-archives.json:14)_
- 2026-09-28 09:10:31 · EventID 1 · Image=`C:\Windows\System32\quser.exe`, CommandLine=`quser`, ParentImage=`C:\Windows\System32\cmd.exe` _(source: op002-style-archives.json:15)_
- 2026-09-28 09:10:35 · EventID 1 · Image=`C:\Windows\System32\ROUTE.EXE`, CommandLine=`route print`, ParentImage=`C:\Windows\System32\cmd.exe` _(source: op002-style-archives.json:16)_
- 2026-09-28 09:10:40 · EventID 1 · Image=`C:\Windows\System32\NETSTAT.EXE`, CommandLine=`netstat -ano`, ParentImage=`C:\Windows\System32\cmd.exe` _(source: op002-style-archives.json:17)_

### 2. Run/RunOnce Key Modified By Script Host Or LOLBin

- **Level:** medium · **ATT&CK:** T1547.001 · **Rule ID:** `b340352c-cceb-40dd-be59-a2dfb3caab6a`
- **Host:** `WIN11-OPS01.soc.lab` · **First event:** 2026-09-28 09:12:00

- 2026-09-28 09:12:00 · EventID 13 · Image=`C:\Windows\System32\reg.exe`, TargetObject=`HKU\S-1-5-21-1111111111-2222222222-3333333333-1105\Software\Microsoft\Windows\CurrentVersion\Run\OP002Persist`, Details=`C:\Users\Public\sync.exe` _(source: op002-style-archives.json:19)_

### 3. PowerShell Launched With ExecutionPolicy Bypass

- **Level:** medium · **ATT&CK:** T1059.001 · **Rule ID:** `8f72d91e-c593-4b45-8542-9e886d948155`
- **Host:** `WIN11-OPS01.soc.lab` · **First event:** 2026-09-28 09:15:00

- 2026-09-28 09:15:00 · EventID 1 · Image=`C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`, CommandLine=`powershell.exe -ep bypass -nop -c "iex (gc C:\Users\Public\s.ps1 -raw)"`, ParentImage=`C:\Windows\System32\cmd.exe` _(source: op002-style-archives.json:20)_

### 4. Rundll32 Spawned By PowerShell

- **Level:** high · **ATT&CK:** T1218.011, T1059.001 · **Rule ID:** `66c4add3-8deb-4078-87f8-4b7a8a545398`
- **Host:** `WIN11-OPS01.soc.lab` · **First event:** 2026-09-28 09:15:10

- 2026-09-28 09:15:10 · EventID 1 · Image=`C:\Windows\System32\rundll32.exe`, CommandLine=`rundll32.exe C:\Users\Public\helper.dll,Start`, ParentImage=`C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe` _(source: op002-style-archives.json:21)_

### 5. Defender Tamper Protection Blocked A Configuration Change

- **Level:** high · **ATT&CK:** T1562.001 · **Rule ID:** `a4d2e069-cfb1-4840-853d-850a34a3a4d3`
- **Host:** `WIN11-OPS01.soc.lab` · **First event:** 2026-09-28 09:16:30

- 2026-09-28 09:16:30 · EventID 5013 · Value=`HKLM\SOFTWARE\Microsoft\Windows Defender\Real-Time Protection\DisableRealtimeMonitoring = 0x1` _(source: op002-style-archives.json:23)_

### 6. Workstation-To-Workstation Network Logon

- **Level:** medium · **ATT&CK:** T1021.002, T1550.002, T1078 · **Rule ID:** `15a7687e-950f-422b-9922-a946500cf3bf`
- **Host:** `Win10.soc.lab` · **First event:** 2026-09-28 09:20:00

- 2026-09-28 09:20:00 · EventID 4624 · TargetUserName=`labuser`, IpAddress=`10.10.2.9`, LogonType=`3` _(source: op002-style-archives.json:26)_

## Suggested next steps

1. Confirm or rule out each finding against the host's normal activity.
2. Scope it: search for the same command lines, Run values and source IPs on other hosts.
3. If confirmed, open a case and request containment through the approval workflow.

