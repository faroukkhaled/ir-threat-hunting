# ir-threat-hunting: Hunts

Hunts in `irforge/hunts.py`, with the technique id and severity set in code. The hypothesis text is each hunt's docstring.

| Hunt | Severity | ATT&CK | Hypothesis and false-positive notes |
|---|---|---|---|
| office-spawns-shell | high | T1204.002 | Hypothesis: a macro or exploit makes an Office process start a script interpreter. |
| encoded-powershell | high | T1059.001 | Hypothesis: attackers hide PowerShell payloads with -EncodedCommand. |
| c2-port | medium | T1071 | Hypothesis: implants use well-known framework ports. FP: developer tools on those ports. |
| run-key-persistence | medium | T1547.001 | Hypothesis: persistence through a Run key set by a process in a user-writable path. |
| lsass-access | high | T1003.001 | Hypothesis: credential dumping opens LSASS. FP: AV and EDR agents (allow-list them). |
| kerberoasting | high | T1558.003 | Hypothesis: many RC4 (0x17) service ticket requests from one source in a short time. |
| brute-force | medium | T1110 | Hypothesis: many failed logons from one source, optionally followed by a success. |
| new-local-account | medium | T1136.001 | Hypothesis: attackers create a backdoor account (event 4720). |
| beaconing | high | T1071.001 | Hypothesis: implants call home on a timer. Regular intervals (low coefficient of variation) to one destination from one process look like a beacon. FP: update checkers, monitoring agents. |
| dga-dns | medium | T1568.002 | Hypothesis: domain generation algorithms produce long, high-entropy labels, many per host. |
| lateral-logons | high | T1021 | Hypothesis: one account/source authenticating to many hosts quickly is lateral movement. |
| rare-parent-child | medium | T1218 | Hypothesis: a LOLBin started by a parent never seen in the baseline is worth a look. |
| shadow-copy-delete | critical | T1490 | Hypothesis: ransomware deletes shadow copies before encrypting. |

Limits: rules are teaching-grade and untuned for any real environment. See the Scope and limits section of the README.
