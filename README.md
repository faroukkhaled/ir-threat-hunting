# irforge: Incident Response and Threat Hunting Toolkit

A Python toolkit for hypothesis-driven threat hunting and incident response on Windows event data. Load Sysmon and Windows Security events, run a library of hunts, rebuild process trees, extract indicators, score hosts, track cases and generate an incident report.

Lab and portfolio project, built with AI assistance. `sample_data/` is synthetic (documentation IP ranges). `real_data/` holds real attack-emulation telemetry from the public OTRF Security-Datasets project (MIT licence), recorded in OTRF's lab. No employer, bank or customer data, and not production IR experience. Standard library only, Python 3.10+.

## What it does
| Command | Purpose |
|---------|---------|
| `irforge hunt events.csv` | Run 13 hunts, each mapped to MITRE ATT&CK, sorted by severity |
| `irforge list` | List hunts with technique, severity and hypothesis |
| `irforge tree events.csv --host WS01` | Process tree with flagged processes marked `[!]`, pruned to suspicious branches |
| `irforge iocs events.csv` | IPs, URLs, domains, hashes, and decoded PowerShell `-EncodedCommand` payloads |
| `irforge timeline events.csv` | Findings grouped into kill-chain phases |
| `irforge score events.csv` | Per-host risk score (severity weights plus a bonus for phase breadth) |
| `irforge report events.csv --format html --out r.html` | Markdown or HTML report (escaped, self-contained) |
| `irforge case new/list/note/status/show` | SQLite case manager for findings and analyst notes |
| `irforge simulate` | Generate a labelled multi-stage intrusion with benign noise |

## Quick start
```bash
python3 -m irforge simulate --out sample_data/intrusion.csv
python3 -m irforge hunt sample_data/intrusion.csv
python3 -m irforge tree sample_data/intrusion.csv --host WS01
python3 -m irforge report sample_data/intrusion.csv --out report.md
python3 -m unittest discover -s tests
```
A pre-built report for the sample is in `sample_data/intrusion-report.md`. The original `python3 hunt.py events.csv` still works.

## Running on real telemetry
```bash
python3 -m irforge import-otrf --dataset mimikatz_logonpasswords --out /tmp/mimi.csv   # or use the files in real_data/
python3 -m irforge hunt real_data/lsass_dump_comsvcs.csv
python3 -m irforge tree real_data/regsvr32_sct_launcher.csv --host WORKSTATION5
```
Real logs changed the hunts. `lsass-access` fired on `svchost.exe` (normal during logons) and `run-key-persistence` fired on Defender (`MsMpEng.exe`), so both are now allow-listed. Real LSASS dumps (comsvcs.dll via rundll32, Mimikatz from PowerShell) are still caught, and regsvr32, mshta and bitsadmin show up through `rare-parent-child`. Limits: no hunt targets those LOLBins by command line yet, and Mordor labs are small and clean compared with a real network.

## Hunts
Phishing macro (`office-spawns-shell`), `encoded-powershell`, `c2-port`, `run-key-persistence`, `lsass-access`, `kerberoasting`, `brute-force` (higher severity if followed by a success), `new-local-account`, `shadow-copy-delete`, plus statistical hunts:

- `beaconing`: groups outbound connections by host, process and destination and flags regular intervals using the coefficient of variation of the gaps. A monitoring agent with jittery polling is in the sample data to prove it is not flagged.
- `dga-dns`: Shannon entropy of DNS labels, several hits per host.
- `lateral-logons`: one account and source authenticating to many hosts in a short window.
- `rare-parent-child`: LOLBin started by a parent not in the baseline.

Add a hunt by writing one function with the `@hunt(name, technique, severity)` decorator in `irforge/hunts.py`. The docstring is the hypothesis and is shown by `irforge list`.

## Input format
CSV or JSON lines with: `time, host, user, event_id, image, parent_image, command_line, target, source_ip` and optional `pid, ppid` (enables exact process trees; otherwise links are inferred and marked approximate). Event ids: 1 process, 3 network, 10 process access, 13 registry, 22 DNS (Sysmon); 4624, 4625, 4720, 4769 (Security).

## Tests
26 unit tests cover each hunt on the simulation, near-miss benign cases (no false positives), IOC extraction including nested encoded payloads, tree pruning, scoring, HTML escaping and the case store.

## Layout
- `irforge/` library and CLI
- `sample_data/` original 16-row chain (`events.csv`), generated `intrusion.csv`, sample report
- `hunts/` Sigma rule and Splunk queries
- `playbooks/`, `templates/` NIST 800-61 IR playbook and report template
- `tests/`

## Limitations
Hunts are heuristics. Thresholds need tuning per environment and the process tree needs pid data to be exact. Not a replacement for an EDR.
