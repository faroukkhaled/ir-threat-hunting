# Incident Response & Threat Hunting

A small toolkit for practising incident response and hypothesis-driven threat hunting on Windows event data.

- `hunt.py` runs 8 hunts (encoded PowerShell, Office spawning shells, LSASS access, Run-key persistence, Kerberoasting, brute force, new local accounts, C2 port) over a CSV and maps findings to MITRE ATT&CK. Standard library only.
- `sample_data/events.csv` a synthetic attack chain: phishing macro, PowerShell, persistence, credential access, Kerberoasting, brute force, backdoor account.
- `hunts/` a Sigma rule and example Splunk queries.
- `playbooks/` IR playbook following NIST 800-61.
- `templates/` incident report template.

```
python3 hunt.py sample_data/events.csv
```
All data is synthetic.
