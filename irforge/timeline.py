"""Build an incident timeline: findings first, grouped into kill-chain phases."""
from .hunts import REGISTRY

TACTIC_BY_TECH = {
    "T1204.002": "Initial Access", "T1059.001": "Execution", "T1071": "Command and Control",
    "T1071.001": "Command and Control", "T1568.002": "Command and Control", "T1547.001": "Persistence",
    "T1003.001": "Credential Access", "T1558.003": "Credential Access", "T1110": "Credential Access",
    "T1136.001": "Persistence", "T1021": "Lateral Movement", "T1218": "Defense Evasion", "T1490": "Impact",
}
PHASE_ORDER = ["Initial Access", "Execution", "Persistence", "Defense Evasion", "Credential Access",
               "Discovery", "Lateral Movement", "Command and Control", "Impact"]


def tactic(f):
    return TACTIC_BY_TECH.get(f.technique, "Other")


def build(findings):
    rows = []
    for f in sorted(findings, key=lambda f: f.time):
        rows.append({
            "time": f.time, "host": f.host, "phase": tactic(f), "severity": f.severity,
            "technique": f.technique, "hunt": f.hunt, "message": f.message,
        })
    return rows


def phases(findings):
    seen = {tactic(f) for f in findings}
    return [p for p in PHASE_ORDER if p in seen] + sorted(seen - set(PHASE_ORDER))


def dwell(findings):
    """Seconds between first and last finding, a rough measure of how long the intrusion ran."""
    if not findings:
        return 0
    ts = [f.time for f in findings]
    return int((max(ts) - min(ts)).total_seconds())
