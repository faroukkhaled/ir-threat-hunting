"""Host risk scoring: weighted by severity, with a bonus for breadth of kill-chain phases."""
from collections import defaultdict

from .timeline import tactic

WEIGHT = {"critical": 40, "high": 25, "medium": 10, "low": 3}


def host_scores(findings):
    by_host = defaultdict(list)
    for f in findings:
        by_host[f.host].append(f)
    out = []
    for host, fs in by_host.items():
        base = sum(WEIGHT.get(f.severity, 1) for f in fs)
        phases = len({tactic(f) for f in fs})
        score = min(100, base + 5 * max(0, phases - 1))
        label = "critical" if score >= 80 else "high" if score >= 50 else "medium" if score >= 20 else "low"
        out.append({"host": host, "score": score, "label": label, "findings": len(fs), "phases": phases})
    return sorted(out, key=lambda r: -r["score"])
