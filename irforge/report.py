"""Incident report as Markdown or a self-contained HTML page (all values HTML-escaped)."""
import html

from . import iocs, scoring, timeline, tree


def _flagged_events(findings):
    seen, out = set(), []
    for f in findings:
        for e in f.events:
            if id(e) not in seen:
                seen.add(id(e))
                out.append(e)
    return out


def _summary(findings):
    sev = {}
    for f in findings:
        sev[f.severity] = sev.get(f.severity, 0) + 1
    return sev


def markdown(events, findings, title="Incident report"):
    ioc = iocs.extract(_flagged_events(findings))
    scores = scoring.host_scores(findings)
    out = ["# %s" % title, ""]
    out.append("Events analysed: %d. Findings: %d (%s)." % (
        len(events), len(findings), ", ".join("%d %s" % (v, k) for k, v in sorted(_summary(findings).items())) or "none"))
    out.append("Kill-chain phases seen: %s. Span of findings: %ds." % (", ".join(timeline.phases(findings)) or "none", timeline.dwell(findings)))
    out += ["", "## Host risk", "", "| Host | Score | Level | Findings | Phases |", "|---|---|---|---|---|"]
    for s in scores:
        out.append("| %(host)s | %(score)d | %(label)s | %(findings)d | %(phases)d |" % s)
    out += ["", "## Timeline", "", "| Time | Host | Phase | Severity | Technique | Detail |", "|---|---|---|---|---|---|"]
    for r in timeline.build(findings):
        out.append("| %s | %s | %s | %s | %s | %s |" % (r["time"].strftime("%Y-%m-%d %H:%M:%S"), r["host"], r["phase"], r["severity"], r["technique"], r["message"].replace("|", "/")))
    out += ["", "## Indicators of compromise", ""]
    for k in ("ips", "domains", "urls", "hashes"):
        out.append("- %s: %s" % (k, ", ".join(ioc[k]) or "none"))
    if ioc["decoded"]:
        out += ["", "Decoded PowerShell payloads:", ""]
        out += ["    " + d for d in ioc["decoded"]]
    flagged = {id(e) for f in findings for e in f.events}
    t = tree.build(events)
    out += ["", "## Process tree", "", "```", tree.render(t, flagged, only_flagged=True), "```", ""]
    out += ["## Recommended next steps", "",
            "1. Isolate hosts rated high or critical and preserve memory and disk before rebooting.",
            "2. Block the IP addresses and domains above at the firewall and DNS layer.",
            "3. Reset credentials for accounts seen on affected hosts, and for any account exposed to LSASS access or Kerberoasting.",
            "4. Remove persistence (Run keys, scheduled tasks, new accounts) found in the timeline.",
            "5. Scope: search all hosts for the IOCs and the same parent/child patterns.", ""]
    return "\n".join(out)


def html_report(events, findings, title="Incident report"):
    e = html.escape
    ioc = iocs.extract(_flagged_events(findings))
    rows = "".join(
        "<tr class='%s'><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>" % (
            e(r["severity"]), e(r["time"].strftime("%H:%M:%S")), e(r["host"]), e(r["phase"]), e(r["severity"]), e(r["technique"]), e(r["message"]))
        for r in timeline.build(findings))
    hosts = "".join("<tr><td>%s</td><td>%d</td><td>%s</td></tr>" % (e(s["host"]), s["score"], e(s["label"])) for s in scoring.host_scores(findings))
    flagged = {id(x) for f in findings for x in f.events}
    pre = e(tree.render(tree.build(events), flagged, only_flagged=True))
    iochtml = "".join("<li><b>%s</b>: %s</li>" % (e(k), e(", ".join(ioc[k]) or "none")) for k in ("ips", "domains", "urls", "hashes"))
    return """<!doctype html><meta charset="utf-8"><title>%s</title>
<style>body{font:14px system-ui;margin:2rem;max-width:1000px}table{border-collapse:collapse;width:100%%}td,th{border:1px solid #ccc;padding:4px 8px;text-align:left}
tr.critical td{background:#f8d7da}tr.high td{background:#ffe5d0}tr.medium td{background:#fff3cd}pre{background:#f4f4f4;padding:1rem;overflow:auto}</style>
<h1>%s</h1><p>%d events, %d findings. Phases: %s.</p>
<h2>Host risk</h2><table><tr><th>Host</th><th>Score</th><th>Level</th></tr>%s</table>
<h2>Timeline</h2><table><tr><th>Time</th><th>Host</th><th>Phase</th><th>Severity</th><th>Technique</th><th>Detail</th></tr>%s</table>
<h2>Indicators</h2><ul>%s</ul><h2>Process tree</h2><pre>%s</pre>""" % (
        e(title), e(title), len(events), len(findings), e(", ".join(timeline.phases(findings)) or "none"), hosts, rows, iochtml, pre)
