"""Hunt library. Each hunt is a generator registered with @hunt and returns Finding objects.

Hunts are hypothesis driven: the docstring states the hypothesis, the ATT&CK technique and what a
false positive looks like. Add a hunt by writing one function and decorating it.
"""
import re
from collections import defaultdict
from datetime import timedelta

from .models import Finding
from .util import entropy, mean, stdev

REGISTRY = {}

OFFICE = ("winword.exe", "excel.exe", "outlook.exe", "powerpnt.exe")
INTERPRETERS = ("powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe")
LOLBINS = INTERPRETERS + ("certutil.exe", "bitsadmin.exe", "schtasks.exe", "wmic.exe", "msbuild.exe", "installutil.exe")
DEFAULT_BASELINE = {
    ("explorer.exe", "cmd.exe"), ("explorer.exe", "powershell.exe"), ("services.exe", "svchost.exe"),
    ("cmd.exe", "ipconfig.exe"), ("svchost.exe", "powershell.exe"),
}


def hunt(name, technique, severity):
    def deco(fn):
        fn.hunt_name, fn.technique, fn.severity = name, technique, severity
        REGISTRY[name] = fn
        return fn
    return deco


def _f(fn, events, msg, **ev):
    return Finding(fn.hunt_name, fn.technique, fn.severity, msg, events, ev)


@hunt("office-spawns-shell", "T1204.002", "high")
def office_spawns_shell(events, **_):
    """Hypothesis: a macro or exploit makes an Office process start a script interpreter."""
    for e in events:
        if e.event_id == 1 and e.parent_exe in OFFICE and e.exe in INTERPRETERS:
            yield _f(office_spawns_shell, [e], "%s spawned %s" % (e.parent_exe, e.exe))


@hunt("encoded-powershell", "T1059.001", "high")
def encoded_powershell(events, **_):
    """Hypothesis: attackers hide PowerShell payloads with -EncodedCommand."""
    pat = re.compile(r"\s-(e|ec|enc|encodedcommand)\s", re.I)
    for e in events:
        if e.event_id == 1 and "powershell" in e.command_line.lower() and pat.search(e.command_line + " "):
            yield _f(encoded_powershell, [e], "Encoded PowerShell command line")


@hunt("c2-port", "T1071", "medium")
def c2_port(events, ports=(4444, 1337, 8888, 9001), **_):
    """Hypothesis: implants use well-known framework ports. FP: developer tools on those ports."""
    groups = defaultdict(list)
    for e in events:
        if e.event_id == 3 and e.target.rsplit(":", 1)[-1] in {str(p) for p in ports}:
            groups[(e.host, e.exe, e.target)].append(e)
    for (host, exe, dest), evs in groups.items():
        yield _f(c2_port, evs, "%s on %s connected to %s (%d times)" % (exe, host, dest, len(evs)), dest=dest, count=len(evs))


@hunt("run-key-persistence", "T1547.001", "medium")
def run_key(events, **_):
    """Hypothesis: persistence through a Run key set by a process in a user-writable path."""
    for e in events:
        if e.event_id == 13 and "currentversion\\run" in e.target.lower():
            tmp = "\\temp\\" in e.image.lower() or "\\appdata\\" in e.image.lower()
            yield _f(run_key, [e], "Run key set by %s%s" % (e.exe, " (user-writable path)" if tmp else ""))


@hunt("lsass-access", "T1003.001", "high")
def lsass_access(events, **_):
    """Hypothesis: credential dumping opens LSASS. FP: AV and EDR agents (allow-list them)."""
    allow = ("msmpeng.exe", "csrss.exe", "wininit.exe")
    for e in events:
        if e.event_id == 10 and e.target.lower().endswith("lsass.exe") and e.exe not in allow:
            yield _f(lsass_access, [e], "%s accessed LSASS" % e.exe)


@hunt("kerberoasting", "T1558.003", "high")
def kerberoasting(events, threshold=3, window=60, **_):
    """Hypothesis: many RC4 (0x17) service ticket requests from one source in a short time."""
    by_src = defaultdict(list)
    for e in events:
        if e.event_id == 4769 and "0x17" in e.target:
            by_src[e.source_ip].append(e)
    for src, evs in by_src.items():
        for i in range(len(evs)):
            grp = [x for x in evs[i:] if (x.time - evs[i].time).total_seconds() <= window]
            if len(grp) >= threshold:
                yield _f(kerberoasting, grp, "%d RC4 service tickets from %s in %ds" % (len(grp), src, window), source=src)
                break


@hunt("brute-force", "T1110", "medium")
def brute_force(events, threshold=5, window=120, **_):
    """Hypothesis: many failed logons from one source, optionally followed by a success."""
    by_src = defaultdict(list)
    for e in events:
        if e.event_id in (4625, 4624):
            by_src[e.source_ip].append(e)
    for src, evs in by_src.items():
        fails = [e for e in evs if e.event_id == 4625]
        for i in range(len(fails)):
            grp = [x for x in fails[i:] if (x.time - fails[i].time).total_seconds() <= window]
            if len(grp) >= threshold:
                later_ok = [e for e in evs if e.event_id == 4624 and e.time > grp[-1].time and e.user == grp[-1].user]
                sev = "high" if later_ok else "medium"
                f = _f(brute_force, grp + later_ok[:1], "%d failed logons from %s%s" % (len(grp), src, " then a success" if later_ok else ""), source=src)
                f.severity = sev
                yield f
                break


@hunt("new-local-account", "T1136.001", "medium")
def new_local_account(events, **_):
    """Hypothesis: attackers create a backdoor account (event 4720)."""
    for e in events:
        if e.event_id == 4720:
            yield _f(new_local_account, [e], "Account created: %s" % e.target)


@hunt("beaconing", "T1071.001", "high")
def beaconing(events, min_conns=8, max_cv=0.25, min_interval=5, **_):
    """Hypothesis: implants call home on a timer. Regular intervals (low coefficient of variation)
    to one destination from one process look like a beacon. FP: update checkers, monitoring agents."""
    groups = defaultdict(list)
    for e in events:
        if e.event_id == 3:
            groups[(e.host, e.exe, e.target)].append(e)
    for (host, exe, dest), evs in groups.items():
        if len(evs) < min_conns:
            continue
        gaps = [(b.time - a.time).total_seconds() for a, b in zip(evs, evs[1:])]
        m = mean(gaps)
        if m < min_interval:
            continue
        cv = stdev(gaps) / m if m else 1
        if cv <= max_cv:
            yield _f(beaconing, evs, "%s on %s contacts %s every ~%.0fs (%d conns, cv=%.2f)" % (exe, host, dest, m, len(evs), cv),
                     interval=round(m, 1), cv=round(cv, 3), connections=len(evs), dest=dest)


@hunt("dga-dns", "T1568.002", "medium")
def dga_dns(events, min_len=12, min_entropy=3.3, min_hits=3, **_):
    """Hypothesis: domain generation algorithms produce long, high-entropy labels, many per host."""
    by_host = defaultdict(list)
    for e in events:
        if e.event_id == 22:
            label = e.target.split(".")[0]
            if len(label) >= min_len and entropy(label) >= min_entropy:
                by_host[e.host].append(e)
    for host, evs in by_host.items():
        if len(evs) >= min_hits:
            yield _f(dga_dns, evs, "%d high-entropy DNS names queried by %s (e.g. %s)" % (len(evs), host, evs[0].target), host=host)


@hunt("lateral-logons", "T1021", "high")
def lateral_logons(events, min_hosts=4, window=600, **_):
    """Hypothesis: one account/source authenticating to many hosts quickly is lateral movement."""
    by_key = defaultdict(list)
    for e in events:
        if e.event_id == 4624 and e.target == "3" and e.source_ip:
            by_key[(e.user, e.source_ip)].append(e)
    for (user, src), evs in by_key.items():
        for i in range(len(evs)):
            grp = [x for x in evs[i:] if (x.time - evs[i].time).total_seconds() <= window]
            hosts = {x.host for x in grp}
            if len(hosts) >= min_hosts:
                yield _f(lateral_logons, grp, "%s logged on to %d hosts from %s within %ds" % (user, len(hosts), src, window),
                         hosts=sorted(hosts))
                break


@hunt("rare-parent-child", "T1218", "medium")
def rare_parent_child(events, baseline=None, **_):
    """Hypothesis: a LOLBin started by a parent never seen in the baseline is worth a look."""
    base = set(baseline) if baseline is not None else DEFAULT_BASELINE
    seen = set()
    for e in events:
        if e.event_id == 1 and e.exe in LOLBINS:
            pair = (e.parent_exe, e.exe)
            if pair not in base and pair not in seen and e.parent_exe not in OFFICE:
                seen.add(pair)
                yield _f(rare_parent_child, [e], "Unusual parent/child: %s -> %s" % pair, pair=pair)


@hunt("shadow-copy-delete", "T1490", "critical")
def shadow_copy_delete(events, **_):
    """Hypothesis: ransomware deletes shadow copies before encrypting."""
    for e in events:
        c = e.command_line.lower()
        if e.event_id == 1 and (("vssadmin" in c and "delete" in c and "shadows" in c) or ("wmic" in c and "shadowcopy" in c and "delete" in c)):
            yield _f(shadow_copy_delete, [e], "Shadow copies deleted on %s" % e.host)


def run_all(events, only=None, **opts):
    findings = []
    for name, fn in REGISTRY.items():
        if only and name not in only:
            continue
        findings.extend(fn(events, **opts))
    sev = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    return sorted(findings, key=lambda f: (sev.get(f.severity, 9), f.time))
