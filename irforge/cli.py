import argparse
import json
import sys

from . import case as case_mod, hunts, iocs, report, scoring, simulate, timeline, tree
from .models import load_events


def _load(a):
    ev = load_events(a.events)
    only = set(a.only.split(",")) if getattr(a, "only", None) else None
    return ev, hunts.run_all(ev, only=only)


def cmd_hunt(a):
    ev, fs = _load(a)
    if a.json:
        print(json.dumps([{"hunt": f.hunt, "technique": f.technique, "severity": f.severity, "host": f.host,
                           "time": f.time.isoformat(), "message": f.message} for f in fs], indent=2))
    else:
        for f in fs:
            print("[%-8s] %s %-5s %-20s %-10s %s" % (f.severity.upper(), f.time.strftime("%H:%M:%S"), f.host, f.hunt, f.technique, f.message))
        print("\n%d findings from %d events (%d hunts)" % (len(fs), len(ev), len(hunts.REGISTRY)))
    return 0


def cmd_list(a):
    for name, fn in hunts.REGISTRY.items():
        print("%-22s %-10s %-8s %s" % (name, fn.technique, fn.severity, (fn.__doc__ or "").strip().splitlines()[0]))
    return 0


def cmd_iocs(a):
    ev, fs = _load(a)
    evs = ev if a.all else report._flagged_events(fs)
    res = iocs.extract(evs)
    for k, vals in res.items():
        print("%s (%d)" % (k, len(vals)))
        for v in vals:
            print("  " + v)
    return 0


def cmd_tree(a):
    ev, fs = _load(a)
    flagged = {id(e) for f in fs for e in f.events}
    print(tree.render(tree.build(ev, host=a.host), flagged, only_flagged=not a.all))
    return 0


def cmd_timeline(a):
    _, fs = _load(a)
    for r in timeline.build(fs):
        print("%s  %-6s %-20s %-8s %s" % (r["time"].strftime("%H:%M:%S"), r["host"], r["phase"], r["severity"], r["message"]))
    return 0


def cmd_score(a):
    _, fs = _load(a)
    for s in scoring.host_scores(fs):
        print("%-8s score=%3d level=%-8s findings=%d phases=%d" % (s["host"], s["score"], s["label"], s["findings"], s["phases"]))
    return 0


def cmd_report(a):
    ev, fs = _load(a)
    text = report.html_report(ev, fs, a.title) if a.format == "html" else report.markdown(ev, fs, a.title)
    if a.out:
        with open(a.out, "w", encoding="utf-8") as fh:
            fh.write(text)
        print("wrote %s" % a.out)
    else:
        print(text)
    return 0


def cmd_simulate(a):
    rows = simulate.generate(a.seed, a.noise)
    simulate.write_csv(a.out, rows)
    print("wrote %d events to %s" % (len(rows), a.out))
    return 0


def cmd_case(a):
    store = case_mod.CaseStore(a.db)
    if a.action == "new":
        ev, fs = _load(a)
        cid = store.new_case(a.title, fs[0].severity if fs else "low")
        n = store.attach(cid, fs)
        print("case %d created with %d findings" % (cid, n))
    elif a.action == "list":
        for c in store.list_cases():
            print("#%(id)d %(status)-13s %(severity)-8s findings=%(findings)d %(title)s" % c)
    elif a.action == "note":
        store.note(a.case_id, a.text)
        print("note added")
    elif a.action == "status":
        store.set_status(a.case_id, a.text)
        print("status set")
    elif a.action == "show":
        print(json.dumps(store.show(a.case_id), indent=2))
    return 0


def main(argv=None):
    p = argparse.ArgumentParser(prog="irforge")
    sub = p.add_subparsers(dest="cmd", required=True)

    def ev_parser(name, fn, help_):
        s = sub.add_parser(name, help=help_)
        s.add_argument("events")
        s.add_argument("--only", help="comma separated hunt names")
        s.set_defaults(fn=fn)
        return s

    s = ev_parser("hunt", cmd_hunt, "run all hunts")
    s.add_argument("--json", action="store_true")
    sub.add_parser("list", help="list hunts").set_defaults(fn=cmd_list)
    s = ev_parser("iocs", cmd_iocs, "extract indicators from events involved in findings")
    s.add_argument("--all", action="store_true", help="scan every event, not only flagged ones")
    s = ev_parser("tree", cmd_tree, "process tree")
    s.add_argument("--host")
    s.add_argument("--all", action="store_true", help="show the whole tree")
    ev_parser("timeline", cmd_timeline, "incident timeline")
    ev_parser("score", cmd_score, "host risk scores")
    s = ev_parser("report", cmd_report, "incident report")
    s.add_argument("--format", choices=["md", "html"], default="md")
    s.add_argument("--title", default="Incident report")
    s.add_argument("--out")
    s = sub.add_parser("simulate", help="write a synthetic intrusion dataset")
    s.add_argument("--out", default="sample_data/intrusion.csv")
    s.add_argument("--seed", type=int, default=11)
    s.add_argument("--noise", type=int, default=120)
    s.set_defaults(fn=cmd_simulate)
    s = sub.add_parser("case", help="case management")
    s.add_argument("action", choices=["new", "list", "note", "status", "show"])
    s.add_argument("--db", default="cases.db")
    s.add_argument("--events")
    s.add_argument("--only")
    s.add_argument("--title", default="Untitled case")
    s.add_argument("--case-id", type=int)
    s.add_argument("--text", default="")
    s.set_defaults(fn=cmd_case)
    a = p.parse_args(argv)
    return a.fn(a)


if __name__ == "__main__":
    sys.exit(main())
