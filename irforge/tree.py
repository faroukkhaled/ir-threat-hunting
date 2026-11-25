"""Process tree reconstruction from process creation events (event id 1).

Uses (host, pid, ppid) when present. Without pids it falls back to chaining by parent image name,
which is approximate and marked as such.
"""
from collections import defaultdict


def build(events, host=None):
    procs = [e for e in events if e.event_id == 1 and (host is None or e.host == host)]
    have_pids = any(e.pid is not None for e in procs)
    nodes = {}
    children = defaultdict(list)
    roots = []
    if have_pids:
        for e in procs:
            if e.pid is not None:
                nodes[(e.host, e.pid)] = e
        for key, e in nodes.items():
            pkey = (e.host, e.ppid)
            if e.ppid is not None and pkey in nodes and pkey != key:
                children[pkey].append(key)
            else:
                roots.append(key)
        return {"mode": "pid", "nodes": nodes, "children": children, "roots": sorted(roots, key=lambda k: nodes[k].time)}
    # approximate mode: group by parent image
    for i, e in enumerate(procs):
        nodes[i] = e
    by_image = defaultdict(list)
    for i, e in nodes.items():
        by_image[(e.host, e.image.lower())].append(i)
    for i, e in nodes.items():
        parents = [p for p in by_image.get((e.host, e.parent_image.lower()), []) if nodes[p].time <= e.time and p != i]
        if parents:
            children[parents[-1]].append(i)
        else:
            roots.append(i)
    return {"mode": "approx", "nodes": nodes, "children": children, "roots": roots}


def render(tree, flagged=None, max_cmd=90, only_flagged=False):
    """Return a text rendering. `flagged` is a set of events to mark with an asterisk."""
    flagged = flagged or set()
    lines = []
    keep = {}

    def has_flag(key):
        if key not in keep:
            keep[key] = id(tree["nodes"][key]) in flagged or any(has_flag(k) for k in tree["children"].get(key, []))
        return keep[key]

    def walk(key, prefix, last):
        e = tree["nodes"][key]
        mark = " [!]" if id(e) in flagged else ""
        cmd = e.command_line if len(e.command_line) <= max_cmd else e.command_line[: max_cmd - 3] + "..."
        branch = "" if prefix is None else (prefix + ("`-- " if last else "|-- "))
        lines.append("%s%s [%s %s]%s  %s" % (branch, e.exe or e.image, e.host, e.time.strftime("%H:%M:%S"), mark, cmd))
        kids = [k for k in tree["children"].get(key, []) if not only_flagged or has_flag(k)]
        np = "" if prefix is None else prefix + ("    " if last else "|   ")
        for j, k in enumerate(kids):
            walk(k, np, j == len(kids) - 1)

    for r in tree["roots"]:
        if not only_flagged or has_flag(r):
            walk(r, None, True)
    if tree["mode"] == "approx":
        lines.append("(approximate: events had no pid/ppid, links are inferred from image names)")
    return "\n".join(lines)
