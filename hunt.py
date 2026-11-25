#!/usr/bin/env python3
"""Run simple hunts over a CSV of Windows/Sysmon events and print findings mapped to MITRE ATT&CK.

Usage: python3 hunt.py sample_data/events.csv
"""
import csv
import sys
from collections import defaultdict
from datetime import datetime

OFFICE = ("winword.exe", "excel.exe", "outlook.exe", "powerpnt.exe")


def low(s):
    return (s or "").lower()


def t(row):
    return datetime.fromisoformat(row["time"])


def hunt_office_spawns_shell(rows):
    for r in rows:
        if r["event_id"] == "1" and low(r["parent_image"]).endswith(OFFICE) and \
           low(r["image"]).endswith(("powershell.exe", "cmd.exe", "wscript.exe", "mshta.exe")):
            yield ("T1204.002 / T1059", "high", r, "Office application spawned a script interpreter")


def hunt_encoded_powershell(rows):
    for r in rows:
        c = low(r["command_line"])
        if r["event_id"] == "1" and "powershell" in c and (" -enc" in c or "-encodedcommand" in c):
            yield ("T1059.001", "high", r, "Encoded PowerShell command line")


def hunt_c2_port(rows):
    for r in rows:
        if r["event_id"] == "3" and r["target"].endswith(":4444"):
            yield ("T1071", "medium", r, "Outbound connection to a common C2 port")


def hunt_run_key(rows):
    for r in rows:
        if r["event_id"] == "13" and "currentversion\\run" in low(r["target"]):
            yield ("T1547.001", "medium", r, "Run key persistence set by a process in a user temp folder"
                   if "\\temp\\" in low(r["image"]) else "Run key persistence")


def hunt_lsass_access(rows):
    for r in rows:
        if r["event_id"] == "10" and low(r["target"]).endswith("lsass.exe"):
            yield ("T1003.001", "high", r, "Process accessed LSASS memory")


def hunt_kerberoast(rows, threshold=3, window=60):
    by_src = defaultdict(list)
    for r in rows:
        if r["event_id"] == "4769" and "0x17" in r["target"]:
            by_src[r["source_ip"]].append(r)
    for src, rs in by_src.items():
        rs.sort(key=t)
        if len(rs) >= threshold and (t(rs[-1]) - t(rs[0])).total_seconds() <= window:
            yield ("T1558.003", "high", rs[0], f"{len(rs)} RC4 service ticket requests from {src} in {window}s")


def hunt_bruteforce(rows, threshold=5, window=30):
    by_key = defaultdict(list)
    for r in rows:
        if r["event_id"] in ("4625", "4624"):
            by_key[(r["user"], r["source_ip"])].append(r)
    for (user, src), rs in by_key.items():
        rs.sort(key=t)
        fails = [x for x in rs if x["event_id"] == "4625"]
        wins = [x for x in rs if x["event_id"] == "4624"]
        if len(fails) >= threshold and wins and (t(wins[0]) - t(fails[0])).total_seconds() <= window:
            yield ("T1110", "high", wins[0], f"{len(fails)} failed logons then success for {user} from {src}")


def hunt_new_account(rows):
    for r in rows:
        c = low(r["command_line"])
        if r["event_id"] == "1" and "net" in low(r["image"]) and " user " in c and "/add" in c:
            yield ("T1136.001", "medium", r, "Local account created via net.exe")


HUNTS = [hunt_office_spawns_shell, hunt_encoded_powershell, hunt_c2_port, hunt_run_key,
         hunt_lsass_access, hunt_kerberoast, hunt_bruteforce, hunt_new_account]


def main(path):
    with open(path, newline="", encoding="utf-8") as f:
        rows = list(csv.DictReader(f))
    findings = [x for h in HUNTS for x in h(rows)]
    findings.sort(key=lambda x: t(x[2]))
    print(f"{len(rows)} events analysed, {len(findings)} findings\n")
    for tech, sev, r, why in findings:
        print(f"[{sev.upper():6}] {r['time']} {r['host']:5} {r['user']:12} {tech:18} {why}")
    return findings


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    main(sys.argv[1])
