"""Convert OTRF Security-Datasets / Mordor JSON exports (real lab telemetry) into irforge events.

Source: https://github.com/OTRF/Security-Datasets (MIT, Open Threat Research Forge).
Only Sysmon events 1, 3, 10, 11, 13, 22 and Security 4624/4625/4688 are mapped.
"""
import csv
import io
import json
import urllib.request
import zipfile

from .simulate import FIELDS

BASE = "https://raw.githubusercontent.com/OTRF/Security-Datasets/master/datasets/atomic/windows/"
DATASETS = {
    "mimikatz_logonpasswords": "credential_access/host/empire_mimikatz_logonpasswords.zip",
    "dcsync_drsuapi": "credential_access/host/empire_dcsync_dcerpc_drsuapi_DsGetNCChanges.zip",
    "lsass_dump_comsvcs": "credential_access/host/psh_lsass_memory_dump_comsvcs.zip",
    "run_key_persistence": "persistence/host/empire_persistence_registry_modification_run_keys_elevated_user.zip",
    "schtasks_persistence": "persistence/host/empire_schtasks_creation_execution_elevated_user.zip",
    "regsvr32_sct_launcher": "defense_evasion/host/empire_launcher_sct_regsvr32.zip",
    "mshta_vbscript_psh": "defense_evasion/host/cmd_mshta_vbscript_execute_psh.zip",
    "bitsadmin_download": "defense_evasion/host/cmd_bitsadmin_download_psh_script.zip",
}


def _hex_or_int(v):
    if v in (None, ""):
        return ""
    try:
        return int(str(v), 0)
    except ValueError:
        return ""


def convert(rec):
    """Return an irforge row (dict) for one OTRF record, or None if it is not mapped."""
    ch = str(rec.get("Channel", "")).lower()
    eid = rec.get("EventID")
    t = rec.get("UtcTime") or rec.get("EventTime") or rec.get("TimeCreated") or rec.get("@timestamp")
    if not t or eid is None:
        return None
    t = str(t).replace("Z", "").replace(" ", "T")[:23]
    row = dict.fromkeys(FIELDS, "")
    row.update(time=t, host=rec.get("Hostname", ""), event_id=eid, user=rec.get("User", "") or rec.get("SubjectUserName", ""))
    if "sysmon" in ch:
        if eid == 1:
            row.update(image=rec.get("Image", ""), parent_image=rec.get("ParentImage", ""), command_line=rec.get("CommandLine", ""),
                       pid=_hex_or_int(rec.get("ProcessId")), ppid=_hex_or_int(rec.get("ParentProcessId")))
        elif eid == 3:
            row.update(image=rec.get("Image", ""), target="%s:%s" % (rec.get("DestinationIp", ""), rec.get("DestinationPort", "")),
                       source_ip=rec.get("SourceIp", ""), pid=_hex_or_int(rec.get("ProcessId")))
        elif eid == 10:
            row.update(image=rec.get("SourceImage", ""), target=rec.get("TargetImage", ""), pid=_hex_or_int(rec.get("SourceProcessId")))
        elif eid in (11, 13):
            row.update(image=rec.get("Image", ""), target=rec.get("TargetFilename") or rec.get("TargetObject", ""),
                       pid=_hex_or_int(rec.get("ProcessId")))
        elif eid == 22:
            row.update(image=rec.get("Image", ""), target=rec.get("QueryName", ""), pid=_hex_or_int(rec.get("ProcessId")))
        else:
            return None
    elif ch == "security" and eid in (4624, 4625, 4688):
        row.update(source_ip=rec.get("IpAddress", "") if rec.get("IpAddress") not in ("-", None) else "",
                   target=rec.get("TargetUserName", ""), image=rec.get("NewProcessName", ""), command_line=rec.get("CommandLine", ""))
        if eid == 4688:
            row.update(parent_image=rec.get("ParentProcessName", ""), pid=_hex_or_int(rec.get("NewProcessId")),
                       ppid=_hex_or_int(rec.get("ProcessId")))
    else:
        return None
    return row


def convert_lines(lines):
    rows = []
    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            row = convert(json.loads(line))
        except json.JSONDecodeError:
            continue
        if row:
            rows.append(row)
    return sorted(rows, key=lambda r: r["time"])


def write_csv(rows, path):
    with open(path, "w", encoding="utf-8", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=FIELDS)
        w.writeheader()
        w.writerows(rows)


def fetch(name):
    with urllib.request.urlopen(BASE + DATASETS[name], timeout=120) as r:
        z = zipfile.ZipFile(io.BytesIO(r.read()))
    member = [n for n in z.namelist() if n.endswith(".json")][0]
    return convert_lines(io.TextIOWrapper(z.open(member), encoding="utf-8"))
