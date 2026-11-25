"""Event and finding models plus loaders (CSV and JSON lines)."""
import csv
import json
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional


@dataclass
class Event:
    time: datetime
    host: str
    user: str
    event_id: int
    image: str = ""
    parent_image: str = ""
    command_line: str = ""
    target: str = ""
    source_ip: str = ""
    pid: Optional[int] = None
    ppid: Optional[int] = None
    raw: Dict[str, Any] = field(default_factory=dict)

    @property
    def exe(self):
        return self.image.replace("/", "\\").rsplit("\\", 1)[-1].lower()

    @property
    def parent_exe(self):
        return self.parent_image.replace("/", "\\").rsplit("\\", 1)[-1].lower()

    def key(self):
        return (self.host, self.pid) if self.pid is not None else None


@dataclass
class Finding:
    hunt: str
    technique: str
    severity: str
    message: str
    events: List[Event]
    evidence: Dict[str, Any] = field(default_factory=dict)

    @property
    def time(self):
        return min(e.time for e in self.events)

    @property
    def host(self):
        return self.events[0].host


def _int(v):
    try:
        return int(v) if v not in (None, "") else None
    except ValueError:
        return None


def _from_dict(d):
    return Event(
        time=datetime.fromisoformat(d["time"]),
        host=d.get("host", ""),
        user=d.get("user", ""),
        event_id=int(d["event_id"]),
        image=d.get("image", "") or "",
        parent_image=d.get("parent_image", "") or "",
        command_line=d.get("command_line", "") or "",
        target=d.get("target", "") or "",
        source_ip=d.get("source_ip", "") or "",
        pid=_int(d.get("pid")),
        ppid=_int(d.get("ppid")),
        raw=dict(d),
    )


def load_csv(path):
    with open(path, encoding="utf-8", newline="") as fh:
        return sorted((_from_dict(r) for r in csv.DictReader(fh)), key=lambda e: e.time)


def load_jsonl(path):
    out = []
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            if line.strip():
                out.append(_from_dict(json.loads(line)))
    return sorted(out, key=lambda e: e.time)


def load_events(path):
    return load_jsonl(path) if path.endswith((".jsonl", ".json")) else load_csv(path)
