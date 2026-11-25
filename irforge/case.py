"""Tiny case manager on SQLite: cases, findings attached to cases, analyst notes, status history."""
import sqlite3
from datetime import datetime

SCHEMA = """
create table if not exists cases(id integer primary key, title text not null, severity text not null,
  status text not null default 'open', opened text not null, closed text);
create table if not exists case_findings(id integer primary key, case_id integer references cases(id),
  hunt text, technique text, severity text, host text, message text, found_at text);
create table if not exists notes(id integer primary key, case_id integer references cases(id), ts text, author text, body text);
"""
STATUSES = ("open", "investigating", "contained", "closed")


class CaseStore:
    def __init__(self, path=":memory:"):
        self.db = sqlite3.connect(path)
        self.db.row_factory = sqlite3.Row
        self.db.executescript(SCHEMA)

    def new_case(self, title, severity="medium"):
        cur = self.db.execute("insert into cases(title,severity,opened) values(?,?,?)", (title, severity, datetime.now().isoformat(timespec="seconds")))
        self.db.commit()
        return cur.lastrowid

    def attach(self, case_id, findings):
        for f in findings:
            self.db.execute("insert into case_findings(case_id,hunt,technique,severity,host,message,found_at) values(?,?,?,?,?,?,?)",
                            (case_id, f.hunt, f.technique, f.severity, f.host, f.message, f.time.isoformat()))
        self.db.commit()
        return len(findings)

    def note(self, case_id, body, author="analyst"):
        self.db.execute("insert into notes(case_id,ts,author,body) values(?,?,?,?)", (case_id, datetime.now().isoformat(timespec="seconds"), author, body))
        self.db.commit()

    def set_status(self, case_id, status):
        if status not in STATUSES:
            raise ValueError("status must be one of %s" % ", ".join(STATUSES))
        closed = datetime.now().isoformat(timespec="seconds") if status == "closed" else None
        self.db.execute("update cases set status=?, closed=? where id=?", (status, closed, case_id))
        self.db.commit()

    def list_cases(self):
        return [dict(r) for r in self.db.execute("select c.*, (select count(*) from case_findings f where f.case_id=c.id) as findings from cases c order by id")]

    def show(self, case_id):
        case = self.db.execute("select * from cases where id=?", (case_id,)).fetchone()
        if not case:
            return None
        return {
            "case": dict(case),
            "findings": [dict(r) for r in self.db.execute("select * from case_findings where case_id=? order by found_at", (case_id,))],
            "notes": [dict(r) for r in self.db.execute("select * from notes where case_id=? order by id", (case_id,))],
        }
