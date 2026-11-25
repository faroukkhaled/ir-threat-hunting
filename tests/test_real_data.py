"""Hunts against real OTRF telemetry committed in real_data/ (MIT, see real_data/README.md)."""
import os
import unittest

from irforge import hunts, iocs, otrf
from irforge.models import load_events

D = os.path.join(os.path.dirname(__file__), "..", "real_data")


def findings(name):
    return hunts.run_all(load_events(os.path.join(D, name + ".csv")))


class RealData(unittest.TestCase):
    def test_lsass_dump_found(self):
        for name in ("lsass_dump_comsvcs", "mimikatz_logonpasswords"):
            fs = [f for f in findings(name) if f.hunt == "lsass-access"]
            self.assertTrue(fs, name)
            self.assertTrue(all(f.events[0].exe != "svchost.exe" for f in fs), name)

    def test_run_key_found_and_defender_ignored(self):
        fs = [f for f in findings("run_key_persistence") if f.hunt == "run-key-persistence"]
        self.assertEqual(len(fs), 1)

    def test_lolbin_parent_child_found(self):
        for name, child in (("regsvr32_sct_launcher", "regsvr32.exe"), ("mshta_vbscript_psh", "mshta.exe"), ("bitsadmin_download", "bitsadmin.exe")):
            msgs = " ".join(f.message for f in findings(name) if f.hunt == "rare-parent-child")
            self.assertIn(child, msgs, name)

    def test_converter_skips_unmapped_events(self):
        self.assertIsNone(otrf.convert({"Channel": "Security", "EventID": 5156, "EventTime": "2020-01-01 00:00:00"}))
        row = otrf.convert({"Channel": "Microsoft-Windows-Sysmon/Operational", "EventID": 1, "UtcTime": "2020-01-01 00:00:00.123",
                            "Hostname": "H", "Image": "C:\\a.exe", "ProcessId": "12", "ParentProcessId": "4"})
        self.assertEqual((row["pid"], row["ppid"], row["host"]), (12, 4, "H"))

    def test_iocs_extract_runs_on_real_data(self):
        res = iocs.extract(load_events(os.path.join(D, "regsvr32_sct_launcher.csv")))
        self.assertIn("urls", res)


if __name__ == "__main__":
    unittest.main()
