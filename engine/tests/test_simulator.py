"""Tests for the simulator. Run from the engine folder: python -m unittest discover -s tests"""

import hashlib
import hmac
import random
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from simulator.client import ApiClient, canonical_string, sign
from simulator.generators import Generators
from simulator.hospital import build_hospital, load_config, load_synthea_patients
from simulator.runner import SOURCES, minute_records, poisson, run


class SigningTest(unittest.TestCase):
    def test_shared_vector(self):
        """The same vector is checked in web/tests, so both languages must agree."""
        master = "0123456789abcdef0123456789abcdef"
        secret = hmac.new(master.encode(), b"collector:sim_hospital_01", hashlib.sha256).hexdigest()
        self.assertEqual(secret, "4f77f91d662217a01618981516897e90e54d127ebb31ea34545b9e72e8f452f5")
        self.assertEqual(sign(secret, "1760000000", "POST", "/api/ingest", b'{"a":1}'), "310a45b5e2aaff8f823736eb10a0a0f7f22e5c2f65aaa9740a1757273a424545")

    def test_canonical_string_binds_every_part(self):
        base = canonical_string("1", "POST", "/a", b"x")
        for other in [("2", "POST", "/a", b"x"), ("1", "GET", "/a", b"x"), ("1", "POST", "/b", b"x"), ("1", "POST", "/a", b"y")]:
            self.assertNotEqual(base, canonical_string(*other))

    def test_client_needs_url_and_secret(self):
        with self.assertRaises(ValueError):
            ApiClient("", "c", "s")
        with self.assertRaises(ValueError):
            ApiClient("http://localhost", "c", "")


class HospitalTest(unittest.TestCase):
    def setUp(self):
        self.config = load_config()

    def test_same_seed_same_hospital(self):
        a, b = build_hospital(self.config), build_hospital(self.config)
        self.assertEqual(a.inventory(), b.inventory())
        self.assertEqual(a.patients, b.patients)

    def test_ids_and_addresses_are_unique(self):
        h = build_hospital(self.config)
        self.assertEqual(len({s.id for s in h.staff}), len(h.staff))
        self.assertEqual(len({a.id for a in h.assets}), len(h.assets))
        self.assertEqual(len({a.ip for a in h.assets}), len(h.assets))
        self.assertEqual(len(h.devices), 40)

    def test_synthea_loader(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "patients.csv"
            path.write_text("Id,BIRTHDATE,FIRST,LAST\nabc,1980,A,B\ndef,1990,C,D\n", encoding="utf-8")
            self.assertEqual(load_synthea_patients(path), ["abc", "def"])
            h = build_hospital(self.config, synthea_patients=path)
            self.assertEqual(sorted(h.patients), ["abc", "def"])
            bad = Path(tmp) / "bad.csv"
            bad.write_text("name\nx\n", encoding="utf-8")
            with self.assertRaises(ValueError):
                load_synthea_patients(bad)


class GeneratorTest(unittest.TestCase):
    def setUp(self):
        self.hospital = build_hospital(load_config())

    def records(self, seed, minutes=45, hour=10):
        gen = Generators(self.hospital, random.Random(seed), "testrun")
        out = []
        for m in range(minutes):
            out.extend(minute_records(gen, self.hospital, datetime(2026, 10, 9, hour, m, tzinfo=timezone.utc)))
        return out

    def test_every_source_is_emitted(self):
        seen = {source for _, source, _ in self.records(1)}
        self.assertEqual(seen, set(SOURCES))

    def test_same_seed_same_records(self):
        a = [(s, p) for _, s, p in self.records(7, minutes=5)]
        b = [(s, p) for _, s, p in self.records(7, minutes=5)]
        self.assertEqual(a, b)
        c = [(s, p) for _, s, p in self.records(8, minutes=5)]
        self.assertNotEqual(a, c)

    def test_record_ids_are_unique(self):
        key = {"ehr": "id", "edr": "event_id", "windows": "RecordId", "linux": "id", "firewall": "id", "vpn": "id",
               "dns": "id", "email": "message_id", "medical_device": "flow_id", "cloud": "eventID"}
        ids = [(s, p[key[s]]) for _, s, p in self.records(3)]
        self.assertEqual(len(ids), len(set(ids)))

    def test_night_is_quieter_than_day(self):
        day = sum(1 for _, s, _ in self.records(5, hour=10) if s == "ehr")
        night = sum(1 for _, s, _ in self.records(5, hour=3) if s == "ehr")
        self.assertGreater(day, night * 2)

    def test_devices_talk_to_their_gateway_or_the_firmware_server(self):
        allowed_extra = self.hospital.asset_by_id["SRVFILE01"].ip
        for _, source, payload in self.records(2):
            if source == "medical_device":
                device = self.hospital.asset_by_id[payload["device"]]
                gateway = self.hospital.asset_by_id[device.attributes["gateway"]]
                self.assertIn(payload["dst_ip"], (gateway.ip, allowed_extra))

    def test_isolated_machines_fall_silent(self):
        gen = Generators(self.hospital, random.Random(9), "iso")
        gen.isolated = {a.id for a in self.hospital.workstations} | {d.id for d in self.hospital.devices}
        hosts = set()
        for m in range(20):
            for _, source, payload in minute_records(gen, self.hospital, datetime(2026, 10, 9, 10, m, tzinfo=timezone.utc)):
                if source == "edr":
                    hosts.add(payload["hostname"])
                if source == "medical_device":
                    hosts.add(payload["device"])
        self.assertFalse(hosts & gen.isolated)

    def test_poisson_mean(self):
        rng = random.Random(1)
        mean = sum(poisson(rng, 4.0) for _ in range(4000)) / 4000
        self.assertAlmostEqual(mean, 4.0, delta=0.2)
        self.assertEqual(poisson(rng, 0), 0)

    def test_dry_run_ledger_matches_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            out, ledger_path = Path(tmp) / "out.jsonl", Path(tmp) / "ledger.json"
            ledger = run(self.hospital, client=None, run_id="dry", seed=4, minutes=10, realtime=False,
                         ledger_path=ledger_path, dry_run_path=out, log=lambda _: None)
            lines = out.read_text(encoding="utf-8").splitlines()
            self.assertEqual(len(lines), ledger.data["emitted_total"])
            self.assertEqual(sum(ledger.data["emitted"].values()), ledger.data["emitted_total"])
            self.assertTrue(ledger_path.exists())


if __name__ == "__main__":
    unittest.main()
