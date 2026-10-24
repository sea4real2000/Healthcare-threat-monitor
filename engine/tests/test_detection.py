"""Tests for rules, scoring, models, scenarios and forwarding. None of them needs a database."""

import json
import random
import socket
import threading
import unittest
from datetime import datetime, timedelta, timezone

import forwarding
from detection.models import EndpointModel
from detection.pipeline import band_for, combine
from detection.rules import Rule, RuleEngine, RuleError
from simulator import scenarios
from simulator.generators import Generators
from simulator.hospital import build_hospital, load_config

T0 = datetime(2026, 10, 9, 10, 0, tzinfo=timezone.utc)
SETTINGS = {
    "detection.high_min_sources": 2, "detection.single_source_cap": 0.79, "detection.band_high": 0.8, "detection.band_medium": 0.5,
    "model.min_training_windows": 50, "model.min_group_windows": 50, "model.trees": 100, "model.sample_size": 512, "model.alert_quantile": 0.995,
    "model.min_feature_z": 3, "model.full_confidence_z": 12, "model.confidence_min": 0.35, "model.confidence_max": 0.75, "feedback.normal_weight": 50,
}


def event(seconds=0, **over):
    ev = {"id": random.randrange(10**9), "source": "edr", "occurred_at": T0 + timedelta(seconds=seconds), "category": "process",
          "action": "process_start", "outcome": "success", "actor_user": "abaker", "host": "WSED001", "src_ip": None, "dst_ip": None,
          "dst_port": None, "attributes": {}, "actor": {"role": "nurse"}, "asset": {"kind": "workstation", "role": "clinical_workstation"}}
    ev.update(over)
    return ev


def rule(kind="match", **definition):
    return {"id": "r1", "name": "Test rule", "kind": kind, "category": "ransomware", "severity": 3, "confidence": 0.8,
            "technique_id": "T1490", "technique_name": "x", "definition": definition, "load_error": None}


def engine(*rows):
    e = RuleEngine()
    e.load_rules(list(rows))
    return e


class RuleTest(unittest.TestCase):
    def test_match_rule(self):
        e = engine(rule(where=[{"field": "category", "op": "eq", "value": "process"},
                               {"field": "attributes.command_line", "op": "contains_any", "value": ["vssadmin delete shadows"]}]))
        self.assertEqual(e.process(event(attributes={"command_line": "cmd /c echo hello"})), [])
        hit = e.process(event(attributes={"command_line": "VSSADMIN Delete Shadows /all"}))
        self.assertEqual(len(hit), 1)
        self.assertEqual((hit[0].detector_id, hit[0].host, hit[0].user, hit[0].entity), ("r1", "WSED001", "abaker", "WSED001"))

    def test_every_operator(self):
        cases = [("eq", "nurse", True), ("ne", "nurse", False), ("in", ["nurse", "x"], True), ("not_in", ["nurse"], False),
                 ("contains", "urs", True), ("regex", "^nu", True), ("exists", None, True), ("not_exists", None, False)]
        for op, value, expected in cases:
            cond = {"field": "actor.role", "op": op}
            if value is not None:
                cond["value"] = value
            self.assertEqual(Rule(rule(where=[cond])).matches(event()), expected, op)
        num = lambda op, v: Rule(rule(where=[{"field": "bytes_out", "op": op, "value": v}])).matches(event(bytes_out=100))
        self.assertTrue(num("gt", 99) and num("gte", 100) and num("lt", 101) and num("lte", 100))
        self.assertFalse(num("gt", 100) or num("lt", 100))
        self.assertFalse(Rule(rule(where=[{"field": "bytes_out", "op": "gt", "value": 1}])).matches(event(bytes_out=None)))
        arr = Rule(rule(where=[{"field": "attributes.attachment_extensions", "op": "any_in", "value": ["docm", "iso"]}]))
        self.assertTrue(arr.matches(event(attributes={"attachment_extensions": ["pdf", "DOCM"]})))
        self.assertFalse(arr.matches(event(attributes={"attachment_extensions": ["pdf"]})))
        flag = Rule(rule(where=[{"field": "same_department", "op": "is_false"}]))
        self.assertTrue(flag.matches(event(same_department=False)))
        self.assertFalse(flag.matches(event(same_department=None)))

    def test_threshold_rule_counts_inside_the_window_only(self):
        e = engine(rule("threshold", where=[{"field": "action", "op": "eq", "value": "file_rename"}], window_seconds=60, count=5))
        fired = [bool(e.process(event(seconds=i * 20, action="file_rename"))) for i in range(8)]
        self.assertFalse(any(fired))  # never five inside any 60 seconds
        e2 = engine(rule("threshold", where=[{"field": "action", "op": "eq", "value": "file_rename"}], window_seconds=60, count=5))
        fired = [bool(e2.process(event(seconds=i, action="file_rename"))) for i in range(6)]
        self.assertEqual(fired, [False, False, False, False, True, True])

    def test_threshold_rule_with_distinct_values(self):
        e = engine(rule("threshold", where=[{"field": "action", "op": "eq", "value": "logon"}], entity_field="src_host", host_field="src_host",
                        distinct=["host"], window_seconds=600, count=3))
        same = [bool(e.process(event(seconds=i, action="logon", src_host="WSED009", host="SRVDC01"))) for i in range(10)]
        self.assertFalse(any(same))
        spread = [bool(e.process(event(seconds=20 + i, action="logon", src_host="WSED009", host=f"H{i}"))) for i in range(2)]
        self.assertEqual(spread, [False, True])

    def test_new_value_rule(self):
        e = engine(rule("new_value", where=[{"field": "category", "op": "eq", "value": "device_flow"}], value_field="dst_ip", fallback="global"))
        e.load_baseline([("r1", "PUMP0001", "10.10.1.31"), ("r1", "PUMP0002", "10.10.1.99")])
        flow = lambda host, dst: e.process(event(category="device_flow", host=host, dst_ip=dst))
        self.assertEqual(flow("PUMP0001", "10.10.1.31"), [])
        hit = flow("PUMP0001", "10.40.1.50")
        self.assertEqual(hit[0].baseline, {"scope": "r1", "entity": "PUMP0001", "value": "10.40.1.50"})
        # A device nobody has seen before is compared with what every other device does.
        self.assertEqual(flow("PUMP0009", "10.10.1.99"), [])
        self.assertEqual(len(flow("PUMP0009", "203.0.113.5")), 1)
        # A value learned as normal for everyone silences the rule for that value.
        e.load_baseline([("r1", "PUMP0001", "10.10.1.31"), ("r1", "*", "10.40.1.50")])
        self.assertEqual(flow("PUMP0001", "10.40.1.50"), [])

    def test_learning_period_records_new_values_and_still_reports_clear_attacks(self):
        new_value = rule("new_value", where=[{"field": "category", "op": "eq", "value": "device_flow"}], value_field="dst_ip", fallback="global")
        attack = dict(rule(where=[{"field": "category", "op": "eq", "value": "device_flow"}, {"field": "dst_port", "op": "eq", "value": 4444}]), id="r2")
        e = engine(new_value, attack)
        learned = []
        flow = lambda dst, port=443, learning=False: e.process(event(category="device_flow", host="PUMP0001", dst_ip=dst, dst_port=port),
                                                               learning=learning, learned=learned)
        # Everything is new on a new installation. While learning, nothing new is reported, only recorded.
        self.assertEqual(flow("10.10.1.31", learning=True), [])
        self.assertEqual(flow("10.10.1.31", learning=True), [])
        self.assertEqual(learned, [("r1", "PUMP0001", "10.10.1.31")])
        # A clear sign of attack is reported even while learning.
        self.assertEqual([d.detector_id for d in flow("10.10.1.32", port=4444, learning=True)], ["r2"])
        # After learning, what was learned is normal and anything new is reported.
        self.assertEqual(flow("10.10.1.31"), [])
        self.assertEqual([d.detector_id for d in flow("203.0.113.9")], ["r1"])

    def test_entity_falls_back_to_the_address_of_an_unlisted_machine(self):
        e = engine(rule(where=[{"field": "category", "op": "eq", "value": "network_flow"}], entity_field="host", entity_fallback="src_ip"))
        listed = e.process(event(category="network_flow", host="WSED001", src_ip="10.10.1.21"))
        unlisted = e.process(event(category="network_flow", host=None, src_ip="10.99.0.7", seconds=1))
        self.assertEqual((listed[0].entity, unlisted[0].entity), ("WSED001", "10.99.0.7"))
        with self.assertRaises(RuleError):
            Rule(rule(entity_fallback="no spaces allowed"))

    def test_feedback_exceptions(self):
        e = engine(rule("threshold", where=[{"field": "action", "op": "eq", "value": "file_rename"}], window_seconds=60, count=3))
        e.load_exceptions([("r1", "SRVFILE01", "threshold", 6)])
        quiet = [bool(e.process(event(seconds=i, action="file_rename", host="SRVFILE01"))) for i in range(5)]
        self.assertFalse(any(quiet))
        self.assertTrue(e.process(event(seconds=5, action="file_rename", host="SRVFILE01")))
        self.assertTrue([e.process(event(seconds=i, action="file_rename", host="WSED002")) for i in range(3)][-1])
        e.load_exceptions([("r1", "WSED001", "suppress", None)])
        m = engine(rule(where=[{"field": "category", "op": "eq", "value": "process"}]))
        m.load_exceptions([("r1", "WSED001", "suppress", None)])
        self.assertEqual(m.process(event()), [])
        self.assertEqual(len(m.process(event(host="WSED002"))), 1)

    def test_bad_definitions_are_reported_not_fatal(self):
        bad = [rule(where=[]), rule(where=[{"field": "host", "op": "nope", "value": 1}]), rule(where=[{"field": "host; drop", "op": "eq", "value": 1}]),
               rule(where=[{"field": "host", "op": "regex", "value": "("}]), rule("threshold", where=[{"field": "host", "op": "exists"}]),
               rule("new_value", where=[{"field": "host", "op": "exists"}]), rule(where=[{"field": "host", "op": "in", "value": "x"}])]
        for row in bad:
            with self.assertRaises(RuleError):
                Rule(row)
        e = RuleEngine()
        good = rule(where=[{"field": "category", "op": "eq", "value": "process"}])
        e.load_rules([dict(bad[0], id="broken"), good])
        self.assertIn("broken", e.errors)
        self.assertEqual(len(e.process(event())), 1)


class ScoringTest(unittest.TestCase):
    def test_independent_detectors_combine(self):
        self.assertAlmostEqual(combine([0.6]), 0.6)
        self.assertAlmostEqual(combine([0.6, 0.5]), 0.8)
        self.assertGreater(combine([0.35, 0.6, 0.25]), 0.8)
        self.assertEqual(combine([]), 0.0)

    def test_bands_and_the_single_source_cap(self):
        self.assertEqual(band_for(0.95, 1, SETTINGS), (0.79, "medium"))
        self.assertEqual(band_for(0.95, 2, SETTINGS)[1], "high")
        self.assertEqual(band_for(0.5, 3, SETTINGS)[1], "medium")
        self.assertEqual(band_for(0.49, 3, SETTINGS)[1], "low")


class ModelTest(unittest.TestCase):
    def windows(self, n, rng, burst=0):
        out = []
        for i in range(n):
            acc = {"file_write": rng.choice([0, 0, 0, 1]), "file_rename": 0, "file_delete": 0, "ext": {"docx"}, "process": rng.choice([1, 1, 2]),
                   "names": {"winword.exe"}, "script": 0, "connect": 0, "role": "clinical_workstation", "_events": [], "_sources": {"edr"},
                   "_host": f"WS{i % 20}", "_user": None, "_n": 2}
            out.append((f"WS{i % 20}", 1000 + 60 * i, acc))
        for i in range(burst):
            acc = dict(out[i][2], file_write=50, ext={"dll", "exe", "tmp"})
            out.append((f"WS{i}", 900000 + 60 * i, acc))
        return out

    def attack(self):
        return ("WS3", 5_000_000, {"file_write": 2, "file_rename": 85, "file_delete": 0, "ext": {"locked"}, "process": 1, "names": {"svchosts.exe"},
                                   "script": 0, "connect": 0, "role": "clinical_workstation", "_events": [], "_sources": {"edr"}, "_host": "WS3", "_user": None, "_n": 88})

    def test_untrained_model_is_silent(self):
        m = EndpointModel()
        self.assertIsNone(m.fit(self.windows(10, random.Random(1)), {}, SETTINGS))
        self.assertEqual(m.score([self.attack()], SETTINGS, {}, "t"), [])

    def test_flags_an_encryption_burst_and_explains_it(self):
        m = EndpointModel()
        summary = m.fit(self.windows(600, random.Random(1)), {}, SETTINGS)
        self.assertEqual(summary["training_rows"], 600)
        normal = m.score(self.windows(200, random.Random(2)), SETTINGS, {}, "t")
        self.assertLessEqual(len(normal), 2)
        alerts = m.score([self.attack()], SETTINGS, {"file_renames": "Files renamed"}, "Unusual endpoint behaviour")
        self.assertEqual(len(alerts), 1)
        top = alerts[0].explanation[0]
        self.assertEqual((top["label"], top["value"], top["beyond_training"]), ("Files renamed", 85.0, True))
        self.assertAlmostEqual(alerts[0].confidence, 0.75)
        self.assertEqual(alerts[0].baseline["group"], "clinical_workstation")

    def test_taught_windows_widen_the_normal_range(self):
        deployment = ("WS5", 6_000_000, dict(self.windows(1, random.Random(3))[0][2], file_write=50, ext={"dll", "exe", "tmp"}))
        m = EndpointModel()
        m.fit(self.windows(600, random.Random(1)), {}, SETTINGS)
        before = m.score([deployment], SETTINGS, {}, "t")
        self.assertEqual(len(before), 1)
        taught = EndpointModel()
        taught.fit(self.windows(600, random.Random(1)), {}, SETTINGS, [before[0].baseline] * 3)
        self.assertEqual(taught.score([deployment], SETTINGS, {}, "t"), [])
        # Teaching the model about installs must not hide an encryption burst.
        self.assertEqual(len(taught.score([self.attack()], SETTINGS, {}, "t")), 1)

    def test_entity_threshold_from_feedback(self):
        m = EndpointModel()
        m.fit(self.windows(600, random.Random(1)), {}, SETTINGS)
        first = m.score([self.attack()], SETTINGS, {}, "t")[0]
        m.entity_thresholds = {"WS3": first.observed * 1.25}
        self.assertEqual(m.score([self.attack()], SETTINGS, {}, "t"), [])
        m.suppress = {"WS3"}
        self.assertEqual(m.score([self.attack()], SETTINGS, {}, "t"), [])


class ScenarioTest(unittest.TestCase):
    def setUp(self):
        self.hospital = build_hospital(load_config())
        self.gen = Generators(self.hospital, random.Random(5), "t")

    def test_every_scenario_builds_in_time_order_with_unique_keys(self):
        for name in scenarios.SCENARIOS:
            sc = scenarios.build(name, self.gen, T0)
            offsets = [s[0] for s in sc.steps]
            self.assertEqual(offsets, sorted(offsets), name)
            keys = [(s[1], scenarios.event_key(s[1], s[2])) for s in sc.steps]
            self.assertEqual(len(keys), len(set(keys)), name)
            self.assertTrue(sc.hosts, name)

    def test_file_server_steps_depend_on_lateral_movement(self):
        sc = scenarios.build("ransomware", self.gen, T0)
        server_steps = [s for s in sc.steps if s[4] == "SRVFILE01"]
        self.assertTrue(server_steps)
        self.assertTrue(all(s[5] == "lateral_movement" for s in server_steps))
        self.assertTrue(all(s[5] is None for s in sc.steps if s[4] != "SRVFILE01"))

    def test_time_scale_compresses_a_scenario(self):
        full = scenarios.build("ransomware", Generators(self.hospital, random.Random(5), "a"), T0, 1.0)
        fast = scenarios.build("ransomware", Generators(self.hospital, random.Random(5), "a"), T0, 0.25)
        self.assertAlmostEqual(fast.steps[-1][0], full.steps[-1][0] * 0.25, places=3)

    def test_the_rules_shipped_with_the_platform_catch_the_ransomware_script(self):
        """Feeds the scenario through the real seed rules, after the same normalization the API applies."""
        import pathlib
        import re
        seed = (pathlib.Path(__file__).resolve().parents[2] / "supabase" / "migrations" / "0007_seed.sql").read_text(encoding="utf-8")
        block = seed.split("insert into rules")[1].split("on conflict")[0]
        rows = []
        for m in re.finditer(r"\('([a-z_]+)', '((?:[^']|'')*)', '((?:[^']|'')*)', '([a-z]+)', '([a-z_]+)',\s*'((?:[^']|'')*)'::jsonb, (\d), ([0-9.]+), '([^']*)', '([^']*)'\)", block):
            rows.append({"id": m[1], "name": m[2], "kind": m[5], "category": m[4], "severity": int(m[7]), "confidence": float(m[8]),
                         "technique_id": m[9], "technique_name": m[10], "definition": json.loads(m[6].replace("''", "'")), "load_error": None})
        self.assertGreaterEqual(len(rows), 20)
        e = RuleEngine()
        e.load_rules(rows)
        self.assertEqual(e.errors, {})
        sc = scenarios.build("ransomware", self.gen, T0)
        fired = set()
        for offset, source, p, *_ in sc.steps:
            if source != "edr":
                continue
            proc, f = p.get("process", {}), p.get("file", {})
            ev = event(seconds=offset, source="edr", category={"process_start": "process"}.get(p["event_type"], "file"), action=p["event_type"],
                       host=p["hostname"], actor_user=p["user"],
                       attributes={"process_name": (proc.get("name") or "").lower(), "parent_name": (proc.get("parent") or "").lower(),
                                   "command_line": proc.get("cmdline"), "file_path": f.get("path"), "file_new_path": f.get("new_path")})
            fired.update(d.detector_id for d in e.process(ev))
        for expected in ("office_spawns_script", "credential_dump", "ransom_shadow_copy_delete", "ransom_mass_file_rename", "ransom_note_created"):
            self.assertIn(expected, fired)


class ForwardingTest(unittest.TestCase):
    MESSAGE = forwarding.build_message("incident_opened", {
        "id": 7, "title": "Ransomware behaviour on WS|ED=1", "category": "ransomware", "status": "open", "band": "high", "confidence": 0.91234,
        "severity": 3, "primary_host": "WSED001", "primary_user": "abaker", "techniques": ["T1486", "T1490"], "sources": ["edr", "dns"], "alert_count": 4,
        "decided_by": "should not be forwarded"}, "Healthcare Threat Monitor", {"seq": 12, "hash": "ab"})

    def test_message_keeps_only_what_a_siem_needs(self):
        self.assertEqual(self.MESSAGE["incident"]["confidence"], 0.9123)
        self.assertNotIn("decided_by", self.MESSAGE["incident"])
        self.assertEqual(self.MESSAGE["audit_head"], {"seq": 12, "hash": "ab"})

    def test_cef_line_is_escaped(self):
        cef = forwarding.to_cef(self.MESSAGE)
        self.assertTrue(cef.startswith("CEF:0|HTM|Healthcare Threat Monitor|0.8|incident_opened|Ransomware behaviour on WS\\|ED=1|9|"))
        self.assertIn("cs1Label=band cs1=high", cef)
        self.assertIn("cs2=T1486,T1490", cef)
        self.assertEqual(forwarding.cef_extension("a=b\\c\nd"), "a\\=b\\\\c\\nd")

    def test_syslog_frame_and_delivery(self):
        frame = forwarding.syslog_frame("CEF:0|x", "high")
        self.assertTrue(frame.startswith(b"<162>1 "))  # local4, critical
        server = socket.socket()
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        got = []

        def accept():
            conn, _ = server.accept()
            got.append(conn.recv(4096))
            conn.close()

        thread = threading.Thread(target=accept)
        thread.start()
        forwarding.send_syslog("127.0.0.1", server.getsockname()[1], "tcp", frame)
        thread.join(timeout=5)
        server.close()
        self.assertEqual(got[0], str(len(frame)).encode() + b" " + frame)

    def test_webhook_signature_binds_time_path_and_body(self):
        a = forwarding.sign_webhook("k" * 32, "1760000000", "/api/siem/receive", b"{}")
        self.assertEqual(len(a), 64)
        for other in [("k" * 31 + "x", "1760000000", "/api/siem/receive", b"{}"), ("k" * 32, "1760000001", "/api/siem/receive", b"{}"),
                      ("k" * 32, "1760000000", "/other", b"{}"), ("k" * 32, "1760000000", "/api/siem/receive", b"{ }")]:
            self.assertNotEqual(a, forwarding.sign_webhook(*other))


if __name__ == "__main__":
    unittest.main()
