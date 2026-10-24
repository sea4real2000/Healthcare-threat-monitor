"""The database connection's row conversion, checked against the examples shared with the console."""
import json
import unittest
from datetime import datetime, timezone
from pathlib import Path

from connectors.records_convert import RowError, action_code, parse_time, to_audit_event

CASES = json.loads((Path(__file__).resolve().parents[2] / "shared" / "record_conversion_cases.json").read_text())


class SharedCases(unittest.TestCase):
    def test_every_shared_case(self):
        opts = CASES["options"]
        for i, c in enumerate(CASES["cases"], 1):
            with self.subTest(case=i):
                run = lambda: to_audit_event(c["row"], c["timezone"], c["dayFirst"], opts["sourceName"], opts["idPrefix"], c.get("assetIps"))
                if "error" in c:
                    with self.assertRaises(RowError) as ctx:
                        run()
                    self.assertEqual(str(ctx.exception), c["error"])
                    continue
                p = run()["payload"]
                got = {"id": p["id"], "recorded": p["recorded"], "action": p["action"], "outcome": p.get("outcome"),
                       "user": p["agent"][0]["who"]["identifier"]["value"], "address": p["agent"][0].get("network", {}).get("address")}
                for k, v in c["expect"].items():
                    self.assertEqual(got[k], v, k)


class NativeValues(unittest.TestCase):
    """Database drivers hand back dates and numbers, not text."""

    def test_naive_datetime_uses_the_source_zone(self):
        self.assertEqual(parse_time(datetime(2026, 3, 10, 14, 5, 9), "Africa/Lagos", True), "2026-03-10T13:05:09.000Z")

    def test_aware_datetime_is_kept(self):
        self.assertEqual(parse_time(datetime(2026, 3, 10, 14, 5, tzinfo=timezone.utc), "Africa/Lagos", True), "2026-03-10T14:05:00.000Z")

    def test_boolean_outcome_and_integer_record_id(self):
        p = to_audit_event({"time": datetime(2026, 1, 1), "user": "A", "patient": 77, "outcome": False, "record_id": 9}, "UTC", True, "db", "db1")["payload"]
        self.assertEqual((p["id"], p["outcome"], p["entity"][0]["what"]["reference"]), ("db1-9", "8", "Patient/77"))

    def test_action_words(self):
        self.assertEqual([action_code(x) for x in ("View", None, "INSERT", "modified", "purge")], ["R", "R", "C", "U", "D"])


if __name__ == "__main__":
    unittest.main()
