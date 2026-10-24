"""Checks the learning period against a real database, from start to finish.

Run on a fresh database that has every migration applied, with the engine folder as the working folder:
    DATABASE_URL=... python -m db_checks.learning_period
It changes settings, so never point it at a database in use. Exits non zero on the first failure.
"""

from __future__ import annotations

import sys
import uuid
from datetime import datetime, timezone

from psycopg.types.json import Jsonb

from detection.pipeline import Detector, connect


def fail(msg: str) -> None:
    print(f"FAIL: {msg}")
    sys.exit(1)


def main() -> int:
    conn = connect()
    with conn.cursor() as cur:
        cur.execute("update settings set value = 'false'::jsonb where key = 'engine.simulate'")
        cur.execute("update settings set value = '7'::jsonb where key = 'learning.days'")
        cur.execute("delete from learning_periods")
        cur.execute("delete from baseline_values where scope = 'dns_new_domain'")
        cur.execute("select coalesce(max(id), 0) as id from events")
        cursor = cur.fetchone()["id"]
        cur.execute("insert into engine_state (key, value) values ('event_cursor', %s) on conflict (key) do update set value = excluded.value", (Jsonb(cursor),))
        cur.execute("delete from engine_state where key = 'retrain_requested'")
        cur.execute("insert into collectors (id, name) values ('learning_check', 'Learning check') on conflict do nothing")
    conn.commit()
    det = Detector(conn)
    # Alerts are deduplicated, so every run uses its own computer and domain names.
    run = uuid.uuid4().hex[:8]
    host = f"WSLC{run}".upper()
    name = lambda d: d if d == "secureloginportal.example" else f"{d.split('.')[0]}-{run}.example"

    def send(domains: list[str]) -> dict:
        with conn.cursor() as cur:
            cur.execute("insert into ingest_batches (collector_id, batch_id) values ('learning_check', %s) returning id", (str(uuid.uuid4()),))
            batch = cur.fetchone()["id"]
            for d in domains:
                cur.execute("""insert into events (batch_pk, source, source_event_id, occurred_at, category, action, outcome, host, src_ip, attributes, raw)
                    values (%s, 'dns', %s, %s, 'dns', 'dns_query', 'success', %s, '10.0.0.5',
                            %s, '{}'::jsonb)""",
                            (batch, str(uuid.uuid4()), datetime.now(timezone.utc), host,
                             Jsonb({"query_name": f"www.{name(d)}", "registered_domain": name(d), "response_code": "NOERROR"})))
        conn.commit()
        return det.process_new()

    def alerts(detector_id: str) -> int:
        with conn.cursor() as cur:
            cur.execute("select count(*) as n from alerts where detector_id = %s", (detector_id,))
            n = cur.fetchone()["n"]
        conn.commit()
        return n

    def period() -> dict | None:
        with conn.cursor() as cur:
            cur.execute("select *, ends_at > now() + interval '6 days' as long_enough from learning_periods where source = 'dns'")
            row = cur.fetchone()
        conn.commit()
        return row

    before_new, before_threat = alerts("dns_new_domain"), alerts("dns_threat_list")

    # A new installation: every domain is new, but none is reported while learning.
    send(["hospital-portal.example", "labsupplier.example", "pharmacy-wholesale.example", "hospital-portal.example"])
    row = period()
    if not row:
        fail("no learning period started when the first DNS record arrived")
    if row["finished_at"] is not None or not row["long_enough"]:
        fail(f"the learning period should run for the configured 7 days: {row}")
    if row["events"] != 4 or row["values_learned"] != 3:
        fail(f"expected 4 records and 3 values learned, got {row['events']} and {row['values_learned']}")
    if alerts("dns_new_domain") != before_new:
        fail("a new domain was reported during the learning period")
    print("PASS: new domains are learned, not reported, during the learning period")

    # A clear sign of attack is reported even while learning.
    send(["secureloginportal.example"])
    if alerts("dns_threat_list") != before_threat + 1:
        fail("a known malicious domain was not reported during the learning period")
    print("PASS: a clear sign of attack is still reported during the learning period")

    # The administrator finishes learning early. The detector ends it and asks for retraining.
    with conn.cursor() as cur:
        cur.execute("update learning_periods set ends_at = now(), finished_by = 'learning check' where source = 'dns'")
    conn.commit()
    send(["labsupplier.example"])
    row = period()
    if row["finished_at"] is None or row["finished_by"] != "learning check":
        fail(f"learning did not finish when asked: {row}")
    if not det.state("retrain_requested"):
        fail("finishing learning did not ask for the detectors to retrain")
    if alerts("dns_new_domain") != before_new:
        fail("a domain learned during the learning period was reported afterwards")
    print("PASS: learning finished when asked, retraining was requested, and learned domains stay quiet")

    # After learning, something genuinely new is reported.
    send(["never-seen-before.example"])
    if alerts("dns_new_domain") != before_new + 1:
        fail("a new domain was not reported after learning finished")
    print("PASS: a new domain is reported once learning has finished")

    with conn.cursor() as cur:
        cur.execute("select count(*) as n from audit_log where action in ('learning.started', 'learning.finished') and subject_id = 'dns'")
        if cur.fetchone()["n"] < 2:
            fail("the start and finish of learning were not written to the audit log")
        cur.execute("select ok from audit_verify()")
        if not cur.fetchone()["ok"]:
            fail("audit chain broken")
    print("PASS: learning period recorded in the audit log, chain intact")
    return 0


if __name__ == "__main__":
    sys.exit(main())
