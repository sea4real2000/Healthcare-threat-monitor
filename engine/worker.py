"""The platform's background service.

One process does everything that has to run continuously:

  the hospital simulator, sending logs at real speed through the ingestion API
  detection: rules, models and correlation over new events
  learning from analyst decisions, and retraining
  attack scenarios requested from the console
  the simulated endpoint connector, which carries out isolation requests
  forwarding incidents to the SIEM
  retention

Run from the engine folder:  python -m worker
"""

from __future__ import annotations

import os
import random
import signal
import sys
import time
import uuid
from datetime import datetime, timedelta, timezone

import psycopg
from psycopg.types.json import Jsonb

import forwarding
from detection.feedback import apply_pending
from detection.pipeline import Detector, connect
from simulator import scenarios
from simulator.client import ApiClient, ApiError
from simulator.generators import Generators
from simulator.hospital import build_hospital, load_config
from simulator.runner import minute_records

VERSION = "0.8.1"


def log(msg: str) -> None:
    print(f"{datetime.now(timezone.utc):%H:%M:%S} {msg}", file=sys.stderr, flush=True)


class Worker:
    def __init__(self) -> None:
        self.conn = connect()
        self.api_url = os.environ.get("HTM_API_URL", "")
        self.client = ApiClient(self.api_url, os.environ.get("HTM_COLLECTOR_ID", "sim_hospital_01"), os.environ.get("HTM_COLLECTOR_SECRET", ""))
        self.hospital = build_hospital(load_config())
        self.run_tag = f"live{int(time.time())}"
        self.gen = Generators(self.hospital, random.Random(), self.run_tag)
        if os.environ.get("HTM_DEVICE_DATASET"):
            # Optional: shape device attack traffic from the CICIoMT2024 dataset.
            from simulator.dataset import load, summary
            self.gen.device_dataset = load(os.environ["HTM_DEVICE_DATASET"])
            log(f"device dataset loaded: {summary(self.gen.device_dataset)}")
        self.batches = 0
        self.detector = Detector(self.conn)
        self.next_minute = datetime.now(timezone.utc).replace(second=0, microsecond=0)
        self.active: dict[int, dict] = {}
        self.last = {"connector": 0.0, "prune": 0.0, "retrain": time.time(), "auto": time.time(), "heartbeat": 0.0}
        self.stopping = False
        self.sources = None

    @property
    def s(self) -> dict:
        return self.detector.settings

    # Sending

    def send(self, records: list[tuple]) -> None:
        for i in range(0, len(records), 500):
            chunk = records[i:i + 500]
            batch_id = str(uuid.uuid5(uuid.NAMESPACE_URL, f"htm:{self.run_tag}:{self.batches}"))
            self.client.send_batch(batch_id, self.run_tag, [{"source": s, "payload": p} for _, s, p in chunk])
            self.batches += 1

    # Start up

    def bootstrap(self) -> None:
        """On a new installation, builds a day of history so the models have something to learn from."""
        if self.s["engine.simulate"]:
            # Only the simulated hospital registers its own staff and machines. A real hospital enters its own in Setup.
            self.client.send_inventory(self.hospital.inventory())
        with self.conn.cursor() as cur:
            cur.execute("select id from assets where status = 'isolated'")
            self.gen.isolated = {r["id"] for r in cur}
            cur.execute("update scenario_runs set status = 'failed', finished_at = now(), note = 'service restarted' where status = 'running'")
            cur.execute("select count(*) as n, max(occurred_at) as newest from events")
            have = cur.fetchone()
        self.conn.commit()
        hours = int(self.s["engine.bootstrap_hours"])
        stale = have["newest"] is None or have["newest"] < datetime.now(timezone.utc) - timedelta(hours=2)
        if self.s["engine.simulate"] and hours > 0 and stale:
            log(f"building {hours} hours of history")
            start = self.next_minute - timedelta(hours=hours)
            pending: list[tuple] = []
            for m in range(hours * 60):
                pending.extend(minute_records(self.gen, self.hospital, start + timedelta(minutes=m)))
                if len(pending) >= 500 or m == hours * 60 - 1:
                    self.send(pending)
                    pending = []
            with self.conn.cursor() as cur:
                # History is for learning, not for alerting. Detection starts from here.
                cur.execute("select coalesce(max(id), 0) as id from events")
                self.detector.set_state("event_cursor", cur.fetchone()["id"])
            self.conn.commit()
        if not self.detector.trained():
            log(f"training: {self.detector.train()}")

    # Recurring work

    def simulate(self) -> None:
        if not self.s["engine.simulate"]:
            self.next_minute = datetime.now(timezone.utc).replace(second=0, microsecond=0)
            return
        now = datetime.now(timezone.utc)
        # Catch up at most ten minutes after a pause, so a long outage does not cause a flood.
        if now - self.next_minute > timedelta(minutes=10):
            self.next_minute = now.replace(second=0, microsecond=0) - timedelta(minutes=10)
        while self.next_minute + timedelta(minutes=1) <= now:
            self.send(minute_records(self.gen, self.hospital, self.next_minute))
            self.next_minute += timedelta(minutes=1)

    def run_scenarios(self) -> None:
        if not self.s["engine.simulate"]:
            # Scenarios write made up attack records. On a real hospital's installation they would mix with its real data.
            with self.conn.cursor() as cur:
                cur.execute("""update scenario_runs set status = 'failed', finished_at = now(),
                    note = 'Not run: the simulated hospital is switched off on this installation' where status = 'requested'""")
            self.conn.commit()
            return
        with self.conn.cursor() as cur:
            cur.execute("select id, scenario from scenario_runs where status = 'requested' order by id")
            for row in cur.fetchall():
                start = datetime.now(timezone.utc)
                try:
                    sc = scenarios.build(row["scenario"], self.gen, start, float(self.s["scenario.time_scale"]))
                except ValueError as err:
                    cur.execute("update scenario_runs set status = 'failed', finished_at = now(), note = %s where id = %s", (str(err), row["id"]))
                    continue
                self.active[row["id"]] = {"start": start, "steps": sc.steps, "at": 0, "sent": 0, "withheld": 0, "done": set(), "blocked": set()}
                cur.execute("update scenario_runs set status = 'running', started_at = now(), target = %s where id = %s", (Jsonb(sc.target()), row["id"]))
                cur.execute("select audit_append('system', 'simulator', 'Hospital simulator', 'scenario.started', 'scenario_run', %s, %s)",
                            (str(row["id"]), Jsonb({"scenario": row["scenario"], **sc.target()})))
                log(f"scenario {row['scenario']} started as run {row['id']}")
        self.conn.commit()
        now = datetime.now(timezone.utc)
        for run_id, run in list(self.active.items()):
            due = []
            while run["at"] < len(run["steps"]) and run["start"] + timedelta(seconds=run["steps"][run["at"]][0]) <= now:
                offset, source, payload, stage, origin, requires = run["steps"][run["at"]]
                run["at"] += 1
                # A step is withheld when its machine is isolated, or when an earlier stage it depends on was stopped.
                if (origin and origin in self.gen.isolated) or (requires and (requires in run["blocked"] or requires not in run["done"])):
                    run["withheld"] += 1
                    run["blocked"].add(stage)
                    continue
                run["done"].add(stage)
                due.append((run["start"] + timedelta(seconds=offset), source, payload, stage))
            if due:
                with self.conn.cursor() as cur:
                    cur.executemany("insert into ground_truth (source, source_event_id, scenario_run_id, stage) values (%s, %s, %s, %s) on conflict do nothing",
                                    [(s, scenarios.event_key(s, p), run_id, stage) for _, s, p, stage in due])
                    cur.execute("""update scenario_runs set first_event_at = coalesce(first_event_at, %s), last_event_at = %s where id = %s""",
                                (due[0][0], due[-1][0], run_id))
                self.conn.commit()
                self.send([(t, s, p) for t, s, p, _ in due])
                run["sent"] += len(due)
            left = run["steps"][run["at"]:]
            # Nothing more can happen when every remaining step is on an isolated machine or depends on a stopped stage.
            stopped = bool(left) and all((o and o in self.gen.isolated) or (r and (r in run["blocked"] or r not in run["done"])) for *_, o, r in left)
            if not left or stopped:
                withheld = run["withheld"] + len(left)
                # Contained means isolation stopped the attack before its impact stage.
                contained = withheld > 0 and "impact" not in run["done"]
                with self.conn.cursor() as cur:
                    cur.execute("update scenario_runs set status = %s, finished_at = now(), note = %s where id = %s",
                                ("contained" if contained else "completed", f"{run['sent']} records sent, {withheld} withheld by isolation", run_id))
                self.conn.commit()
                del self.active[run_id]
                log(f"scenario run {run_id} finished")

    def auto_scenario(self) -> None:
        every = float(self.s["scenario.auto_interval_minutes"])
        if self.s["engine.simulate"] and every > 0 and time.time() - self.last["auto"] >= every * 60 and not self.active:
            self.last["auto"] = time.time()
            with self.conn.cursor() as cur:
                cur.execute("insert into scenario_runs (scenario, requested_by) values (%s, 'schedule')", (random.choice(scenarios.SCENARIOS),))
            self.conn.commit()

    def connector(self) -> None:
        """The simulated endpoint product. It reads isolation requests through the same signed API a real connector would use."""
        if time.time() - self.last["connector"] < float(self.s["response.connector_poll_seconds"]):
            return
        self.last["connector"] = time.time()
        if not self.s.get("response.simulated_connector", True):
            # A real connector is in charge. Mirror what it has done, so isolated machines fall silent here too.
            with self.conn.cursor() as cur:
                cur.execute("select id from assets where status = 'isolated'")
                self.gen.isolated = {r["id"] for r in cur}
            self.conn.commit()
            return
        for action in self.client.request("GET", "/api/response/actions").get("actions", []):
            if action["action"] == "isolate":
                self.gen.isolated.add(action["asset_id"])
            else:
                self.gen.isolated.discard(action["asset_id"])
            self.client.request("POST", f"/api/response/actions/{action['id']}/ack", {"status": "acknowledged", "note": "simulated endpoint"})
            log(f"{action['action']} carried out on {action['asset_id']}")

    def demo_release(self) -> None:
        """While the public demo is on, machines isolated for a while are released, so the next visitor finds the hospital running."""
        minutes = float(self.s.get("demo.auto_release_minutes", 0) or 0)
        if not self.s.get("demo.enabled", False) or minutes <= 0 or time.time() - self.last.get("demo", 0.0) < 60:
            return
        self.last["demo"] = time.time()
        with self.conn.cursor() as cur:
            cur.execute("""
                select a.id from assets a
                where a.status = 'isolated'
                  and not exists (select 1 from response_actions w where w.asset_id = a.id and w.status = 'requested')
                  and (select max(r.acknowledged_at) from response_actions r
                       where r.asset_id = a.id and r.action = 'isolate' and r.status = 'acknowledged') < now() - make_interval(secs => %s)""",
                        (int(minutes * 60),))
            for row in cur.fetchall():
                cur.execute("""insert into response_actions (asset_id, action, requested_by_name) values (%s, 'release', 'Demo reset') returning id""",
                            (row["id"],))
                action_id = cur.fetchone()["id"]
                cur.execute("select audit_append('system', 'demo_reset', 'Demo reset', 'release.approved', 'asset', %s, %s)",
                            (row["id"], Jsonb({"action_id": action_id, "after_minutes": minutes})))
                log(f"demo reset: release requested for {row['id']}")
        self.conn.commit()

    def record_sources(self) -> None:
        """Connections to the hospital's own records databases, set up in the console under Sources."""
        if time.time() - self.last.get("sources", 0.0) < 5:
            return
        self.last["sources"] = time.time()
        if not os.environ.get("SOURCES_SECRET"):
            return
        if self.sources is None:
            from connectors.records_db import RecordSources
            self.sources = RecordSources(self.conn, self.client, log)
        self.sources.run(self.s)

    def retrain(self) -> None:
        asked = self.detector.state("retrain_requested")
        every = float(self.s["engine.retrain_hours"])
        if asked or (every > 0 and time.time() - self.last["retrain"] >= every * 3600):
            self.last["retrain"] = time.time()
            log(f"retraining: {self.detector.train()}")
            with self.conn.cursor() as cur:
                cur.execute("delete from engine_state where key = 'retrain_requested'")
            self.conn.commit()

    def prune(self) -> None:
        if time.time() - self.last["prune"] < 1800:
            return
        self.last["prune"] = time.time()
        with self.conn.cursor() as cur:
            cur.execute("delete from events where occurred_at < now() - make_interval(hours => %s)", (int(self.s["retention.events_hours"]),))
            removed = cur.rowcount
            cur.execute("""delete from ingest_batches b where b.received_at < now() - make_interval(hours => %s)
                and not exists (select 1 from events e where e.batch_pk = b.id)""", (int(self.s["retention.events_hours"]),))
            cur.execute("delete from siem_inbox where received_at < now() - interval '7 days'")
            cur.execute("delete from rate_limits where window_start < now() - interval '1 hour'")
            cur.execute("delete from sessions where expires_at < now()")
        self.conn.commit()
        if removed:
            log(f"retention removed {removed} old events")

    def heartbeat(self, stats: dict) -> None:
        if time.time() - self.last["heartbeat"] < 10:
            return
        self.last["heartbeat"] = time.time()
        self.detector.set_state("heartbeat", {"at": datetime.now(timezone.utc).isoformat(), "version": VERSION,
                                              "simulating": bool(self.s["engine.simulate"]), "trained": self.detector.trained(),
                                              "running_scenarios": len(self.active), **stats})
        self.conn.commit()

    def loop(self) -> None:
        self.bootstrap()
        log("running")
        while not self.stopping:
            started = time.time()
            try:
                self.simulate()
                self.run_scenarios()
                stats = self.detector.process_new()
                if apply_pending(self.conn, self.s):
                    self.detector.reload(force=True)
                forwarding.flush(self.conn, self.s, self.api_url)
                self.connector()
                self.auto_scenario()
                self.demo_release()
                self.record_sources()
                self.retrain()
                self.prune()
                self.heartbeat(stats)
            except (ApiError, RuntimeError, OSError, psycopg.Error) as err:
                # The console or the database was unreachable. Start again from a clean connection.
                log(f"error: {err}")
                time.sleep(5)
                try:
                    self.conn.rollback()
                except psycopg.Error:
                    pass
                if self.conn.closed or self.conn.broken:
                    try:
                        self.conn = connect()
                        self.detector = Detector(self.conn)
                        self.detector.train()
                    except (psycopg.Error, RuntimeError) as again:
                        log(f"still unreachable: {again}")
                continue
            time.sleep(max(0.2, float(self.s.get("engine.poll_seconds", 2)) - (time.time() - started)))
        log("stopped")


def main() -> int:
    worker = Worker()
    signal.signal(signal.SIGTERM, lambda *_: setattr(worker, "stopping", True))
    try:
        worker.loop()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
