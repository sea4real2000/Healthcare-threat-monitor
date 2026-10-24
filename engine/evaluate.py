"""The evaluation harness.

One command measures the whole platform against ground truth:

  1. a baseline of normal hospital activity, which the models train on
  2. phase A: normal activity with scripted attacks mixed in
  3. a simulated analyst rules on every incident from phase A, and the detectors learn
  4. phase B: the same again, to measure what the feedback changed

Everything goes through the signed ingestion API, the same path live data takes.
Results are measured on simulated data with scripted attacks. They show that the
method works and can be measured. They are not a claim about a live hospital.

Run from the engine folder:  python -m evaluate --reset-data
"""

from __future__ import annotations

import argparse
import json
import os
import random
import statistics
import sys
import uuid
from datetime import datetime, timedelta, timezone

from psycopg.types.json import Jsonb

from detection.feedback import apply_pending
from detection.pipeline import Detector, connect
from simulator import scenarios
from simulator.client import ApiClient
from simulator.generators import Generators
from simulator.hospital import build_hospital, load_config
from simulator.runner import minute_records

DATA_TABLES = ["ground_truth", "scenario_runs", "feedback", "response_actions", "siem_outbox", "siem_inbox", "alerts",
               "incident_entities", "incidents", "model_training_labels", "detector_exceptions", "baseline_values",
               "ingest_rejects", "events", "ingest_batches", "engine_state"]


def log(msg: str) -> None:
    print(msg, file=sys.stderr, flush=True)


class Feeder:
    """Sends records through the ingestion API and records which ones belong to a scenario."""

    def __init__(self, client: ApiClient, conn, run_tag: str) -> None:
        self.client, self.conn, self.run_tag = client, conn, run_tag
        self.batches = 0
        self.sent = 0

    def send(self, records: list[tuple]) -> None:
        for i in range(0, len(records), 500):
            chunk = records[i:i + 500]
            batch_id = str(uuid.uuid5(uuid.NAMESPACE_URL, f"htm:{self.run_tag}:{self.batches}"))
            response = self.client.send_batch(batch_id, self.run_tag, [{"source": s, "payload": p} for _, s, p in chunk])
            if response.get("rejected"):
                raise RuntimeError(f"the API rejected records: {response.get('rejects')}")
            self.batches += 1
            self.sent += len(chunk)


def simulate(gen, hospital, feeder: Feeder, conn, detector: Detector | None, start: datetime, minutes: int,
             plan: list[dict], label: str) -> None:
    """Feeds one period, minute by minute, mixing in any scenario steps that fall due."""
    for m in range(minutes):
        t0 = start + timedelta(minutes=m)
        records = minute_records(gen, hospital, t0)
        for run in plan:
            due = [s for s in run["steps"] if t0 <= run["start"] + timedelta(seconds=s[0]) < t0 + timedelta(minutes=1)]
            if not due:
                continue
            with conn.cursor() as cur:
                for offset, source, payload, stage, _origin, _requires in due:
                    records.append((run["start"] + timedelta(seconds=offset), source, payload))
                    cur.execute("insert into ground_truth (source, source_event_id, scenario_run_id, stage) values (%s, %s, %s, %s) on conflict do nothing",
                                (source, scenarios.event_key(source, payload), run["id"], stage))
            conn.commit()
        records.sort(key=lambda r: r[0])
        feeder.send(records)
        if detector and (m % 30 == 29 or m == minutes - 1):
            while detector.process_new()["events"] >= 20000:
                pass
        if m % 240 == 239:
            log(f"  {label}: {m + 1} of {minutes} minutes, {feeder.sent} records sent")
    if detector:
        detector.process_new(flush=True)


def plan_scenarios(gen, conn, eval_id: int, start: datetime, minutes: int, per_kind: int, rng: random.Random) -> list[dict]:
    """Spreads scenarios across the phase and records each one as a scenario run."""
    names = [n for n in scenarios.SCENARIOS for _ in range(per_kind)]
    rng.shuffle(names)
    slot = (minutes - 60) / len(names)
    plan = []
    with conn.cursor() as cur:
        for i, name in enumerate(names):
            begin = start + timedelta(minutes=10 + i * slot + rng.uniform(0, max(slot - 45, 1)))
            sc = scenarios.build(name, gen, begin, 1.0)
            first = begin + timedelta(seconds=sc.steps[0][0])
            last = begin + timedelta(seconds=sc.steps[-1][0])
            cur.execute("""insert into scenario_runs (scenario, status, requested_by, started_at, finished_at, first_event_at, last_event_at, target, evaluation_run_id)
                values (%s, 'completed', 'evaluation', %s, %s, %s, %s, %s, %s) returning id""",
                        (name, first, last, first, last, Jsonb(sc.target()), eval_id))
            plan.append({"id": cur.fetchone()["id"], "name": name, "start": begin, "steps": sc.steps, "first": first, "last": last,
                         "hosts": set(sc.hosts), "users": set(sc.users)})
    conn.commit()
    return plan


def score_phase(conn, plan: list[dict], start: datetime, end: datetime, events_sent: int) -> dict:
    """Compares incidents with ground truth for one phase."""
    with conn.cursor() as cur:
        cur.execute("""select i.id, i.band, i.status, i.opened_at, i.last_activity_at, i.medium_at, i.high_at, i.hosts, i.users, i.detectors, i.category
            from incidents i where i.opened_at >= %s and i.opened_at < %s order by i.id""", (start, end))
        incidents = cur.fetchall()
        cur.execute("""select a.incident_id, g.scenario_run_id, min(a.occurred_at) as first_at
            from alerts a cross join lateral jsonb_array_elements(a.evidence) e
            join events ev on ev.id = (e->>'id')::bigint
            join ground_truth g on g.source = ev.source and g.source_event_id = ev.source_event_id
            where a.occurred_at >= %s and a.incident_id is not null group by 1, 2""", (start - timedelta(hours=1),))
        evidence_links = {(r["incident_id"], r["scenario_run_id"]): r["first_at"] for r in cur}
        cur.execute("""select a.detector_id, count(*) as alerts,
              count(*) filter (where exists (select 1 from jsonb_array_elements(a.evidence) e join events ev on ev.id = (e->>'id')::bigint
                join ground_truth g on g.source = ev.source and g.source_event_id = ev.source_event_id)) as on_attack
            from alerts a where a.occurred_at >= %s and a.occurred_at < %s group by 1 order by 1""", (start, end + timedelta(hours=1)))
        detectors = {r["detector_id"]: {"alerts": r["alerts"], "on_attack": r["on_attack"]} for r in cur}
    conn.rollback()

    # An incident can hold more than one attack when they touch the same people or machines.
    matched: dict[int, list[int]] = {}
    for inc in incidents:
        for run in plan:
            shares = bool(run["hosts"] & set(inc["hosts"])) or bool(run["users"] & set(inc["users"]))
            overlaps = inc["opened_at"] <= run["last"] + timedelta(minutes=15) and inc["last_activity_at"] >= run["first"] - timedelta(minutes=1)
            if shares and overlaps and (inc["id"], run["id"]) in evidence_links:
                matched.setdefault(inc["id"], []).append(run["id"])

    def reached(inc: dict, run: dict, column: str):
        """When this incident was at that band and already held evidence of this attack."""
        if inc[column] is None:
            return None
        return max((max(inc[column], evidence_links[(inc["id"], run["id"])]) - run["first"]).total_seconds(), 0.0)

    per_scenario: dict[str, dict] = {}
    runs_out = []
    for run in plan:
        mine = [i for i in incidents if run["id"] in matched.get(i["id"], [])]
        queue = [i for i in mine if i["band"] in ("medium", "high")]
        ttd = min((v for v in (reached(i, run, "medium_at") for i in queue) if v is not None), default=None)
        tth = min((v for v in (reached(i, run, "high_at") for i in queue) if v is not None), default=None)
        runs_out.append({"scenario": run["name"], "run_id": run["id"], "detected": bool(queue), "reached_high": tth is not None,
                         "seconds_to_detect": ttd, "seconds_to_high": tth, "incidents": [i["id"] for i in mine]})
        agg = per_scenario.setdefault(run["name"], {"runs": 0, "detected": 0, "reached_high": 0, "ttd": [], "tth": []})
        agg["runs"] += 1
        agg["detected"] += bool(queue)
        agg["reached_high"] += tth is not None
        if ttd is not None:
            agg["ttd"].append(ttd)
        if tth is not None:
            agg["tth"].append(tth)
    for agg in per_scenario.values():
        agg["detection_rate"] = agg["detected"] / agg["runs"]
        agg["median_seconds_to_detect"] = statistics.median(agg.pop("ttd")) if agg["ttd"] else None
        agg["median_seconds_to_high"] = statistics.median(agg.pop("tth")) if agg["tth"] else None

    queue = [i for i in incidents if i["band"] in ("medium", "high")]
    false_pos = [i for i in queue if i["id"] not in matched]
    hours = (end - start).total_seconds() / 3600
    by_category: dict[str, int] = {}
    for i in false_pos:
        by_category[i["category"]] = by_category.get(i["category"], 0) + 1
    total_runs = len(plan)
    detected = sum(r["detected"] for r in runs_out)
    return {
        "hours": hours, "events": events_sent, "scenario_runs": total_runs, "detected": detected,
        "detection_rate": detected / total_runs if total_runs else None,
        "queue_incidents": len(queue), "true_incidents": len(queue) - len(false_pos), "false_incidents": len(false_pos),
        "false_incidents_per_day": len(false_pos) / hours * 24,
        "false_incidents_high": sum(1 for i in false_pos if i["band"] == "high"),
        "precision": (len(queue) - len(false_pos)) / len(queue) if queue else None,
        "false_by_category": by_category, "low_band_incidents": sum(1 for i in incidents if i["band"] == "low"),
        "per_scenario": per_scenario, "runs": runs_out, "detectors": detectors,
        "queue_ids": [i["id"] for i in queue], "matched": {str(k): v for k, v in matched.items()},
        "merged_incidents": sum(1 for v in matched.values() if len(v) > 1),
    }


def simulated_analyst(conn, result: dict) -> dict:
    """Rules on every queued incident using ground truth, as a careful analyst would after investigating."""
    counts = {"confirmed": 0, "dismissed": 0}
    with conn.cursor() as cur:
        for incident_id in result["queue_ids"]:
            true = str(incident_id) in result["matched"]
            status, verdict, reason = ("confirmed", "true_positive", "confirmed_attack") if true else ("dismissed", "false_positive", "expected_activity")
            cur.execute("""update incidents set status = %s, decided_by_name = 'Simulated analyst', decided_at = now(), decision_reason = %s
                where id = %s and status = 'open'""", (status, reason, incident_id))
            if cur.rowcount:
                cur.execute("insert into feedback (incident_id, verdict, reason, created_by_name) values (%s, %s, %s, 'Simulated analyst')",
                            (incident_id, verdict, reason))
                cur.execute("select audit_append('system', 'evaluation', 'Simulated analyst', %s, 'incident', %s, %s)",
                            (f"incident.{status}", str(incident_id), Jsonb({"reason": reason})))
                counts[status] += 1
    conn.commit()
    return counts


def fmt_seconds(v) -> str:
    if v is None:
        return "not reached"
    return f"{v:.0f} s" if v < 120 else f"{v / 60:.1f} min"


def pct(v) -> str:
    return "n/a" if v is None else f"{v * 100:.0f}%"


def report(metrics: dict) -> str:
    a, b, cfg = metrics["phase_a"], metrics["phase_b"], metrics["config"]
    lines = [
        "# Evaluation report", "",
        f"Run finished {metrics['finished_at']}. Seed {cfg['seed']}.", "",
        "## What was measured", "",
        f"A simulated hospital produced {cfg['baseline_hours']} hours of normal activity for training, then two test phases of "
        f"{cfg['phase_hours']} hours each. Each phase mixed {a['scenario_runs']} scripted attacks into normal activity: "
        f"{cfg['per_kind']} of each of three kinds. Between the phases a simulated analyst ruled on every incident and the detectors learned from those decisions.", "",
        "All data is simulated and the attacks are scripted. These numbers show that the method works and can be measured. "
        "They are not a claim about performance in a live hospital.", "",
        "## Headline results", "",
        "| Measure | Before feedback | After feedback |", "| --- | --- | --- |",
        f"| Attacks detected | {a['detected']} of {a['scenario_runs']} ({pct(a['detection_rate'])}) | {b['detected']} of {b['scenario_runs']} ({pct(b['detection_rate'])}) |",
        f"| False incidents in the analyst queue per day | {a['false_incidents_per_day']:.1f} | {b['false_incidents_per_day']:.1f} |",
        f"| Of those, eligible for isolation | {a['false_incidents_high']} | {b['false_incidents_high']} |",
        f"| Share of queued incidents that were real | {pct(a['precision'])} | {pct(b['precision'])} |",
        f"| Low band incidents, logged only | {a['low_band_incidents']} | {b['low_band_incidents']} |",
        f"| Events processed | {a['events']:,} | {b['events']:,} |", "",
        "## By attack type", "",
        "| Attack | Phase | Detected | Reached high band | Median time to detect | Median time to high band |", "| --- | --- | --- | --- | --- | --- |",
    ]
    for name in sorted(a["per_scenario"]):
        for label, phase in (("Before feedback", a), ("After feedback", b)):
            s = phase["per_scenario"].get(name)
            if s:
                lines.append(f"| {name.replace('_', ' ')} | {label} | {s['detected']} of {s['runs']} | {s['reached_high']} of {s['runs']} | "
                             f"{fmt_seconds(s['median_seconds_to_detect'])} | {fmt_seconds(s['median_seconds_to_high'])} |")
    lines += ["", "Time to detect runs from the first malicious event to the moment an incident reached the analyst queue, measured in event time.", "",
              "## False incidents by category", "", "| Category | Before feedback | After feedback |", "| --- | --- | --- |"]
    for cat in sorted(set(a["false_by_category"]) | set(b["false_by_category"])):
        lines.append(f"| {cat} | {a['false_by_category'].get(cat, 0)} | {b['false_by_category'].get(cat, 0)} |")
    lines += ["", "## By detector", "", "| Detector | Alerts before | On real attacks | Alerts after | On real attacks |", "| --- | --- | --- | --- | --- |"]
    for det in sorted(set(a["detectors"]) | set(b["detectors"])):
        x, y = a["detectors"].get(det, {"alerts": 0, "on_attack": 0}), b["detectors"].get(det, {"alerts": 0, "on_attack": 0})
        lines.append(f"| {det} | {x['alerts']} | {x['on_attack']} | {y['alerts']} | {y['on_attack']} |")
    lines += ["", "## How to read this", "",
              "- An incident counts as a detection only when it shares a machine or person with the attack, overlaps it in time, and holds at least one malicious event as evidence.",
              "- The simulated analyst rules with perfect knowledge. A human analyst would be slower and would make some mistakes.",
              f"- The analyst made {metrics['analyst']['confirmed']} confirmations and {metrics['analyst']['dismissed']} dismissals between the phases.",
              "- Attack targets are chosen at random in each phase, so the two phases do not attack the same machines.",
              f"- Attacks that touch the same people or machines close together can land in one incident. That happened {a['merged_incidents']} times before feedback and {b['merged_incidents']} times after.",
              "- The same seed gives the same result. Rerun with a different seed to see how much the numbers move. The effect of feedback in particular varies a good deal from one draw to the next."]
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="evaluate", description="Measure detection against ground truth")
    p.add_argument("--baseline-hours", type=int, default=24)
    p.add_argument("--phase-hours", type=int, default=24)
    p.add_argument("--per-kind", type=int, default=4, help="scenarios of each kind in each phase")
    p.add_argument("--seed", type=int, default=11)
    p.add_argument("--start", default="2026-01-05T00:00:00+00:00", help="simulated start time. Fixed by default so results can be reproduced")
    p.add_argument("--reset-data", action="store_true", help="empty the event, alert and incident tables first")
    p.add_argument("--report", default="runs/evaluation_report.md")
    p.add_argument("--device-dataset", metavar="FOLDER",
                   help="folder of CICIoMT2024 feature CSV files. Device attacks then take their traffic shape from the dataset")
    p.add_argument("--min-detection-rate", type=float, default=0.0,
                   help="exit with an error when the detection rate after feedback is below this, for automated checks")
    p.add_argument("--publish", metavar="JSON_FILE",
                   help="store a finished report in this database so its Evaluation page shows it, then exit. "
                        "Use it to show results from a separate evaluation database on the live site")
    args = p.parse_args(argv)

    conn = connect()
    if args.publish:
        with open(args.publish, encoding="utf-8") as fh:
            metrics = json.load(fh)
        if not {"config", "phase_a", "phase_b"} <= set(metrics):
            print("That file is not an evaluation report written by this command.", file=sys.stderr)
            return 2
        with conn.cursor() as cur:
            cur.execute("""insert into evaluation_runs (finished_at, status, config, metrics, report_markdown)
                values (now(), 'completed', %s, %s, %s) returning id""", (Jsonb(metrics["config"]), Jsonb(metrics), report(metrics)))
            print(f"published as evaluation run {cur.fetchone()['id']}")
        conn.commit()
        return 0
    with conn.cursor() as cur:
        cur.execute("select (select count(*) from events) + (select count(*) from incidents) as n")
        busy = cur.fetchone()["n"]
        if busy and not args.reset_data:
            print("The database already holds events or incidents. Use a separate database for evaluation, "
                  "or pass --reset-data to empty the data tables first.", file=sys.stderr)
            return 2
        if args.reset_data:
            cur.execute("truncate " + ", ".join(DATA_TABLES) + " restart identity cascade")
            cur.execute("update models set version = 0, trained_at = null, training_rows = null, threshold = null, score_summary = null, feature_stats = null")
        cur.execute("insert into evaluation_runs (config) values (%s) returning id",
                    (Jsonb({"baseline_hours": args.baseline_hours, "phase_hours": args.phase_hours, "per_kind": args.per_kind, "seed": args.seed}),))
        eval_id = cur.fetchone()["id"]
    conn.commit()

    try:
        client = ApiClient(os.environ.get("HTM_API_URL", ""), os.environ.get("HTM_COLLECTOR_ID", "sim_hospital_01"), os.environ.get("HTM_COLLECTOR_SECRET", ""))
        hospital = build_hospital(load_config())
        client.send_inventory(hospital.inventory())
        rng = random.Random(args.seed)
        tag = f"eval{eval_id}"
        gen = Generators(hospital, rng, tag)
        if args.device_dataset:
            from simulator.dataset import load, summary
            gen.device_dataset = load(args.device_dataset)
            log(f"device dataset: {summary(gen.device_dataset)}")
        feeder = Feeder(client, conn, tag)
        phase = args.phase_hours * 60
        # A fixed simulated calendar, so the same seed gives the same result on any day it is run.
        t0 = datetime.fromisoformat(args.start).astimezone(timezone.utc).replace(second=0, microsecond=0)
        if t0 + timedelta(hours=args.baseline_hours + 2 * args.phase_hours) > datetime.now(timezone.utc):
            raise RuntimeError("--start must be far enough in the past for the whole evaluation to fit before now")
        t1 = t0 + timedelta(hours=args.baseline_hours)
        t2 = t1 + timedelta(minutes=phase)
        t3 = t2 + timedelta(minutes=phase)

        log(f"baseline: {args.baseline_hours} hours of normal activity")
        simulate(gen, hospital, feeder, conn, None, t0, args.baseline_hours * 60, [], "baseline")
        detector = Detector(conn)
        with conn.cursor() as cur:
            cur.execute("select coalesce(max(id), 0) as id from events")
            detector.set_state("event_cursor", cur.fetchone()["id"])
        conn.commit()
        log(f"training: {detector.train(until=t1)}")

        sent = feeder.sent
        log("phase A: before feedback")
        plan_a = plan_scenarios(gen, conn, eval_id, t1, phase, args.per_kind, rng)
        simulate(gen, hospital, feeder, conn, detector, t1, phase, plan_a, "phase A")
        result_a = score_phase(conn, plan_a, t1, t2, feeder.sent - sent)

        analyst = simulated_analyst(conn, result_a)
        apply_pending(conn, detector.settings)
        log(f"analyst: {analyst}. retraining: {detector.train(until=t2)}")

        sent = feeder.sent
        log("phase B: after feedback")
        plan_b = plan_scenarios(gen, conn, eval_id, t2, phase, args.per_kind, rng)
        simulate(gen, hospital, feeder, conn, detector, t2, phase, plan_b, "phase B")
        result_b = score_phase(conn, plan_b, t2, t3, feeder.sent - sent)

        metrics = {"config": {"baseline_hours": args.baseline_hours, "phase_hours": args.phase_hours, "per_kind": args.per_kind, "seed": args.seed, "start": args.start,
                              "device_dataset": bool(args.device_dataset)},
                   "finished_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"), "analyst": analyst,
                   "phase_a": result_a, "phase_b": result_b, "events_total": feeder.sent}
        text = report(metrics)
        with conn.cursor() as cur:
            cur.execute("update evaluation_runs set finished_at = now(), status = 'completed', metrics = %s, report_markdown = %s where id = %s",
                        (Jsonb(metrics), text, eval_id))
        conn.commit()
        os.makedirs(os.path.dirname(args.report) or ".", exist_ok=True)
        with open(args.report, "w", encoding="utf-8") as fh:
            fh.write(text)
        with open(os.path.splitext(args.report)[0] + ".json", "w", encoding="utf-8") as fh:
            json.dump(metrics, fh, indent=2, default=str)
        print(text)
        if (result_b["detection_rate"] or 0.0) < args.min_detection_rate:
            print(f"RESULT: FAIL. Detection rate {result_b['detection_rate']:.2f} is below the required {args.min_detection_rate:.2f}", file=sys.stderr)
            return 1
        return 0
    except Exception:
        conn.rollback()
        with conn.cursor() as cur:
            cur.execute("update evaluation_runs set finished_at = now(), status = 'failed' where id = %s", (eval_id,))
        conn.commit()
        raise


if __name__ == "__main__":
    sys.exit(main())
