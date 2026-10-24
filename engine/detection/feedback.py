"""Turns analyst decisions into changes in how the detectors behave.

A confirmed incident keeps its activity out of future training. A dismissal
marked as expected activity teaches the detector that raised it:

  new value rule   the value becomes part of that entity's baseline
  threshold rule   that entity needs a higher count before the rule fires again
  match rule       the rule is silenced for that entity
  model            that entity must sit further from normal than the dismissed window,
                   and the window joins later training as a heavily weighted normal example

Every change is specific to one entity, so a busy file server learning to
tolerate its archive job does not make the rule blind anywhere else.
"""

from __future__ import annotations

import math

from psycopg.types.json import Jsonb

LEARNING_REASON = "expected_activity"


def apply_pending(conn, settings: dict) -> int:
    """Applies every decision the detectors have not learned from yet. Returns how many were applied."""
    with conn.cursor() as cur:
        cur.execute("select id, incident_id, verdict, reason, created_by_name from feedback where applied_at is null order by id")
        pending = cur.fetchall()
        for fb in pending:
            cur.execute("""select a.id, a.detector_type, a.detector_id, a.entity, a.observed, a.score, a.window_start, a.baseline, r.kind
                from alerts a left join rules r on r.id = a.detector_id and a.detector_type = 'rule'
                where a.incident_id = %s""", (fb["incident_id"],))
            alerts = cur.fetchall()
            applied: list[dict] = []
            for a in alerts:
                if a["detector_type"] == "model" and a["window_start"] is not None:
                    # Only a dismissal marked as expected activity teaches the model. Other dismissals are recorded and no more.
                    label = "attack" if fb["verdict"] == "true_positive" else "normal"
                    vector = a["baseline"] if label == "normal" and fb["reason"] == LEARNING_REASON and (a["baseline"] or {}).get("vector") else None
                    cur.execute("""insert into model_training_labels (model_id, entity, window_start, label, features, source_incident)
                        values (%s, %s, %s, %s, %s, %s)
                        on conflict (model_id, entity, window_start) do update set label = excluded.label, features = excluded.features""",
                                (a["detector_id"], a["entity"], a["window_start"], label, Jsonb(vector) if vector else None, fb["incident_id"]))
                if fb["verdict"] != "false_positive" or fb["reason"] != LEARNING_REASON:
                    continue
                change = None
                if a["detector_type"] == "model" and a["observed"] is not None:
                    change = _exception(cur, a, "threshold", float(a["observed"]) * settings["feedback.model_margin"], fb)
                elif a["kind"] == "new_value" and a["baseline"]:
                    b = a["baseline"]
                    cur.execute("""insert into baseline_values (scope, entity, value, origin) values (%s, %s, %s, 'feedback')
                        on conflict do nothing""", (b["scope"], b["entity"], b["value"]))
                    change = {"detector": a["detector_id"], "entity": b["entity"], "learned_value": b["value"]}
                    cur.execute("""select count(distinct entity) as n from baseline_values
                        where scope = %s and value = %s and origin = 'feedback' and entity <> '*'""", (b["scope"], b["value"]))
                    if cur.fetchone()["n"] >= settings["feedback.global_after_entities"]:
                        cur.execute("""insert into baseline_values (scope, entity, value, origin) values (%s, '*', %s, 'feedback')
                            on conflict do nothing""", (b["scope"], b["value"]))
                        change["normal_for_all"] = True
                elif a["kind"] == "threshold" and a["observed"] is not None:
                    change = _exception(cur, a, "threshold", math.ceil(float(a["observed"]) * settings["feedback.threshold_factor"]), fb)
                elif a["kind"] == "match":
                    change = _exception(cur, a, "suppress", None, fb)
                if change:
                    applied.append(change)
            cur.execute("update feedback set applied_at = now(), applied = %s where id = %s", (Jsonb(applied), fb["id"]))
            cur.execute("select audit_append('system', 'detection', 'Detection service', 'feedback.applied', 'incident', %s, %s)",
                        (str(fb["incident_id"]), Jsonb({"verdict": fb["verdict"], "reason": fb["reason"], "changes": applied})))
    conn.commit()
    return len(pending)


def _exception(cur, alert: dict, kind: str, value, fb: dict) -> dict:
    cur.execute("""insert into detector_exceptions (detector_type, detector_id, entity, kind, value, reason, source_incident, created_by)
        values (%s, %s, %s, %s, %s, %s, %s, %s)
        on conflict (detector_type, detector_id, entity, kind) do update
          set value = greatest(detector_exceptions.value, excluded.value), source_incident = excluded.source_incident""",
                (alert["detector_type"], alert["detector_id"], alert["entity"], kind, value, fb["reason"], fb["incident_id"], fb["created_by_name"]))
    out = {"detector": alert["detector_id"], "entity": alert["entity"], "change": kind}
    if value is not None:
        out["value"] = round(float(value), 4)
    return out
