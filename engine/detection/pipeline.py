"""The detection pipeline.

Reads new events from the database in order, runs every rule and model over
them, stores alerts, and groups related alerts into incidents with one
confidence score each. Nothing here reads the ground truth table.
"""

from __future__ import annotations

from collections import Counter

import os
from datetime import datetime, timedelta, timezone

import psycopg
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

from .models import WindowModel, all_models
from .rules import Draft, RuleEngine

EVENT_COLUMNS = """id, source, occurred_at, category, action, outcome, actor_user, host, host(src_ip) as src_ip,
    host(dst_ip) as dst_ip, dst_port, protocol, patient_ref, bytes_out, bytes_in, attributes"""
CATEGORY_RANK = ["ransomware", "devices", "endpoint", "records", "access", "network"]


def connect(url: str | None = None) -> psycopg.Connection:
    url = url or os.environ.get("DATABASE_URL", "")
    if not url:
        raise RuntimeError("DATABASE_URL is not set")
    # Supabase transaction pooling does not support prepared statements.
    return psycopg.connect(url, row_factory=dict_row, prepare_threshold=None, autocommit=False)


class Context:
    """Inventory facts used to enrich events: who the actor is, what the asset is, whose patient it is."""

    def __init__(self) -> None:
        self.staff: dict[str, dict] = {}
        self.assets: dict[str, dict] = {}
        self.by_ip: dict[str, str] = {}
        self.patients: dict[str, dict] = {}

    def load(self, conn) -> None:
        with conn.cursor() as cur:
            cur.execute("select id, role, department_id as department, status from staff")
            self.staff = {r["id"]: r for r in cur}
            cur.execute("select id, kind, role, department_id as department, zone, host(ip) as ip from assets")
            self.assets = {r["id"]: r for r in cur}
            self.by_ip = {r["ip"]: r["id"] for r in self.assets.values() if r["ip"]}
            cur.execute("select ref, department_id as department, flag from patients")
            self.patients = {r["ref"]: r for r in cur}

    def enrich(self, ev: dict) -> dict:
        ev["attributes"] = ev.get("attributes") or {}
        actor = self.staff.get(ev["actor_user"]) if ev.get("actor_user") else None
        ev["actor"] = actor or {}
        ev["asset"] = self.assets.get(ev["host"], {}) if ev.get("host") else {}
        src = self.by_ip.get(ev["src_ip"]) if ev.get("src_ip") else None
        dst = self.by_ip.get(ev["dst_ip"]) if ev.get("dst_ip") else None
        ev["src_host"], ev["dst_host"] = src, dst
        ev["src_asset"] = self.assets.get(src, {}) if src else {}
        ev["dst_asset"] = self.assets.get(dst, {}) if dst else {}
        patient = self.patients.get(ev["patient_ref"]) if ev.get("patient_ref") else None
        ev["patient"] = patient or {}
        ev["same_department"] = (actor["department"] == patient["department"]) if actor and patient else None
        ev["time"] = {"hour": ev["occurred_at"].astimezone(timezone.utc).hour}
        return ev


def combine(confidences: list[float]) -> float:
    """Independent detectors agreeing: the chance that at least one of them is right."""
    miss = 1.0
    for c in confidences:
        miss *= 1.0 - min(max(c, 0.0), 0.999)
    return 1.0 - miss


def band_for(confidence: float, sources: int, settings: dict) -> tuple[float, str]:
    """Caps confidence when too few independent log sources agree, then names the band."""
    if sources < settings["detection.high_min_sources"]:
        confidence = min(confidence, settings["detection.single_source_cap"])
    if confidence >= settings["detection.band_high"]:
        return confidence, "high"
    if confidence >= settings["detection.band_medium"]:
        return confidence, "medium"
    return confidence, "low"


class Detector:
    def __init__(self, conn: psycopg.Connection) -> None:
        self.conn = conn
        self.ctx = Context()
        self.rules = RuleEngine()
        self.models: list[WindowModel] = all_models()
        self.settings: dict = {}
        self.copy: dict = {}
        self.model_rows: dict = {}
        self.watermark: datetime | None = None
        self.config_stamp = None
        # Kinds of log still in their learning period, and every kind that has had one.
        self.learning: set[str] = set()
        self.learning_known: set[str] | None = None
        self.reload(force=True)

    # Configuration

    def reload(self, force: bool = False) -> None:
        """Picks up edits to rules, exceptions, baselines, settings and inventory."""
        with self.conn.cursor() as cur:
            cur.execute("""select (select coalesce(max(updated_at), 'epoch') from rules)::text
                || (select count(*) from rules) || (select count(*) from detector_exceptions)
                || (select count(*) from baseline_values) || (select coalesce(max(updated_at), 'epoch') from settings)::text
                || (select count(*) from assets) || (select count(*) from patients)
                || (select coalesce(max(updated_at), 'epoch') from staff)::text as stamp""")
            stamp = cur.fetchone()["stamp"]
            if not force and stamp == self.config_stamp:
                self.conn.rollback()
                return
            self.config_stamp = stamp
            cur.execute("select key, value from settings")
            self.settings = {r["key"]: r["value"] for r in cur}
            cur.execute("select key, value from copy where key like 'incident.title.%' or key like 'model.%'")
            self.copy = {r["key"]: r["value"] for r in cur}
            cur.execute("select * from rules where enabled order by id")
            rows = cur.fetchall()
            self.rules.load_rules(rows)
            for row in rows:
                error = self.rules.errors.get(row["id"])
                if error != row["load_error"]:
                    # Leave updated_at alone here, so recording an error does not look like an edit.
                    cur.execute("update rules set load_error = %s where id = %s", (error, row["id"]))
            cur.execute("select scope, entity, value from baseline_values")
            self.rules.load_baseline([(r["scope"], r["entity"], r["value"]) for r in cur])
            cur.execute("select detector_type, detector_id, entity, kind, value from detector_exceptions")
            exceptions = cur.fetchall()
            self.rules.load_exceptions([(r["detector_id"], r["entity"], r["kind"], r["value"]) for r in exceptions if r["detector_type"] == "rule"])
            for model in self.models:
                mine = [r for r in exceptions if r["detector_type"] == "model" and r["detector_id"] == model.id]
                model.suppress = {r["entity"] for r in mine if r["kind"] == "suppress"}
                model.entity_thresholds = {r["entity"]: float(r["value"]) for r in mine if r["kind"] == "threshold" and r["value"] is not None}
            cur.execute("select id, name, enabled, features from models")
            self.model_rows = {r["id"]: r for r in cur}
            self.ctx.load(self.conn)
        self.conn.commit()

    def state(self, key: str, default=None):
        with self.conn.cursor() as cur:
            cur.execute("select value from engine_state where key = %s", (key,))
            row = cur.fetchone()
        return row["value"] if row else default

    def set_state(self, key: str, value) -> None:
        with self.conn.cursor() as cur:
            cur.execute("""insert into engine_state (key, value) values (%s, %s)
                on conflict (key) do update set value = excluded.value, updated_at = now()""", (key, Jsonb(value)))

    def feature_labels(self, model_id: str) -> dict:
        features = (self.model_rows.get(model_id) or {}).get("features") or []
        return {f["key"]: f["label"] for f in features}

    # Training

    def train(self, until: datetime | None = None) -> dict:
        """Fits every model on recent activity and records what each entity normally does."""
        # Pick up the newest inventory first. Training without it would miss who works where and whose patient is whose.
        self.reload()
        hours = self.settings["engine.training_hours"]
        with self.conn.cursor() as cur:
            cur.execute("select coalesce(%s, max(occurred_at)) as upto from events", (until,))
            upto = cur.fetchone()["upto"]
            if upto is None:
                self.conn.rollback()
                return {}
            start = upto - timedelta(hours=hours)
            cur.execute("select model_id, entity, window_start from model_training_labels where label = 'attack'")
            excluded = {(r["model_id"], r["entity"], int(r["window_start"].timestamp())) for r in cur}
            # Anything tied to a confirmed incident is left out of training, whichever detector raised it.
            cur.execute("""select hosts, users, opened_at - interval '5 minutes' as a, last_activity_at + interval '5 minutes' as b
                from incidents where status = 'confirmed' and last_activity_at >= %s""", (start,))
            confirmed = cur.fetchall()

        def tainted(entity: str, begin: int, length: int) -> bool:
            for inc in confirmed:
                if (entity in inc["hosts"] or entity in inc["users"]) and begin < inc["b"].timestamp() and begin + length > inc["a"].timestamp():
                    return True
            return False

        trainers = all_models()
        pairs: set[tuple[str, str, str]] = set()
        with self.conn.cursor(name="training_events") as cur:
            cur.itersize = 5000
            cur.execute(f"select {EVENT_COLUMNS} from events where occurred_at > %s and occurred_at <= %s order by occurred_at", (start, upto))
            for ev in cur:
                self.ctx.enrich(ev)
                when = ev["occurred_at"].timestamp()
                if any((ev.get(k) and tainted(ev[k], int(when), 1)) for k in ("host", "actor_user")):
                    continue
                pairs.update(self.rules.baseline_pairs(ev))
                for m in trainers:
                    m.add(ev)
        summary = {}
        with self.conn.cursor() as cur:
            for trainer in trainers:
                windows = [w for w in trainer.close(None) if (trainer.id, w[0], w[1]) not in excluded and not tainted(w[0], w[1], trainer.window_seconds)]
                cur.execute("select features from model_training_labels where model_id = %s and label = 'normal' and features is not null", (trainer.id,))
                taught = [r["features"] for r in cur]
                result = trainer.fit(windows, {}, self.settings, taught)
                summary[trainer.id] = result["training_rows"] if result else 0
                if result is None:
                    continue
                live = next(m for m in self.models if m.id == trainer.id)
                trainer.open, trainer.suppress, trainer.entity_thresholds = live.open, live.suppress, live.entity_thresholds
                self.models[self.models.index(live)] = trainer
                cur.execute("""update models set version = version + 1, trained_at = now(), training_from = %s, training_to = %s,
                    training_rows = %s, threshold = %s, score_summary = %s, feature_stats = %s where id = %s""",
                            (start, upto, result["training_rows"], result["threshold"], Jsonb(result["score_summary"]),
                             Jsonb(result["feature_stats"]), trainer.id))
            if pairs:
                cur.executemany("insert into baseline_values (scope, entity, value) values (%s, %s, %s) on conflict do nothing", list(pairs))
            cur.execute("select audit_append('system', 'detection', 'Detection service', 'models.trained', 'models', null, %s)", (Jsonb(summary),))
        self.set_state("trained_at", datetime.now(timezone.utc).isoformat())
        self.conn.commit()
        self.reload(force=True)
        return summary

    def trained(self) -> bool:
        return any(m.forest is not None for m in self.models)

    # Learning period

    def refresh_learning(self) -> None:
        """Ends learning periods that are due, and loads which kinds of log are still learning.

        Only a real hospital's installation learns this way. The simulated hospital builds its own history.
        """
        days = float(self.settings.get("learning.days") or 0)
        if self.settings.get("engine.simulate") or days <= 0:
            self.learning, self.learning_known = set(), None
            return
        with self.conn.cursor() as cur:
            cur.execute("""update learning_periods set finished_at = now(), finished_by = coalesce(finished_by, 'schedule')
                where finished_at is null and ends_at <= now() returning source, finished_by, events, values_learned""")
            ended = cur.fetchall()
            for row in ended:
                cur.execute("select audit_append('system', 'detection', 'Detection service', 'learning.finished', 'source', %s, %s)",
                            (row["source"], Jsonb({"finished_by": row["finished_by"], "events": row["events"], "values_learned": row["values_learned"]})))
            cur.execute("select source, finished_at is null as active from learning_periods")
            rows = cur.fetchall()
        if ended:
            # Train straight away on what was learned, so the models judge from the hospital's own normal.
            self.set_state("retrain_requested", True)
        self.conn.commit()
        self.learning = {r["source"] for r in rows if r["active"]}
        self.learning_known = {r["source"] for r in rows}

    def start_learning(self, source: str) -> None:
        days = float(self.settings.get("learning.days") or 0)
        with self.conn.cursor() as cur:
            cur.execute("""insert into learning_periods (source, ends_at) values (%s, now() + make_interval(secs => %s))
                on conflict (source) do nothing returning ends_at""", (source, days * 86400))
            row = cur.fetchone()
            if row:
                cur.execute("select audit_append('system', 'detection', 'Detection service', 'learning.started', 'source', %s, %s)",
                            (source, Jsonb({"days": days, "ends_at": row["ends_at"].isoformat()})))
        assert self.learning_known is not None
        self.learning_known.add(source)
        self.learning.add(source)

    # Processing

    def process_new(self, limit: int = 20000, flush: bool = False) -> dict:
        """Runs detection over events that have arrived since the last call."""
        self.reload()
        cursor = int(self.state("event_cursor", 0))
        with self.conn.cursor() as cur:
            cur.execute(f"select {EVENT_COLUMNS} from events where id > %s order by id limit %s", (cursor, limit))
            events = cur.fetchall()
        self.refresh_learning()
        drafts: list[Draft] = []
        learned: list[tuple[str, str, str]] = []
        seen_learning: Counter = Counter()
        values_learned: Counter = Counter()
        for ev in events:
            self.ctx.enrich(ev)
            source = ev["source"]
            if self.learning_known is not None and source not in self.learning_known:
                self.start_learning(source)
            learning = source in self.learning
            before = len(learned)
            drafts.extend(self.rules.process(ev, learning=learning, learned=learned))
            if learning:
                seen_learning[source] += 1
                values_learned[source] += len(learned) - before
            for model in self.models:
                model.add(ev)
            if self.watermark is None or ev["occurred_at"] > self.watermark:
                self.watermark = ev["occurred_at"]
        if events:
            cursor = events[-1]["id"]
        for model in self.models:
            row = self.model_rows.get(model.id) or {}
            closed = model.close(None if flush else self.watermark) if (self.watermark or flush) else []
            if self.learning:
                # A window that includes a kind of log still being learned is learned from, not judged.
                closed = [w for w in closed if not (w[2]["_sources"] & self.learning)]
            if row.get("enabled", True):
                drafts.extend(model.score(closed, self.settings, self.feature_labels(model.id), row.get("name", model.id)))
        if seen_learning or learned:
            with self.conn.cursor() as cur:
                if learned:
                    cur.executemany("insert into baseline_values (scope, entity, value) values (%s, %s, %s) on conflict do nothing", learned)
                for source, n in seen_learning.items():
                    cur.execute("update learning_periods set events = events + %s, values_learned = values_learned + %s where source = %s",
                                (n, values_learned[source], source))
        new_alerts = self.store_alerts(drafts)
        touched = self.correlate(new_alerts)
        self.set_state("event_cursor", cursor)
        if self.watermark:
            self.set_state("watermark", self.watermark.isoformat())
            self.rules.prune(self.watermark.timestamp())
        self.conn.commit()
        return {"events": len(events), "alerts": len(new_alerts), "incidents": len(touched)}

    def store_alerts(self, drafts: list[Draft]) -> list[dict]:
        """Stores alerts. A repeat of the same detection inside its window updates the first alert."""
        merged: dict[str, Draft] = {}
        for d in drafts:
            seen = merged.get(d.dedupe_key)
            if seen is None:
                merged[d.dedupe_key] = d
                continue
            seen.hits += d.hits
            seen.last_seen_at = max(seen.last_seen_at, d.last_seen_at)
            seen.sources |= d.sources
            if d.observed is not None:
                seen.observed = max(seen.observed or 0, d.observed)
            if len(seen.evidence) < 12:
                seen.evidence.extend(d.evidence[: 12 - len(seen.evidence)])
        created: list[dict] = []
        with self.conn.cursor() as cur:
            for d in sorted(merged.values(), key=lambda x: x.occurred_at):
                cur.execute("""
                    insert into alerts (occurred_at, last_seen_at, detector_type, detector_id, category, title, severity, confidence,
                        host, actor_user, entity, sources, technique_id, technique_name, hits, observed, score, window_start,
                        evidence, explanation, baseline, dedupe_key)
                    values (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                    on conflict (dedupe_key) do update set
                        hits = alerts.hits + excluded.hits,
                        last_seen_at = greatest(alerts.last_seen_at, excluded.last_seen_at),
                        observed = greatest(alerts.observed, excluded.observed),
                        evidence = case when jsonb_array_length(alerts.evidence) < 12 then alerts.evidence || excluded.evidence else alerts.evidence end
                    returning id, (xmax = 0) as inserted""",
                            (d.occurred_at, d.last_seen_at, d.detector_type, d.detector_id, d.category, d.title, d.severity, d.confidence,
                             d.host, d.user, d.entity, sorted(d.sources), d.technique_id, d.technique_name, d.hits, d.observed, d.score,
                             d.window_start, Jsonb(d.evidence), Jsonb(d.explanation), Jsonb(d.baseline) if d.baseline else None, d.dedupe_key))
                row = cur.fetchone()
                if row["inserted"]:
                    created.append({"id": row["id"], "draft": d})
                    cur.execute("select audit_append('system', 'detection', 'Detection service', 'alert.raised', 'alert', %s, %s)",
                                (str(row["id"]), Jsonb({"detector": d.detector_id, "entity": d.entity, "confidence": round(d.confidence, 3)})))
        return created

    def correlate(self, alerts: list[dict]) -> set[int]:
        """Attaches each new alert to an open incident that shares a machine or a person, or opens a new one."""
        window = timedelta(minutes=self.settings["detection.correlation_window_minutes"])
        # An incident stops absorbing new alerts after this long, so one busy desk cannot chain a whole shift together.
        span = timedelta(hours=self.settings["detection.incident_max_hours"])
        touched: set[int] = set()
        with self.conn.cursor() as cur:
            for item in alerts:
                d: Draft = item["draft"]
                entities = [("host", d.host)] if d.host else []
                if d.user:
                    entities.append(("user", d.user))
                incident_id = None
                if entities:
                    clause = " or ".join(["(ie.entity_type = %s and ie.entity_value = %s)"] * len(entities))
                    args = [x for pair in entities for x in pair]
                    cur.execute(f"""select i.id from incident_entities ie join incidents i on i.id = ie.incident_id
                        where ({clause}) and i.status in ('open', 'confirmed') and i.last_activity_at >= %s and i.opened_at <= %s
                          and i.opened_at >= %s
                        order by i.last_activity_at desc limit 1""",
                                (*args, d.occurred_at - window, d.occurred_at + window, d.occurred_at - span))
                    found = cur.fetchone()
                    incident_id = found["id"] if found else None
                opened = incident_id is None
                if opened:
                    cur.execute("""insert into incidents (opened_at, last_activity_at, category, title, band, confidence, severity)
                        values (%s, %s, %s, %s, 'low', 0, %s) returning id""", (d.occurred_at, d.last_seen_at, d.category, d.title, d.severity))
                    incident_id = cur.fetchone()["id"]
                cur.execute("update alerts set incident_id = %s where id = %s", (incident_id, item["id"]))
                for kind, value in entities:
                    cur.execute("insert into incident_entities values (%s, %s, %s) on conflict do nothing", (incident_id, kind, value))
                self.rescore(cur, incident_id, d.last_seen_at, opened)
                touched.add(incident_id)
        return touched

    def rescore(self, cur, incident_id: int, at: datetime, opened: bool) -> None:
        cur.execute("""select detector_id, category, severity, confidence, sources, technique_id, host, actor_user, occurred_at, last_seen_at
            from alerts where incident_id = %s and not suppressed order by occurred_at""", (incident_id,))
        rows = cur.fetchall()
        best: dict[str, float] = {}
        for r in rows:
            best[r["detector_id"]] = max(best.get(r["detector_id"], 0.0), float(r["confidence"]))
        sources = sorted({s for r in rows for s in r["sources"]})
        confidence, band = band_for(combine(list(best.values())), len(sources), self.settings)
        lead = max(rows, key=lambda r: (r["severity"], -CATEGORY_RANK.index(r["category"]) if r["category"] in CATEGORY_RANK else -99, float(r["confidence"])))
        hosts = list(dict.fromkeys(r["host"] for r in rows if r["host"]))
        users = list(dict.fromkeys(r["actor_user"] for r in rows if r["actor_user"]))
        primary_host = lead["host"] or (hosts[0] if hosts else None)
        primary_user = lead["actor_user"] or (users[0] if users else None)
        template = self.copy.get(f"incident.title.{lead['category']}", "incident.title." + lead["category"])
        title = template.replace("{entity}", primary_host or primary_user or "")
        cur.execute("select band, medium_at, high_at from incidents where id = %s", (incident_id,))
        before = cur.fetchone()
        medium_at = before["medium_at"] or (at if band in ("medium", "high") else None)
        high_at = before["high_at"] or (at if band == "high" else None)
        cur.execute("""update incidents set last_activity_at = greatest(last_activity_at, %s), category = %s, title = %s, band = %s,
                confidence = %s, severity = %s, primary_host = %s, primary_user = %s, hosts = %s, users = %s, sources = %s,
                detectors = %s, techniques = %s, alert_count = %s, medium_at = %s, high_at = %s where id = %s""",
                    (max(r["last_seen_at"] for r in rows), lead["category"], title, band, confidence, max(r["severity"] for r in rows),
                     primary_host, primary_user, hosts, users, sources, sorted(best),
                     sorted({r["technique_id"] for r in rows if r["technique_id"]}), len(rows), medium_at, high_at, incident_id))
        order = {"low": 0, "medium": 1, "high": 2}
        escalated = not opened and order[band] > order[before["band"]]
        # Low band incidents are kept for tuning. They are not forwarded and do not page anyone.
        if band != "low" and (escalated or (opened and band != "low")):
            action = "incident.opened" if opened or before["band"] == "low" else "incident.escalated"
            cur.execute("select audit_append('system', 'detection', 'Detection service', %s, 'incident', %s, %s)",
                        (action, str(incident_id), Jsonb({"band": band, "confidence": round(confidence, 3), "sources": sources})))
            cur.execute("select siem_enqueue(%s, %s)", (incident_id, "incident_opened" if action == "incident.opened" else "incident_escalated"))
