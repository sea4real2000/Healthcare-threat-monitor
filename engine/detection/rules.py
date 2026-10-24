"""The rules engine.

Rules are rows in the database, not code. Each rule is one of three kinds:

  match      one event that meets every condition
  threshold  enough matching events for one entity inside a time window
  new_value  a value an entity has never used before, such as a new peer for a medical device

A rule's conditions read fields of the normalized event, its attributes, and
facts looked up from the inventory (the actor's role, the asset's kind, the
patient's department and so on).
"""

from __future__ import annotations

import re
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime


class RuleError(ValueError):
    pass


@dataclass
class Draft:
    """An alert before it is stored."""
    detector_type: str
    detector_id: str
    category: str
    title: str
    severity: int
    confidence: float
    occurred_at: datetime
    entity: str
    dedupe_key: str
    host: str | None = None
    user: str | None = None
    sources: set = field(default_factory=set)
    technique_id: str | None = None
    technique_name: str | None = None
    hits: int = 1
    observed: float | None = None
    score: float | None = None
    window_start: datetime | None = None
    last_seen_at: datetime | None = None
    evidence: list = field(default_factory=list)
    explanation: list = field(default_factory=list)
    baseline: dict | None = None


def get_field(ev: dict, path: str):
    """Reads 'host', 'attributes.command_line', 'actor.role' and similar paths."""
    if "." not in path:
        return ev.get(path)
    head, tail = path.split(".", 1)
    inner = ev.get(head)
    return inner.get(tail) if isinstance(inner, dict) else None


def _text(v) -> str:
    return str(v).lower()


def _num(v):
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


def _op_any_in(actual, wanted) -> bool:
    values = actual if isinstance(actual, list) else [actual]
    return any(_text(v) in wanted for v in values if v is not None)


OPS = {
    "eq": lambda a, w: a is not None and _text(a) == w,
    "ne": lambda a, w: a is None or _text(a) != w,
    "in": lambda a, w: a is not None and _text(a) in w,
    "not_in": lambda a, w: a is None or _text(a) not in w,
    "any_in": lambda a, w: a is not None and _op_any_in(a, w),
    "contains": lambda a, w: a is not None and w in _text(a),
    "contains_any": lambda a, w: a is not None and any(x in _text(a) for x in w),
    "regex": lambda a, w: a is not None and w.search(str(a)) is not None,
    "gt": lambda a, w: _num(a) is not None and _num(a) > w,
    "gte": lambda a, w: _num(a) is not None and _num(a) >= w,
    "lt": lambda a, w: _num(a) is not None and _num(a) < w,
    "lte": lambda a, w: _num(a) is not None and _num(a) <= w,
    "exists": lambda a, w: a is not None and a != "",
    "not_exists": lambda a, w: a is None or a == "",
    "is_true": lambda a, w: a is True,
    "is_false": lambda a, w: a is False,
}
LIST_OPS = {"in", "not_in", "any_in", "contains_any"}
NUMBER_OPS = {"gt", "gte", "lt", "lte"}
NO_VALUE_OPS = {"exists", "not_exists", "is_true", "is_false"}
PATH = re.compile(r"^[a-z_]+(\.[a-z_0-9]+)?$")


def compile_conditions(where) -> list[tuple]:
    if not isinstance(where, list) or not where:
        raise RuleError("where must be a list with at least one condition")
    out = []
    for cond in where:
        if not isinstance(cond, dict):
            raise RuleError("each condition must be an object")
        path, op, value = cond.get("field"), cond.get("op"), cond.get("value")
        if not isinstance(path, str) or not PATH.match(path):
            raise RuleError(f"bad field: {path!r}")
        if op not in OPS:
            raise RuleError(f"unknown op: {op!r}")
        if op in LIST_OPS:
            if not isinstance(value, list) or not value:
                raise RuleError(f"{op} needs a list of values")
            value = frozenset(_text(v) for v in value) if op != "contains_any" else tuple(_text(v) for v in value)
        elif op in NUMBER_OPS:
            if _num(value) is None:
                raise RuleError(f"{op} needs a number")
            value = float(value)
        elif op == "regex":
            if not isinstance(value, str) or len(value) > 300:
                raise RuleError("regex needs a pattern of at most 300 characters")
            try:
                value = re.compile(value)
            except re.error as err:
                raise RuleError(f"bad regex: {err}") from None
        elif op in NO_VALUE_OPS:
            value = None
        else:
            if value is None or isinstance(value, (list, dict)):
                raise RuleError(f"{op} needs a single value")
            value = _text(value)
        out.append((path, OPS[op], value, op))
    return out


def _positive(d: dict, key: str, default=None) -> float:
    v = d.get(key, default)
    if _num(v) is None or float(v) <= 0:
        raise RuleError(f"{key} must be a number above zero")
    return float(v)


class Rule:
    def __init__(self, row: dict) -> None:
        self.id = row["id"]
        self.name = row["name"]
        self.kind = row["kind"]
        self.category = row["category"]
        self.severity = int(row["severity"])
        self.confidence = float(row["confidence"])
        self.technique_id = row.get("technique_id")
        self.technique_name = row.get("technique_name")
        d = row["definition"]
        if not isinstance(d, dict):
            raise RuleError("definition must be an object")
        self.where = compile_conditions(d.get("where"))
        # Rules are indexed by event category so each event only meets the rules that can match it.
        self.categories = None
        for path, _, value, op in self.where:
            if path == "category" and op == "eq":
                self.categories = {value}
            elif path == "category" and op == "in":
                self.categories = set(value)
        self.entity_field = d.get("entity_field", "host")
        # Used when the entity field is empty, such as an address when the machine is not in the inventory.
        self.entity_fallback = d.get("entity_fallback")
        self.host_field = d.get("host_field", "host")
        self.user_field = d.get("user_field", "actor_user")
        if self.entity_fallback is not None and not (isinstance(self.entity_fallback, str) and PATH.match(self.entity_fallback)):
            raise RuleError(f"bad field: {self.entity_fallback!r}")
        for f in (self.entity_field, self.host_field, self.user_field):
            if f != "*" and not (isinstance(f, str) and PATH.match(f)):
                raise RuleError(f"bad field: {f!r}")
        self.dedupe_seconds = _positive(d, "dedupe_seconds", 900)
        if self.kind == "threshold":
            self.window = _positive(d, "window_seconds")
            self.count = _positive(d, "count")
            distinct = d.get("distinct")
            if distinct is not None and (not isinstance(distinct, list) or not all(isinstance(x, str) and PATH.match(x) for x in distinct)):
                raise RuleError("distinct must be a list of fields")
            self.distinct = distinct
        elif self.kind == "new_value":
            self.value_field = d.get("value_field")
            if not isinstance(self.value_field, str) or not PATH.match(self.value_field):
                raise RuleError("new_value needs a value_field")
            self.fallback = d.get("fallback")
            if self.fallback not in (None, "global"):
                raise RuleError("fallback must be global or absent")
        elif self.kind != "match":
            raise RuleError(f"unknown kind: {self.kind!r}")

    def matches(self, ev: dict) -> bool:
        for path, fn, value, _ in self.where:
            if not fn(get_field(ev, path), value):
                return False
        return True


def summarize(ev: dict) -> dict:
    """A compact copy of an event, kept with the alert so the evidence survives event retention."""
    a = ev.get("attributes") or {}
    detail = (a.get("command_line") or a.get("file_new_path") or a.get("file_path") or a.get("query_name")
              or a.get("service_name") or a.get("sender") or a.get("object_key") or a.get("country") or a.get("resource_type"))
    return {
        "id": ev["id"], "at": ev["occurred_at"].isoformat(), "source": ev["source"], "action": ev["action"],
        "outcome": ev["outcome"], "user": ev.get("actor_user"), "host": ev.get("host"), "src_ip": ev.get("src_ip"),
        "dst_ip": ev.get("dst_ip"), "dst_port": ev.get("dst_port"), "patient": ev.get("patient_ref"),
        "detail": str(detail)[:200] if detail is not None else None,
    }


class RuleEngine:
    def __init__(self) -> None:
        self.rules: list[Rule] = []
        self.by_category: dict[str, list[Rule]] = {}
        self.any_category: list[Rule] = []
        self.errors: dict[str, str] = {}
        # scope -> entity -> set of known values
        self.baseline: dict[str, dict[str, set]] = {}
        self.baseline_union: dict[str, set] = {}
        # (detector id, entity) -> True for suppress, or a number for a raised threshold
        self.suppress: set[tuple[str, str]] = set()
        self.thresholds: dict[tuple[str, str], float] = {}
        self.windows: dict[tuple[str, str], deque] = defaultdict(deque)

    def load_rules(self, rows: list[dict]) -> None:
        self.rules, self.by_category, self.any_category, self.errors = [], {}, [], {}
        for row in rows:
            try:
                rule = Rule(row)
            except RuleError as err:
                self.errors[row["id"]] = str(err)
                continue
            self.rules.append(rule)
            if rule.categories is None:
                self.any_category.append(rule)
            else:
                for c in rule.categories:
                    self.by_category.setdefault(c, []).append(rule)
        live = {r.id for r in self.rules if r.kind == "threshold"}
        for key in [k for k in self.windows if k[0] not in live]:
            del self.windows[key]

    def load_baseline(self, rows) -> None:
        self.baseline, self.baseline_union = {}, {}
        for scope, entity, value in rows:
            self.baseline.setdefault(scope, {}).setdefault(entity, set()).add(value)
            self.baseline_union.setdefault(scope, set()).add(value)

    def load_exceptions(self, rows) -> None:
        self.suppress, self.thresholds = set(), {}
        for detector_id, entity, kind, value in rows:
            if kind == "suppress":
                self.suppress.add((detector_id, entity))
            elif value is not None:
                self.thresholds[(detector_id, entity)] = float(value)

    def candidates(self, ev: dict) -> list[Rule]:
        return self.by_category.get(ev["category"], []) + self.any_category

    def baseline_pairs(self, ev: dict) -> list[tuple[str, str, str]]:
        """What this event teaches the new value rules. Used during training only."""
        out = []
        for rule in self.candidates(ev):
            if rule.kind == "new_value" and rule.matches(ev):
                entity = self._entity(rule, ev)
                value = get_field(ev, rule.value_field)
                if entity and value is not None:
                    out.append((rule.id, entity, str(value)))
        return out

    @staticmethod
    def _entity(rule: Rule, ev: dict) -> str | None:
        if rule.entity_field == "*":
            return "*"
        v = get_field(ev, rule.entity_field)
        if v in (None, "") and rule.entity_fallback:
            v = get_field(ev, rule.entity_fallback)
        return str(v) if v not in (None, "") else None

    def _draft(self, rule: Rule, ev: dict, entity: str, key_extra: str = "") -> Draft:
        ts = ev["occurred_at"]
        bucket = int(ts.timestamp() // rule.dedupe_seconds)
        host = get_field(ev, rule.host_field)
        user = get_field(ev, rule.user_field)
        return Draft(
            detector_type="rule", detector_id=rule.id, category=rule.category, title=rule.name, severity=rule.severity,
            confidence=rule.confidence, occurred_at=ts, last_seen_at=ts, entity=entity,
            dedupe_key=f"rule|{rule.id}|{entity}|{key_extra}|{bucket}",
            host=str(host) if host else None, user=str(user) if user else None, sources={ev["source"]},
            technique_id=rule.technique_id, technique_name=rule.technique_name, evidence=[summarize(ev)],
        )

    def process(self, ev: dict, learning: bool = False, learned: list | None = None) -> list[Draft]:
        """Runs every rule that applies to one event.

        While the event's kind of log is in its learning period, the new value rules record what they
        see as normal instead of reporting it. Every other rule reports as usual.
        """
        out: list[Draft] = []
        for rule in self.candidates(ev):
            if not rule.matches(ev):
                continue
            entity = self._entity(rule, ev)
            if entity is None or (rule.id, entity) in self.suppress:
                continue
            if rule.kind == "match":
                out.append(self._draft(rule, ev, entity))
            elif rule.kind == "threshold":
                ts = ev["occurred_at"].timestamp()
                marker = tuple(get_field(ev, f) for f in rule.distinct) if rule.distinct else None
                window = self.windows[(rule.id, entity)]
                window.append((ts, marker))
                while window and window[0][0] < ts - rule.window:
                    window.popleft()
                seen = len({m for _, m in window}) if rule.distinct else len(window)
                if seen >= self.thresholds.get((rule.id, entity), rule.count):
                    draft = self._draft(rule, ev, entity)
                    draft.observed = float(seen)
                    out.append(draft)
            else:
                value = get_field(ev, rule.value_field)
                if value is None:
                    continue
                value = str(value)
                scope = self.baseline.get(rule.id, {})
                if value in scope.get("*", ()):
                    continue
                if learning:
                    if value not in scope.get(entity, ()):
                        self.baseline.setdefault(rule.id, {}).setdefault(entity, set()).add(value)
                        self.baseline_union.setdefault(rule.id, set()).add(value)
                        if learned is not None:
                            learned.append((rule.id, entity, value))
                    continue
                known = scope.get(entity)
                if known is None:
                    # Nothing is known about this entity. Either compare with everyone, or stay silent.
                    if rule.fallback != "global" or value in self.baseline_union.get(rule.id, ()):
                        continue
                elif value in known:
                    continue
                draft = self._draft(rule, ev, entity, key_extra=value)
                draft.baseline = {"scope": rule.id, "entity": entity, "value": value}
                out.append(draft)
        return out

    def prune(self, now_ts: float) -> None:
        """Forgets windows that have gone quiet, so memory does not grow without bound."""
        for key in [k for k, w in self.windows.items() if not w or w[-1][0] < now_ts - 3600]:
            del self.windows[key]
