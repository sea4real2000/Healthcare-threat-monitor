"""The three anomaly models.

Each model watches one kind of entity, summarises its activity over a fixed
window into a handful of counts, and asks an Isolation Forest how unusual that
summary is compared with what it saw during training. Training uses normal
activity only and needs no labelled attacks.

Every alert names the features that were furthest from normal, so an analyst
can see why a window was flagged.
"""

from __future__ import annotations

import math
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone

import numpy as np
from sklearn.ensemble import IsolationForest

from .rules import Draft, summarize

SCRIPT_HOSTS = {"powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe"}
OFFICE_APPS = {"winword.exe", "excel.exe", "outlook.exe", "acrord32.exe", "powerpnt.exe"}


def squash(x: np.ndarray) -> np.ndarray:
    """Counts are heavy tailed. A signed log keeps large values from dominating."""
    return np.sign(x) * np.log1p(np.abs(x))


class WindowModel:
    id = ""
    category = ""
    window_seconds = 60
    feature_keys: list[str] = []

    def __init__(self) -> None:
        self.open: dict[tuple[str, int], dict] = {}
        self.forest: IsolationForest | None = None
        self.threshold = math.inf
        self.stats: dict[str, tuple] = {}
        self.entity_thresholds: dict[str, float] = {}
        self.suppress: set[str] = set()

    # Subclasses define these four.
    def accepts(self, ev: dict) -> bool: raise NotImplementedError
    def entity(self, ev: dict) -> str | None: raise NotImplementedError
    def new_window(self) -> dict: raise NotImplementedError
    def update(self, acc: dict, ev: dict) -> None: raise NotImplementedError
    def vector(self, entity: str, start: int, acc: dict) -> list[float]: raise NotImplementedError
    def learn(self, windows: list[tuple[str, int, dict]], ctx: dict) -> None: pass

    def add(self, ev: dict) -> None:
        if not self.accepts(ev):
            return
        entity = self.entity(ev)
        if not entity:
            return
        start = int(ev["occurred_at"].timestamp() // self.window_seconds) * self.window_seconds
        acc = self.open.get((entity, start))
        if acc is None:
            acc = self.new_window()
            acc.update(_events=[], _sources=set(), _host=ev.get("host"), _user=ev.get("actor_user"), _n=0)
            self.open[(entity, start)] = acc
        acc["_n"] += 1
        acc["_sources"].add(ev["source"])
        # Keep the first few and the latest few events as evidence.
        if len(acc["_events"]) < 4:
            acc["_events"].append(summarize(ev))
        else:
            acc.setdefault("_tail", []).append(summarize(ev))
            acc["_tail"] = acc["_tail"][-4:]
        self.update(acc, ev)

    def close(self, watermark: datetime | None, grace: float = 20.0) -> list[tuple[str, int, dict]]:
        """Returns windows that can no longer receive events. With no watermark, returns everything."""
        limit = math.inf if watermark is None else watermark.timestamp() - grace
        done = [(e, s, acc) for (e, s), acc in self.open.items() if s + self.window_seconds <= limit]
        for e, s, _ in done:
            del self.open[(e, s)]
        return done

    def group(self, entity: str, acc: dict) -> str:
        """The peer group a window is judged against, such as the role of the machine."""
        return "all"

    @staticmethod
    def _stats(rows: np.ndarray) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
        """Typical value, natural spread and highest value seen, for each feature."""
        median = np.median(rows, axis=0)
        mad = np.median(np.abs(rows - median), axis=0) * 1.4826
        wide = (np.percentile(rows, 99.9, axis=0) - median) / 3.09
        spread = (np.percentile(rows, 99, axis=0) - median) / 2.33
        return median, np.maximum(np.maximum(np.maximum(mad, spread), wide), 0.5), rows.max(axis=0)

    def fit(self, windows: list[tuple[str, int, dict]], ctx: dict, settings: dict, taught: list[dict] | None = None) -> dict | None:
        """Trains on closed windows. Returns a summary for the models table, or None if there is too little data.

        `taught` holds windows an analyst dismissed as normal. They join the training set with a heavy
        weight, so the model's sense of the normal range widens for that kind of machine or person.
        """
        if len(windows) < settings["model.min_training_windows"]:
            self.forest = None
            return None
        self.learn(windows, ctx)
        raw = np.array([self.vector(e, s, acc) for e, s, acc in windows], dtype=float)
        groups = [self.group(e, acc) for e, _, acc in windows]
        weight = int(settings["feedback.normal_weight"])
        taught = [t for t in (taught or []) if isinstance(t, dict) and len(t.get("vector", [])) == len(self.feature_keys)]
        extra = np.array([t["vector"] for t in taught], dtype=float) if taught else np.empty((0, len(self.feature_keys)))
        # Range statistics per peer group, with what analysts taught repeated so it counts.
        self.stats = {"all": self._stats(np.vstack([raw, np.repeat(extra, weight, axis=0)]))}
        for g in set(groups):
            rows = raw[[i for i, x in enumerate(groups) if x == g]]
            mine = extra[[i for i, t in enumerate(taught) if t.get("group") == g]] if taught else extra
            if len(rows) >= settings["model.min_group_windows"]:
                self.stats[g] = self._stats(np.vstack([rows, np.repeat(mine, weight, axis=0)]))
        self.forest = IsolationForest(n_estimators=int(settings["model.trees"]), max_samples=min(len(raw), int(settings["model.sample_size"])),
                                      random_state=20261009, n_jobs=1)
        x = squash(raw)
        if len(extra):
            self.forest.fit(np.vstack([x, squash(extra)]), sample_weight=np.concatenate([np.ones(len(x)), np.full(len(extra), float(weight))]))
        else:
            self.forest.fit(x)
        scores = -self.forest.score_samples(x)
        self.threshold = float(np.quantile(scores, settings["model.alert_quantile"]))
        hist, edges = np.histogram(scores, bins=24)
        median, _, top = self.stats["all"]
        return {
            "training_rows": int(len(windows)),
            "taught_rows": len(taught),
            "threshold": self.threshold,
            "score_summary": {
                "p50": float(np.quantile(scores, 0.5)), "p90": float(np.quantile(scores, 0.9)),
                "p99": float(np.quantile(scores, 0.99)), "max": float(scores.max()),
                "histogram": [int(v) for v in hist], "edges": [round(float(v), 4) for v in edges],
            },
            "feature_stats": {k: {"median": float(median[i]), "p99": float(np.percentile(raw[:, i], 99)), "max": float(top[i])}
                              for i, k in enumerate(self.feature_keys)},
        }

    def score(self, windows: list[tuple[str, int, dict]], settings: dict, labels: dict, title: str) -> list[Draft]:
        """Scores closed windows. A window raises an alert when two things hold.

        First, it is unusual: either the forest isolates it quickly, or a feature exceeds anything seen
        in training (a forest cannot see a value outside the range it was trained on). Second, at least
        one feature sits far outside the normal range for that peer group. Confidence grows with that distance.
        """
        if self.forest is None or not windows:
            return []
        windows = [w for w in windows if w[0] not in self.suppress]
        if not windows:
            return []
        raw = np.array([self.vector(e, s, acc) for e, s, acc in windows], dtype=float)
        scores = -self.forest.score_samples(squash(raw))
        out: list[Draft] = []
        lo, hi = settings["model.confidence_min"], settings["model.confidence_max"]
        z_min, z_full = settings["model.min_feature_z"], settings["model.full_confidence_z"]
        for i, (entity, start, acc) in enumerate(windows):
            group = self.group(entity, acc)
            median, scale, highest = self.stats.get(group, self.stats["all"])
            z = (raw[i] - median) / scale
            top = float(z.max())
            beyond = bool(np.any((raw[i] > highest) & (z >= z_min)))
            if not (scores[i] > self.threshold or beyond) or top < max(z_min, self.entity_thresholds.get(entity, -math.inf)):
                continue
            order = np.argsort(-z)
            explanation = [
                {"feature": self.feature_keys[j], "label": labels.get(self.feature_keys[j], self.feature_keys[j]),
                 "value": round(float(raw[i, j]), 2), "typical": round(float(median[j]), 2), "z": round(float(z[j]), 1),
                 "beyond_training": bool(raw[i, j] > highest[j])}
                for j in order[:3] if z[j] >= 2
            ]
            when = datetime.fromtimestamp(start, tz=timezone.utc)
            gap = min(1.0, (top - z_min) / max(z_full - z_min, 1e-9))
            out.append(Draft(
                detector_type="model", detector_id=self.id, category=self.category, title=title, severity=2,
                confidence=float(lo + (hi - lo) * max(0.0, gap)), occurred_at=when + timedelta(seconds=self.window_seconds),
                last_seen_at=when + timedelta(seconds=self.window_seconds), entity=entity,
                dedupe_key=f"model|{self.id}|{entity}|{start}", host=acc.get("_host"), user=acc.get("_user"),
                sources=set(acc["_sources"]), hits=acc["_n"], score=float(scores[i]), observed=round(top, 2), window_start=when,
                evidence=acc["_events"] + acc.get("_tail", []), explanation=explanation,
                baseline={"vector": [float(v) for v in raw[i]], "group": group},
            ))
        return out


class RecordAccessModel(WindowModel):
    """Per user: how many patients they open, and how many of those are outside their own department."""
    id = "record_access"
    category = "records"
    window_seconds = 900
    feature_keys = ["patients", "outside_department", "outside_share", "flagged", "versus_own_normal", "versus_peers", "unusual_hour"]

    def __init__(self) -> None:
        super().__init__()
        self.user_stats: dict[str, tuple[float, float]] = {}
        self.peer_stats: dict[tuple, tuple[float, float]] = {}
        self.user_hours: dict[str, Counter] = {}
        self.peer_of: dict[str, tuple] = {}

    def accepts(self, ev): return ev["category"] == "record_access" and bool(ev.get("actor_user"))
    def entity(self, ev): return ev["actor_user"]
    def group(self, entity, acc): return str((acc.get("peer") or (None,))[0])
    def new_window(self): return {"patients": set(), "outside": set(), "flagged": set(), "peer": None}

    def update(self, acc, ev):
        patient = ev.get("patient_ref")
        if not patient:
            return
        acc["patients"].add(patient)
        if ev.get("same_department") is False:
            acc["outside"].add(patient)
        if (ev.get("patient") or {}).get("flag"):
            acc["flagged"].add(patient)
        actor = ev.get("actor") or {}
        acc["peer"] = (actor.get("role"), actor.get("department"))
        acc["_host"] = None  # this model is about a person, not a machine

    def learn(self, windows, ctx):
        per_user, per_peer, hours = defaultdict(list), defaultdict(list), defaultdict(Counter)
        for user, start, acc in windows:
            n = len(acc["patients"])
            per_user[user].append(n)
            per_peer[acc["peer"]].append(n)
            self.peer_of[user] = acc["peer"]
            hours[user][datetime.fromtimestamp(start, tz=timezone.utc).hour] += acc["_n"]
        self.user_stats = {u: (float(np.mean(v)), float(np.std(v))) for u, v in per_user.items() if len(v) >= 5}
        self.peer_stats = {p: (float(np.mean(v)), float(np.std(v))) for p, v in per_peer.items()}
        self.user_hours = dict(hours)

    def vector(self, entity, start, acc):
        n = len(acc["patients"])
        outside = len(acc["outside"])
        peer_mean, peer_std = self.peer_stats.get(acc["peer"], (1.5, 1.0))
        mean, std = self.user_stats.get(entity, (peer_mean, peer_std))
        hours = self.user_hours.get(entity)
        unusual = 0.0
        if hours and sum(hours.values()) >= 20:
            share = hours.get(datetime.fromtimestamp(start, tz=timezone.utc).hour, 0) / sum(hours.values())
            unusual = 1.0 - min(1.0, share * 24)
        return [n, outside, outside / n if n else 0.0, len(acc["flagged"]),
                (n - mean) / max(std, 1.0), (n - peer_mean) / max(peer_std, 1.0), unusual]


class EndpointModel(WindowModel):
    """Per machine: file and process activity, minute by minute."""
    id = "endpoint_behavior"
    category = "endpoint"
    window_seconds = 60
    feature_keys = ["file_writes", "file_renames", "file_deletes", "extensions", "processes", "new_processes", "script_children", "connections"]

    def __init__(self) -> None:
        super().__init__()
        self.known_processes: dict[str, set] = {}

    def accepts(self, ev): return ev["source"] == "edr" and bool(ev.get("host"))
    def entity(self, ev): return ev["host"]
    def group(self, entity, acc): return str(acc.get("role"))
    def new_window(self):
        return {"file_write": 0, "file_rename": 0, "file_delete": 0, "ext": set(), "process": 0, "names": set(),
                "script": 0, "connect": 0, "role": None}

    def update(self, acc, ev):
        a = ev.get("attributes") or {}
        action = ev["action"]
        acc["role"] = (ev.get("asset") or {}).get("role")
        if action in ("file_write", "file_rename", "file_delete"):
            acc[action] += 1
            new_path = a.get("file_new_path")
            ext = new_path.rsplit(".", 1)[-1].lower() if new_path and "." in new_path else a.get("file_extension")
            if ext:
                acc["ext"].add(ext)
        elif action == "process_start":
            acc["process"] += 1
            name = a.get("process_name")
            if name:
                acc["names"].add(name)
            if name in SCRIPT_HOSTS and a.get("parent_name") in OFFICE_APPS:
                acc["script"] += 1
        elif action == "network_connect":
            acc["connect"] += 1

    def learn(self, windows, ctx):
        known = defaultdict(set)
        for _, _, acc in windows:
            known[acc["role"]].update(acc["names"])
        self.known_processes = dict(known)

    def vector(self, entity, start, acc):
        known = self.known_processes.get(acc["role"], set())
        return [acc["file_write"], acc["file_rename"], acc["file_delete"], len(acc["ext"]), acc["process"],
                len(acc["names"] - known), acc["script"], acc["connect"]]


class DeviceModel(WindowModel):
    """Per medical device: who it talks to, on which ports, and how hard."""
    id = "device_traffic"
    category = "devices"
    window_seconds = 300
    feature_keys = ["flows", "peers", "new_peers", "ports", "bytes", "peak_rate", "syn_packets"]

    def __init__(self) -> None:
        super().__init__()
        self.known_peers: dict[str, set] = {}

    def accepts(self, ev): return ev["category"] == "device_flow" and bool(ev.get("host"))
    def entity(self, ev): return ev["host"]
    def group(self, entity, acc): return str(acc.get("role"))
    def new_window(self): return {"flows": 0, "peers": set(), "ports": set(), "bytes": 0, "rate": 0.0, "syn": 0, "role": None}

    def update(self, acc, ev):
        a = ev.get("attributes") or {}
        acc["role"] = (ev.get("asset") or {}).get("role")
        acc["flows"] += 1
        if ev.get("dst_ip"):
            acc["peers"].add(ev["dst_ip"])
        if ev.get("dst_port") is not None:
            acc["ports"].add(ev["dst_port"])
        acc["bytes"] += ev.get("bytes_out") or 0
        acc["rate"] = max(acc["rate"], float(a.get("rate_pps") or 0))
        acc["syn"] += int(a.get("syn_count") or 0)
        acc["_user"] = None

    def learn(self, windows, ctx):
        peers = defaultdict(set)
        for device, _, acc in windows:
            peers[device].update(acc["peers"])
        self.known_peers = dict(peers)

    def vector(self, entity, start, acc):
        known = self.known_peers.get(entity, set())
        return [acc["flows"], len(acc["peers"]), len(acc["peers"] - known), len(acc["ports"]), acc["bytes"], acc["rate"], acc["syn"]]


def all_models() -> list[WindowModel]:
    return [RecordAccessModel(), EndpointModel(), DeviceModel()]
