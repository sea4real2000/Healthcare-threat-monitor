"""Turns one row of a hospital's own patient record access log into a FHIR AuditEvent.

web/lib/records.ts does the same for uploaded reports. Both are checked against the
same examples in their tests, so a row gives the same event whichever way it arrives.
"""
from __future__ import annotations

import hashlib
import ipaddress
import re
from datetime import date, datetime, timedelta, timezone
from zoneinfo import ZoneInfo

SUCCESS = {"1", "true", "yes", "y", "success", "succeeded", "successful", "ok", "allowed", "granted", "pass", "passed"}
FAILURE = {"false", "no", "n", "fail", "failed", "failure", "denied", "error", "blocked", "refused", "rejected"}

ISO = re.compile(r"^(\d{4})-(\d{2})-(\d{2})(?:[T ](\d{1,2}):(\d{2})(?::(\d{2})(?:[.,](\d{1,6}))?)?)?\s*(Z|[+-]\d{2}:?\d{2})?$", re.I)
SLASH = re.compile(r"^(\d{1,4})[/.-](\d{1,2})[/.-](\d{1,4})(?:[ T](\d{1,2}):(\d{2})(?::(\d{2}))?\s*(am|pm)?)?$", re.I)


class RowError(ValueError):
    pass


def action_code(value) -> str:
    v = "" if value is None else str(value).strip().lower()
    if v in ("r", "c", "u", "d"):
        return v.upper()
    if re.search(r"creat|insert|add|new|register", v):
        return "C"
    if re.search(r"updat|edit|modif|amend|chang|correct", v):
        return "U"
    if re.search(r"delet|remov|purg", v):
        return "D"
    return "R"


def outcome_code(value):
    if value is None:
        return None
    if isinstance(value, bool):
        return "0" if value else "8"
    v = str(value).strip().lower()
    if v in SUCCESS:
        return "0"
    if v in FAILURE:
        return "8"
    return None


def _iso(dt: datetime) -> str:
    dt = dt.astimezone(timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}Z"


def _check(dt: datetime) -> str:
    if not (1970 <= dt.year <= 2200):
        raise RowError("bad_time")
    return _iso(dt)


def parse_time(value, tz: str, day_first: bool) -> str:
    zone = ZoneInfo(tz)
    if value is None or (isinstance(value, str) and not value.strip()):
        raise RowError("missing_time")
    if isinstance(value, datetime):
        return _check(value if value.tzinfo else value.replace(tzinfo=zone))
    if isinstance(value, date):
        return _check(datetime(value.year, value.month, value.day, tzinfo=zone))
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        value = str(value)
    v = str(value).strip()
    if re.fullmatch(r"\d{10}(\.\d+)?", v):
        return _iso(datetime.fromtimestamp(round(float(v) * 1000) / 1000, timezone.utc))
    if re.fullmatch(r"\d{13}", v):
        return _iso(datetime.fromtimestamp(int(v) / 1000, timezone.utc))
    m = ISO.match(v)
    try:
        if m:
            y, mo, d, h, mi, s, frac, off = m.groups()
            ms = round(float(f"0.{frac or '0'}") * 1000)
            base = datetime(int(y), int(mo), int(d), int(h or 0), int(mi or 0), int(s or 0), ms * 1000)
            if off:
                if off.upper() == "Z":
                    return _check(base.replace(tzinfo=timezone.utc))
                sign = -1 if off[0] == "-" else 1
                minutes = sign * (int(off[1:3]) * 60 + int(off[-2:]))
                return _check(base.replace(tzinfo=timezone(timedelta(minutes=minutes))))
            return _check(base.replace(tzinfo=zone))
        m = SLASH.match(v)
        if m:
            a, b, c, h, mi, s, ampm = m.groups()
            if len(a) == 4:
                y, mo, d = int(a), int(b), int(c)
            elif len(c) == 4:
                y, mo, d = (int(c), int(b), int(a)) if day_first else (int(c), int(a), int(b))
            else:
                raise RowError("bad_time")
            hour = int(h or 0)
            if ampm:
                hour = hour % 12 + (12 if ampm.lower() == "pm" else 0)
            return _check(datetime(y, mo, d, hour, int(mi or 0), int(s or 0), tzinfo=zone))
    except ValueError as err:
        if isinstance(err, RowError):
            raise
        raise RowError("bad_time") from err
    raise RowError("bad_time")


def _clean(value, limit: int = 64) -> str:
    return "" if value is None else str(value).strip()[:limit]


def event_id(prefix: str, parts: list[str]) -> str:
    return f"{prefix}-" + hashlib.sha256("\x1f".join(parts).encode("utf-8")).hexdigest()[:24]


def to_audit_event(row: dict, tz: str, day_first: bool, source_name: str, id_prefix: str, asset_ips: dict | None = None) -> dict:
    recorded = parse_time(row.get("time"), tz, day_first)
    user = _clean(row.get("user")).lower()
    patient = _clean(row.get("patient"))
    if not user:
        raise RowError("missing_user")
    if not patient:
        raise RowError("missing_patient")
    action = action_code(row.get("action"))
    outcome = outcome_code(row.get("outcome"))
    station = _clean(row.get("workstation"))
    address = None
    if station:
        try:
            ipaddress.ip_address(station)
            address = station
        except ValueError:
            address = (asset_ips or {}).get(station.upper())
    record_id = _clean(row.get("record_id"), 120)
    eid = f"{id_prefix}-{record_id}" if record_id else event_id(id_prefix, [recorded, user, patient, action, station])
    agent: dict = {"who": {"identifier": {"value": user}}, "requestor": True}
    if address:
        agent["network"] = {"address": address, "type": "2"}
    payload = {
        "resourceType": "AuditEvent",
        "id": eid,
        "recorded": recorded,
        "action": action,
        "agent": [agent],
        "entity": [{"what": {"reference": f"Patient/{patient}"}}],
        "source": {"observer": {"display": source_name[:120]}},
    }
    if outcome:
        payload["outcome"] = outcome
    return {"source": "ehr", "payload": payload}
