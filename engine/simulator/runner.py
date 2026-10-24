"""Runs the simulated clock, sends batches and keeps a ledger of what was emitted."""

from __future__ import annotations

import json
import math
import random
import sys
import time
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

from .client import ApiClient
from .generators import Generators, Record
from .hospital import Hospital

SOURCES = ["ehr", "edr", "windows", "linux", "firewall", "vpn", "dns", "email", "medical_device", "cloud"]


def poisson(rng: random.Random, lam: float) -> int:
    """Draws a Poisson count. Knuth's method is fine for the small rates used here."""
    if lam <= 0:
        return 0
    limit, k, p = math.exp(-lam), 0, 1.0
    while True:
        p *= rng.random()
        if p <= limit:
            return k
        k += 1


def minute_records(gen: Generators, hospital: Hospital, minute_start: datetime) -> list[Record]:
    """Every record for one simulated minute, in time order."""
    config = hospital.config
    factor = config["hourly_activity_factor"][minute_start.hour]
    always_on = set(config["always_on_activities"])
    records: list[Record] = []
    for name, rate in config["rates_per_minute_at_peak"].items():
        lam = float(rate) * (1.0 if name in always_on else factor)
        for _ in range(poisson(gen.rng, lam)):
            records.extend(gen.activities[name](minute_start + timedelta(seconds=gen.rng.uniform(0, 60))))
    records.extend(gen.take_due(minute_start + timedelta(minutes=1)))
    records.sort(key=lambda r: r[0])
    return records


class Ledger:
    """A running account of what the simulator emitted and what the server said it did with it."""

    def __init__(self, path: Path | None, run_id: str, seed: int) -> None:
        self.path = path
        self.data = {
            "run_id": run_id, "seed": seed, "started_at": datetime.now(timezone.utc).isoformat(),
            "simulated_from": None, "simulated_to": None, "minutes": 0, "batches": 0,
            "emitted": {s: 0 for s in SOURCES}, "emitted_total": 0,
            "server": {"accepted": 0, "duplicate": 0, "rejected": 0},
        }

    def count(self, records: list[Record]) -> None:
        for _, source, _ in records:
            self.data["emitted"][source] = self.data["emitted"].get(source, 0) + 1
        self.data["emitted_total"] += len(records)

    def server(self, response: dict) -> None:
        self.data["batches"] += 1
        for key in ("accepted", "duplicate", "rejected"):
            self.data["server"][key] += int(response.get(key, 0))

    def save(self) -> None:
        if self.path:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self.path.write_text(json.dumps(self.data, indent=2) + "\n", encoding="utf-8")


def run(hospital: Hospital, *, client: ApiClient | None, run_id: str, seed: int, minutes: int, realtime: bool,
        batch_size: int = 500, ledger_path: Path | None = None, dry_run_path: Path | None = None,
        log=lambda msg: print(msg, file=sys.stderr, flush=True)) -> Ledger:
    """Simulates the given number of minutes. With realtime on and minutes at zero it runs until stopped.

    In fast mode the simulated period ends at the current minute, so the console's
    recent window shows the run as soon as it finishes.
    """
    rng = random.Random(seed)
    gen = Generators(hospital, rng, run_id)
    ledger = Ledger(ledger_path, run_id, seed)
    now = datetime.now(timezone.utc).replace(second=0, microsecond=0)
    start = now if realtime else now - timedelta(minutes=minutes)
    ledger.data["simulated_from"] = start.isoformat()
    dry_file = open(dry_run_path, "w", encoding="utf-8") if dry_run_path else None

    def flush(records: list[Record]) -> None:
        for i in range(0, len(records), batch_size):
            chunk = records[i:i + batch_size]
            ledger.count(chunk)
            if dry_file:
                for _, source, payload in chunk:
                    dry_file.write(json.dumps({"source": source, "payload": payload}) + "\n")
            elif client:
                # The batch id comes from the run and the batch number, so a retry or a rerun
                # of the same run is recognised by the server and stored only once.
                batch_id = str(uuid.uuid5(uuid.NAMESPACE_URL, f"htm:{run_id}:{ledger.data['batches']}"))
                response = client.send_batch(batch_id, run_id,
                                             [{"source": s, "payload": p} for _, s, p in chunk])
                ledger.server(response)
                if response.get("rejected"):
                    log(f"server rejected {response['rejected']} records: {response.get('rejects')}")
        ledger.save()

    minute = 0
    try:
        while minutes == 0 or minute < minutes:
            minute_start = start + timedelta(minutes=minute)
            if realtime:
                # Wait for the minute to finish, so no record is stamped in the future.
                wait = (minute_start + timedelta(minutes=1) - datetime.now(timezone.utc)).total_seconds()
                if wait > 0:
                    time.sleep(wait)
            records = minute_records(gen, hospital, minute_start)
            ledger.data["minutes"] = minute + 1
            ledger.data["simulated_to"] = (minute_start + timedelta(minutes=1)).isoformat()
            flush(records)
            minute += 1
            if realtime or minute % 10 == 0 or minute == minutes:
                log(f"minute {minute}: {ledger.data['emitted_total']} records emitted so far")
    except KeyboardInterrupt:
        log("stopped")
    finally:
        ledger.save()
        if dry_file:
            dry_file.close()
    return ledger


def verify(client: ApiClient, ledger: dict, out=sys.stdout) -> bool:
    """Compares the ledger with what the database holds for the run. Returns True when every source matches."""
    report = client.run_report(ledger["run_id"])
    stored = report.get("stored", {})
    ok = True
    print(f"run {ledger['run_id']}: {report.get('batches', 0)} batches stored", file=out)
    print(f"{'source':<16}{'emitted':>10}{'stored':>10}  result", file=out)
    for source in sorted(set(ledger["emitted"]) | set(stored)):
        emitted, got = int(ledger["emitted"].get(source, 0)), int(stored.get(source, 0))
        match = emitted == got
        ok = ok and match
        print(f"{source:<16}{emitted:>10}{got:>10}  {'match' if match else 'MISMATCH'}", file=out)
    total_emitted, total_stored = int(ledger["emitted_total"]), int(report.get("stored_total", 0))
    ok = ok and total_emitted == total_stored and total_emitted > 0
    print(f"{'total':<16}{total_emitted:>10}{total_stored:>10}  {'match' if total_emitted == total_stored else 'MISMATCH'}", file=out)
    if total_emitted == 0:
        print("nothing was emitted, so there is nothing to verify", file=out)
    missing = [s for s in SOURCES if int(ledger["emitted"].get(s, 0)) == 0]
    if missing:
        print(f"note: no records emitted for {', '.join(missing)}", file=out)
    print("RESULT: PASS" if ok else "RESULT: FAIL", file=out)
    return ok
