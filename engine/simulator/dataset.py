"""Loader for the CICIoMT2024 medical device traffic dataset.

The dataset is published by the Canadian Institute for Cybersecurity:
https://www.unb.ca/cic/datasets/iomt-dataset-2024.html
Download it yourself and point the simulator at the folder of feature CSV files.
Nothing from the dataset is included in this repository.

Each row of those files summarises a short run of packets captured from real and
simulated medical devices under attack: packet rate, sizes, flag counts and
protocol shares. The rows carry no addresses. So the dataset supplies the shape
of the attack traffic, and the simulator supplies which device is sending it and
to whom.

The attack class is read from the file name, which is how the dataset labels it.
"""

from __future__ import annotations

import csv
import re
from dataclasses import dataclass
from pathlib import Path

CLASSES = ["benign", "recon", "spoofing", "mqtt", "ddos", "dos"]
RECON_WORDS = ("recon", "scan", "sweep")


@dataclass
class TrafficRow:
    rate_pps: float
    packets: int
    bytes: int
    syn: int
    rst: int
    protocol: str


def classify(filename: str) -> str | None:
    """Attack class from a file name such as 'TCP_IP-DDoS-UDP1_train.pcap.csv' or 'Benign_test.pcap.csv'."""
    name = filename.lower()
    if "benign" in name:
        return "benign"
    if any(w in name for w in RECON_WORDS):
        return "recon"
    if "spoof" in name:
        return "spoofing"
    if "mqtt" in name:
        return "mqtt"
    if "ddos" in name:
        return "ddos"
    if "dos" in name:
        return "dos"
    return None


def _key(column: str) -> str:
    return re.sub(r"[^a-z0-9]", "", column.lower())


def _number(row: dict, *names: str, default: float = 0.0) -> float:
    for name in names:
        value = row.get(name)
        if value not in (None, ""):
            try:
                return float(value)
            except ValueError:
                continue
    return default


def read_file(path: Path, limit: int = 5000) -> list[TrafficRow]:
    """Reads up to `limit` rows. Column names are matched loosely, since spelling varies between releases."""
    rows: list[TrafficRow] = []
    with open(path, encoding="utf-8", errors="replace", newline="") as fh:
        reader = csv.reader(fh)
        header = next(reader, None)
        if not header:
            return rows
        keys = [_key(c) for c in header]
        if "rate" not in keys:
            raise ValueError(f"{path.name} has no Rate column, so it is not a CICIoMT2024 feature file")
        for values in reader:
            if len(rows) >= limit:
                break
            row = dict(zip(keys, values))
            try:
                float(row.get("rate", ""))
            except ValueError:
                continue  # a blank line, or a header repeated inside a joined file
            rate = _number(row, "rate")
            packets = max(1, round(_number(row, "number", default=10)))
            size = _number(row, "totsum") or packets * _number(row, "avg", "totsize", default=60)
            shares = {"tcp": _number(row, "tcp"), "udp": _number(row, "udp"), "icmp": _number(row, "icmp")}
            protocol = max(shares, key=shares.get) if max(shares.values()) > 0 else "tcp"
            if rate < 0 or size < 0:
                continue
            rows.append(TrafficRow(rate_pps=rate, packets=packets, bytes=round(size), syn=round(_number(row, "syncount")),
                                   rst=round(_number(row, "rstcount")), protocol=protocol))
    return rows


def load(directory: str | Path, limit_per_file: int = 5000) -> dict[str, list[TrafficRow]]:
    """Loads every CSV under a folder, grouped by attack class."""
    root = Path(directory)
    if not root.is_dir():
        raise ValueError(f"{directory} is not a folder")
    out: dict[str, list[TrafficRow]] = {}
    for path in sorted(root.rglob("*.csv")):
        label = classify(path.name)
        if label is None:
            continue
        out.setdefault(label, []).extend(read_file(path, limit_per_file))
    if not any(out.values()):
        raise ValueError(f"no CICIoMT2024 feature files found under {directory}")
    return out


def summary(data: dict[str, list[TrafficRow]]) -> dict:
    result = {}
    for label in CLASSES:
        rows = data.get(label, [])
        if rows:
            rates = sorted(r.rate_pps for r in rows)
            result[label] = {"rows": len(rows), "median_rate_pps": round(rates[len(rates) // 2], 2), "highest_rate_pps": round(rates[-1], 2)}
    return result
