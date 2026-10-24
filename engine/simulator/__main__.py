"""Command line entry point. Run from the engine folder: python -m simulator --help"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path

from .client import ApiClient, ApiError
from .hospital import build_hospital, load_config
from .runner import run, verify


def make_client(args: argparse.Namespace) -> ApiClient:
    return ApiClient(
        base_url=args.api_url or os.environ.get("HTM_API_URL", ""),
        collector_id=os.environ.get("HTM_COLLECTOR_ID", "sim_hospital_01"),
        secret=os.environ.get("HTM_COLLECTOR_SECRET", ""),
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="simulator", description="Hospital log simulator")
    parser.add_argument("--config", help="path to a hospital config file")
    parser.add_argument("--api-url", help="platform base URL. Defaults to HTM_API_URL")
    parser.add_argument("--synthea-patients", help="path to a Synthea patients.csv export")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("describe", help="print a summary of the simulated hospital")
    p_data = sub.add_parser("dataset", help="check a folder of CICIoMT2024 feature files and print what was found")
    p_data.add_argument("directory")
    sub.add_parser("register", help="send the inventory to the platform")

    p_run = sub.add_parser("run", help="emit logs")
    p_run.add_argument("--minutes", type=int, default=60, help="simulated minutes. Zero with realtime runs until stopped")
    p_run.add_argument("--speed", choices=["fast", "realtime"], default="fast")
    p_run.add_argument("--seed", type=int, help="overrides the seed in the config")
    p_run.add_argument("--run-id", help="letters, digits and underscores only")
    p_run.add_argument("--batch-size", type=int, default=500)
    p_run.add_argument("--ledger", default="runs/ledger.json")
    p_run.add_argument("--dry-run", metavar="FILE", help="write records to a file and send nothing")
    p_run.add_argument("--skip-register", action="store_true")
    p_run.add_argument("--verify", action="store_true", help="compare the ledger with the database when the run ends")

    p_verify = sub.add_parser("verify", help="compare a ledger with what the database holds")
    p_verify.add_argument("--ledger", default="runs/ledger.json")

    args = parser.parse_args(argv)
    config = load_config(args.config)

    try:
        if args.command == "dataset":
            from .dataset import load, summary
            print(json.dumps(summary(load(args.directory)), indent=2))
            return 0
        if args.command == "verify":
            ledger = json.loads(Path(args.ledger).read_text(encoding="utf-8"))
            return 0 if verify(make_client(args), ledger) else 1

        seed = getattr(args, "seed", None)
        hospital = build_hospital(config, seed=None, synthea_patients=args.synthea_patients)
        if args.command == "describe":
            print(json.dumps(hospital.summary(), indent=2))
            return 0
        if args.command == "register":
            print(json.dumps(make_client(args).send_inventory(hospital.inventory())))
            return 0

        realtime = args.speed == "realtime"
        if args.minutes < 0 or (args.minutes == 0 and not realtime):
            parser.error("--minutes must be above zero unless --speed realtime is used")
        run_id = args.run_id or f"run{int(time.time())}"
        client = None if args.dry_run else make_client(args)
        if client and not args.skip_register:
            result = client.send_inventory(hospital.inventory())
            print(f"inventory registered: {result}", file=sys.stderr)
        ledger = run(
            hospital, client=client, run_id=run_id, seed=config["seed"] if seed is None else seed,
            minutes=args.minutes, realtime=realtime, batch_size=args.batch_size,
            ledger_path=Path(args.ledger), dry_run_path=Path(args.dry_run) if args.dry_run else None,
        )
        print(json.dumps(ledger.data, indent=2))
        if args.verify and client:
            return 0 if verify(client, ledger.data) else 1
        return 0
    except ApiError as err:
        print(f"error: {err}", file=sys.stderr)
        return 2
    except (ValueError, RuntimeError, FileNotFoundError) as err:
        print(f"error: {err}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
