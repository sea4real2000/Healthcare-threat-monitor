#!/usr/bin/env python3
"""Checks the report from ZAP's scan of a running installation (security/zap_plan.yaml).

Fails when any alert at or above the chosen risk is not accepted, with a reason, in security/zap_accepted.tsv.
Usage: python3 scripts/zap_check.py REPORT.json [--accepted FILE] [--fail-at high|medium|low|informational]
The risk can also be set with the ZAP_FAIL_AT environment variable. The default is medium.
python3 scripts/zap_check.py --self-test proves the check fails when it should.
"""
import argparse
import json
import os
import sys
import tempfile

RISKS = {"informational": 0, "low": 1, "medium": 2, "high": 3}
NAMES = {v: k for k, v in RISKS.items()}


def load_accepted(path):
    accepted = {}
    with open(path, encoding="utf-8") as f:
        for number, line in enumerate(f, 1):
            line = line.rstrip("\n")
            if not line.strip() or line.startswith("#"):
                continue
            parts = line.split("\t")
            if len(parts) < 3 or not parts[2].strip():
                raise SystemExit(f"{path} line {number}: needs the rule's number, its name and a reason, separated by tabs")
            accepted[parts[0].strip()] = parts[2].strip()
    return accepted


def check(report_path, accepted_path, fail_at):
    with open(report_path, encoding="utf-8") as f:
        report = json.load(f)
    accepted = load_accepted(accepted_path)
    threshold = RISKS[fail_at]
    failures, seen = [], set()
    sites = report.get("site") or []
    if not sites:
        failures.append("the report has no site in it, so the scan reached nothing")
    for site in sites:
        for alert in site.get("alerts", []):
            risk = int(alert.get("riskcode", 0))
            rule = str(alert.get("pluginid"))
            label = f"{NAMES.get(risk, risk)}: {alert.get('name')} (rule {rule}, {alert.get('count', '?')} found)"
            if rule in accepted:
                seen.add(rule)
                print(f"accepted  {label}")
            elif risk >= threshold:
                uri = (alert.get("instances") or [{}])[0].get("uri", "")
                failures.append(f"{label} at {uri}")
            else:
                print(f"below {fail_at}  {label}")
    for rule in sorted(set(accepted) - seen):
        print(f"note: rule {rule} is accepted in {accepted_path} but no longer found, so its line can go")
    for failure in failures:
        print(f"FAIL  {failure}")
    return not failures


def self_test():
    def run(alerts, accepted_lines, fail_at="medium"):
        with tempfile.TemporaryDirectory() as d:
            report, acc = os.path.join(d, "r.json"), os.path.join(d, "a.tsv")
            with open(report, "w") as f:
                json.dump({"site": [{"@name": "https://x", "alerts": alerts}] if alerts is not None else []}, f)
            with open(acc, "w") as f:
                f.write("\n".join(accepted_lines) + "\n")
            return check(report, acc, fail_at)
    high = {"pluginid": "40018", "name": "SQL Injection", "riskcode": "3", "count": "1", "instances": [{"uri": "https://x/a"}]}
    medium = {"pluginid": "10202", "name": "Absence of Anti-CSRF Tokens", "riskcode": "2", "count": "1"}
    low = {"pluginid": "10044", "name": "Big Redirect", "riskcode": "1", "count": "1"}
    results = {
        "a high alert fails": run([high], []) is False,
        "an unaccepted medium alert fails": run([medium], []) is False,
        "an accepted medium alert passes": run([medium], ["10202\tAbsence of Anti-CSRF Tokens\tchecked"]) is True,
        "a low alert passes at medium": run([low], []) is True,
        "a low alert fails at low": run([low], [], "low") is False,
        "a report that reached nothing fails": run(None, []) is False,
    }
    for name, ok in results.items():
        print(("PASS " if ok else "FAIL ") + name)
    return all(results.values())


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("report", nargs="?")
    parser.add_argument("--accepted", default=os.path.join(os.path.dirname(__file__), "..", "security", "zap_accepted.tsv"))
    parser.add_argument("--fail-at", default=os.environ.get("ZAP_FAIL_AT", "medium"), choices=list(RISKS))
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        print("checking that the check fails when it should")
        sys.exit(0 if self_test() else 1)
    if not args.report:
        parser.error("give the report's path")
    ok = check(args.report, args.accepted, args.fail_at)
    print("ZAP scan passed" if ok else "ZAP scan failed")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
