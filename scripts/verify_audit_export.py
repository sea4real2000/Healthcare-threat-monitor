"""Checks an audit log export without trusting the platform that produced it.

Usage:  python scripts/verify_audit_export.py audit_export.json [signing key]

It recomputes every hash from the fields in the file and checks that each entry
points at the one before it. With a signing key it also checks the file signature.
Standard library only.
"""

import hashlib
import hmac
import json
import sys

FIELDS = ["prev_hash", "seq", "at_text", "actor_type", "actor_id", "actor_name", "action", "subject_type", "subject_id", "detail_text"]


def canonical(entry: dict) -> str:
    return "|".join(f"{len(str(entry[f]))}:{entry[f]}" for f in FIELDS)


def main() -> int:
    if len(sys.argv) < 2:
        print(__doc__)
        return 2
    with open(sys.argv[1], encoding="utf-8") as fh:
        export = json.load(fh)
    entries = export["entries"]
    previous, expected = "0" * 64, 1
    for entry in entries:
        if int(entry["seq"]) != expected:
            print(f"FAIL: entry {expected} is missing")
            return 1
        if entry["prev_hash"] != previous:
            print(f"FAIL: entry {entry['seq']} does not link to the entry before it")
            return 1
        if hashlib.sha256(canonical(entry).encode("utf-8")).hexdigest() != entry["hash"]:
            print(f"FAIL: the contents of entry {entry['seq']} were changed")
            return 1
        previous, expected = entry["hash"], expected + 1
    if export.get("head_hash") not in (None, previous) and entries:
        print("FAIL: the head hash in the file does not match the last entry")
        return 1
    print(f"Chain intact: {len(entries)} entries. Newest hash {previous}")
    if len(sys.argv) > 2:
        body = json.dumps(entries, separators=(",", ":"), ensure_ascii=False)
        good = hmac.new(sys.argv[2].encode("utf-8"), body.encode("utf-8"), hashlib.sha256).hexdigest()
        if not export.get("signature") or not hmac.compare_digest(good, export["signature"]):
            print("FAIL: the file signature does not match this key")
            return 1
        print("File signature valid")
    return 0


if __name__ == "__main__":
    sys.exit(main())
