"""A stand in for the platform's ingestion API, used by the Windows collector check in CI.

Listens on http://127.0.0.1:8765, checks each batch's signature exactly as the platform does, writes every
record it accepts to a JSON lines file, and refuses a wrong signature the way the platform does.
    python scripts/windows_ci_receiver.py <secret> <output.jsonl>
Not part of any installation.
"""

import hashlib
import hmac
import json
import sys
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

SECRET, OUT = sys.argv[1], sys.argv[2]


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def reply(self, code: int, body: dict) -> None:
        data = json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        if self.path != "/api/ingest":
            return self.reply(404, {"ok": False, "error": "not_found"})
        ts = self.headers.get("x-htm-timestamp", "")
        if not ts.isdigit() or abs(time.time() - int(ts)) > 300:
            return self.reply(401, {"ok": False, "error": "timestamp_outside_window"})
        canonical = ":".join(["v1", ts, "POST", "/api/ingest", hashlib.sha256(body).hexdigest()])
        expected = hmac.new(SECRET.encode(), canonical.encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, self.headers.get("x-htm-signature", "")):
            return self.reply(401, {"ok": False, "error": "signature_mismatch"})
        batch = json.loads(body)
        with open(OUT, "a", encoding="utf-8") as f:
            for r in batch["records"]:
                f.write(json.dumps({"collector": self.headers.get("x-htm-key-id"), **r}) + "\n")
        n = len(batch["records"])
        return self.reply(200, {"ok": True, "batch_id": batch["batch_id"], "records": n, "accepted": n, "duplicate": 0, "rejected": 0})


print("test receiver on http://127.0.0.1:8765", flush=True)
HTTPServer(("127.0.0.1", 8765), Handler).serve_forever()
