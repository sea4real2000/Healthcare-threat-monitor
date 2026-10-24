"""Signed HTTP client for the platform API. Standard library only."""

from __future__ import annotations

import hashlib
import hmac
import json
import time
import urllib.error
import urllib.request
from urllib.parse import urlparse


class ApiError(Exception):
    def __init__(self, status: int, body: str) -> None:
        super().__init__(f"API returned {status}: {body[:300]}")
        self.status = status
        self.body = body


def canonical_string(timestamp: str, method: str, path: str, body: bytes) -> str:
    """The exact string both sides sign. It must match web/lib/signing.ts."""
    return ":".join(["v1", timestamp, method.upper(), path, hashlib.sha256(body).hexdigest()])


def sign(secret: str, timestamp: str, method: str, path: str, body: bytes) -> str:
    message = canonical_string(timestamp, method, path, body).encode("utf-8")
    return hmac.new(secret.encode("utf-8"), message, hashlib.sha256).hexdigest()


class ApiClient:
    def __init__(self, base_url: str, collector_id: str, secret: str, timeout: float = 30.0, retries: int = 4) -> None:
        if not base_url or not secret:
            raise ValueError("HTM_API_URL and HTM_COLLECTOR_SECRET must both be set")
        self.base_url = base_url.rstrip("/")
        self.collector_id = collector_id
        self.secret = secret
        self.timeout = timeout
        self.retries = retries

    def request(self, method: str, path: str, payload: dict | None = None) -> dict:
        """Sends one signed request. Network errors and server errors are retried with the same body,
        which is safe because the ingestion API ignores a batch it has already stored."""
        body = b"" if payload is None else json.dumps(payload, separators=(",", ":")).encode("utf-8")
        url = self.base_url + path
        last_error: Exception | None = None
        waited = 0
        attempt = 0
        while attempt <= self.retries:
            timestamp = str(int(time.time()))
            headers = {
                "content-type": "application/json",
                "x-htm-key-id": self.collector_id,
                "x-htm-timestamp": timestamp,
                "x-htm-signature": sign(self.secret, timestamp, method, urlparse(url).path, body),
                "user-agent": "htm-simulator/0.1",
            }
            req = urllib.request.Request(url, data=body if method != "GET" else None, headers=headers, method=method)
            try:
                with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                    return json.loads(resp.read().decode("utf-8"))
            except urllib.error.HTTPError as err:
                text = err.read().decode("utf-8", "replace")
                if err.code == 429 and waited < 120:
                    # Over the rate limit. The limit resets each minute, so wait and send the same request again.
                    time.sleep(5)
                    waited += 5
                    continue
                if err.code < 500:
                    raise ApiError(err.code, text) from None
                last_error = ApiError(err.code, text)
            except (urllib.error.URLError, TimeoutError, ConnectionError) as err:
                last_error = err
            if attempt < self.retries:
                time.sleep(min(2 ** attempt, 15))
            attempt += 1
        raise RuntimeError(f"{method} {path} failed after {self.retries + 1} attempts: {last_error}")

    def send_inventory(self, inventory: dict) -> dict:
        return self.request("POST", "/api/inventory", inventory)

    def send_batch(self, batch_id: str, run_id: str, records: list[dict]) -> dict:
        return self.request("POST", "/api/ingest", {"batch_id": batch_id, "run_id": run_id, "records": records})

    def run_report(self, run_id: str) -> dict:
        return self.request("GET", f"/api/runs/{run_id}")
