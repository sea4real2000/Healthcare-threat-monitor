"""A connector that carries out isolation requests by calling a webhook.

Most endpoint products and automation tools can start an isolation from an
incoming webhook. This connector is the bridge: it reads approved requests from
the platform through the signed API, posts each one to the address you set, and
reports back whether the call was accepted.

Run from the engine folder:  python -m connectors.webhook_connector

Environment:
  HTM_API_URL              the console address
  HTM_CONNECTOR_ID         collector to sign as. Defaults to endpoint_webhook_01. It needs the respond permission
  HTM_CONNECTOR_SECRET     that collector's secret, from: npm run collector:key -- endpoint_webhook_01
  CONNECTOR_TARGET_URL     where to post each request
  CONNECTOR_TARGET_KEY     optional. Signs each post with HMAC SHA256 so the target can check where it came from
  CONNECTOR_TARGET_AUTH    optional. Sent as the Authorization header, for example "Bearer abc"
  CONNECTOR_POLL_SECONDS   optional. Defaults to 3

Switch the built in simulated connector off in Settings (response.simulated_connector)
when this one is running, or the two will race for the same requests.

To support a product with its own API instead of a webhook, copy this file and
replace deliver(). Everything else stays the same.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import sys
import time
import urllib.error
import urllib.request
from urllib.parse import urlparse

from simulator.client import ApiClient, ApiError

MAX_ATTEMPTS = 5


def build_payload(action: dict) -> dict:
    return {
        "version": 1, "action": action["action"], "action_id": action["id"],
        "asset": {"id": action["asset_id"], "ip": action.get("asset_ip"), "kind": action.get("asset_kind")},
        "incident_id": action.get("incident_id"), "approved_by": action.get("requested_by_name"), "approved_at": action.get("requested_at"),
    }


def deliver(url: str, payload: dict, key: str = "", auth: str = "", timeout: float = 10.0) -> tuple[bool, str]:
    """Posts one request to the target. Returns whether it was accepted, and a short note."""
    body = json.dumps(payload, separators=(",", ":"), default=str).encode("utf-8")
    headers = {"content-type": "application/json", "user-agent": "htm-connector/0.3"}
    if key:
        timestamp = str(int(time.time()))
        canonical = ":".join(["v1", timestamp, "POST", urlparse(url).path, hashlib.sha256(body).hexdigest()])
        headers["x-htm-timestamp"] = timestamp
        headers["x-htm-signature"] = hmac.new(key.encode("utf-8"), canonical.encode("utf-8"), hashlib.sha256).hexdigest()
    if auth:
        headers["authorization"] = auth
    try:
        with urllib.request.urlopen(urllib.request.Request(url, data=body, headers=headers, method="POST"), timeout=timeout) as resp:
            return True, f"target accepted, http {resp.status}"
    except urllib.error.HTTPError as err:
        return False, f"target refused, http {err.code}"
    except (urllib.error.URLError, OSError) as err:
        return False, f"target unreachable: {err}"


class Connector:
    def __init__(self, client: ApiClient, target_url: str, key: str = "", auth: str = "") -> None:
        if not target_url:
            raise ValueError("CONNECTOR_TARGET_URL must be set")
        self.client, self.target_url, self.key, self.auth = client, target_url, key, auth
        self.attempts: dict[str, int] = {}

    def poll_once(self) -> int:
        """Handles every waiting request once. Returns how many were acknowledged or failed."""
        settled = 0
        for action in self.client.request("GET", "/api/response/actions").get("actions", []):
            ok, note = deliver(self.target_url, build_payload(action), self.key, self.auth)
            tries = self.attempts.get(action["id"], 0) + 1
            self.attempts[action["id"]] = tries
            if not ok and tries < MAX_ATTEMPTS:
                # Leave the request waiting and try again on the next poll.
                print(f"{action['action']} of {action['asset_id']}: {note}. Attempt {tries} of {MAX_ATTEMPTS}", file=sys.stderr, flush=True)
                continue
            self.client.request("POST", f"/api/response/actions/{action['id']}/ack",
                                {"status": "acknowledged" if ok else "failed", "note": note[:200]})
            self.attempts.pop(action["id"], None)
            settled += 1
            print(f"{action['action']} of {action['asset_id']}: {note}", file=sys.stderr, flush=True)
        return settled


def main(argv: list[str] | None = None) -> int:
    once = "--once" in (argv if argv is not None else sys.argv[1:])
    try:
        client = ApiClient(os.environ.get("HTM_API_URL", ""), os.environ.get("HTM_CONNECTOR_ID", "endpoint_webhook_01"),
                           os.environ.get("HTM_CONNECTOR_SECRET", ""))
        connector = Connector(client, os.environ.get("CONNECTOR_TARGET_URL", ""), os.environ.get("CONNECTOR_TARGET_KEY", ""),
                              os.environ.get("CONNECTOR_TARGET_AUTH", ""))
    except ValueError as err:
        print(f"error: {err}", file=sys.stderr)
        return 2
    pause = float(os.environ.get("CONNECTOR_POLL_SECONDS", "3"))
    while True:
        try:
            connector.poll_once()
        except (ApiError, RuntimeError) as err:
            print(f"error: {err}", file=sys.stderr, flush=True)
            if once:
                return 1
        if once:
            return 0
        time.sleep(pause)


if __name__ == "__main__":
    sys.exit(main())
