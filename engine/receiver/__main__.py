"""The built in log receiver for routers, firewalls and servers.

Listens for syslog over UDP and TCP. Every device that sends is listed on the Sources page. Its logs are
only kept once an administrator accepts it, because syslog carries no proof of who sent it. Messages in a
format the platform reads become records for the firewall, VPN or Linux sources and are stored through
the same signed ingestion path every collector uses.

Run with the engine folder as the working folder:  python -m receiver
Settings come from the environment, or from the file named by HTM_ENV_FILE, like the background service.
"""

from __future__ import annotations

import os
import signal
import socket
import socketserver
import sys
import threading
import time
import uuid
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone

import psycopg
from psycopg.types.json import Jsonb

from detection.pipeline import connect
from receiver.parsers import recognise, split_syslog, zone_for
from simulator.client import ApiClient, ApiError

MAX_BUFFER = 100_000
MAX_TCP_CLIENTS = 200


def default_gateway() -> str | None:
    """The address the container's network traffic leaves through. When Docker passes traffic on through its
    own proxy, every device appears to come from this address, and the console warns about it."""
    try:
        with open("/proc/net/route") as f:
            for line in f.read().splitlines()[1:]:
                parts = line.split()
                if len(parts) > 2 and parts[1] == "00000000":
                    raw = bytes.fromhex(parts[2])
                    return ".".join(str(b) for b in reversed(raw))
    except (OSError, ValueError):
        pass
    return None


def log(msg: str) -> None:
    print(f"{datetime.now(timezone.utc):%H:%M:%S} receiver: {msg}", file=sys.stderr, flush=True)


@dataclass
class Sender:
    address: str
    state: str = "pending"
    name: str = ""
    received: int = 0
    not_understood: int = 0
    dropped: int = 0
    last_unparsed: str | None = None
    format: str | None = None
    last_seen: datetime | None = None
    minute: int = 0
    minute_count: int = 0
    dirty: bool = True


@dataclass
class Receiver:
    conn: psycopg.Connection
    client: ApiClient
    settings: dict = field(default_factory=dict)
    senders: dict[str, Sender] = field(default_factory=dict)
    zones: dict[str, str] = field(default_factory=dict)
    buffer: deque = field(default_factory=lambda: deque(maxlen=MAX_BUFFER))
    lock: threading.Lock = field(default_factory=threading.Lock)
    lost: int = 0
    batches: int = 0
    counts: dict = field(default_factory=lambda: {"udp": 0, "tcp": 0})
    gateway: str | None = field(default_factory=default_gateway)

    # Loading what the console decides

    def refresh(self) -> None:
        with self.conn.cursor() as cur:
            cur.execute("select key, value from settings where key like 'receiver.%'")
            settings = {r["key"]: r["value"] for r in cur}
            cur.execute("select host(address) as address, state, name from log_senders")
            rows = cur.fetchall()
            cur.execute("select host(ip) as ip, zone from assets where ip is not null")
            zones = {r["ip"]: r["zone"] for r in cur}
        self.conn.commit()
        with self.lock:
            self.settings, self.zones = settings, zones
            for r in rows:
                s = self.senders.setdefault(r["address"], Sender(r["address"], dirty=False))
                s.state, s.name = r["state"], r["name"]

    # Receiving

    def handle(self, address: str, data: bytes) -> None:
        now = datetime.now(timezone.utc)
        limit = int(self.settings.get("receiver.max_message_bytes", 8192))
        per_minute = int(self.settings.get("receiver.sender_per_minute", 60000))
        with self.lock:
            s = self.senders.get(address)
            if s is None:
                s = self.senders[address] = Sender(address)
            s.received += 1
            s.last_seen = now
            s.dirty = True
            if s.state == "blocked":
                return
            minute = int(now.timestamp() // 60)
            if minute != s.minute:
                s.minute, s.minute_count = minute, 0
            s.minute_count += 1
            if s.minute_count > per_minute:
                s.dropped += 1
                return
            msg = split_syslog(data, limit)
            parsed = recognise(msg)
            if parsed is None:
                s.not_understood += 1
                s.last_unparsed = msg.msg[:300]
                return
            s.format = parsed.format
            if s.state != "accepted" or parsed.source is None:
                return
            record = self.record(parsed.source, dict(parsed.payload), msg, s, now)
            if len(self.buffer) == self.buffer.maxlen:
                self.lost += 1
            self.buffer.append((address, record))

    def record(self, source: str, payload: dict, msg, s: Sender, now: datetime) -> dict:
        device = s.name or msg.hostname or s.address
        stamp = now.isoformat()
        payload["id"] = f"rx-{uuid.uuid4().hex}"
        if source == "firewall":
            payload["ts"] = stamp
            payload["fw"] = payload.get("fw") or device
            payload["src_zone"] = zone_for(payload.get("src"), self.zones)
            payload["dst_zone"] = zone_for(payload.get("dst"), self.zones)
        elif source == "vpn":
            payload["time"] = stamp
            payload["gateway"] = payload.get("gateway") or device
        elif source == "linux":
            payload["ts"] = stamp
            payload["host"] = payload.get("host") or device
            payload["facility"] = str(msg.facility) if msg.facility is not None else None
        if msg.device_time:
            payload["device_time"] = msg.device_time
        return {"source": source, "payload": payload}

    # Passing on

    def flush(self) -> None:
        with self.lock:
            pending = list(self.buffer)
            self.buffer.clear()
            changed = [s for s in self.senders.values() if s.dirty]
            snapshot = [(s.address, s.received, s.not_understood + s.dropped, s.last_unparsed, s.format, s.last_seen) for s in changed]
            for s in changed:
                s.received = s.not_understood = s.dropped = 0
                s.dirty = False
        stored: dict[str, int] = {}
        for i in range(0, len(pending), 500):
            chunk = pending[i:i + 500]
            batch_id = str(uuid.uuid4())
            try:
                self.client.send_batch(batch_id, None, [r for _, r in chunk])
            except (ApiError, RuntimeError, OSError) as err:
                # Keep what could not be sent, to try again next time.
                log(f"could not pass {len(pending) - i} records on: {err}")
                with self.lock:
                    for item in reversed(pending[i:]):
                        if len(self.buffer) == self.buffer.maxlen:
                            self.lost += 1
                            break
                        self.buffer.appendleft(item)
                break
            self.batches += 1
            for address, _ in chunk:
                stored[address] = stored.get(address, 0) + 1
        with self.conn.cursor() as cur:
            for address, received, unread, sample, fmt, seen in snapshot:
                cur.execute("""insert into log_senders (address, received, not_understood, last_unparsed, format, last_seen_at)
                    values (%s, %s, %s, %s, %s, %s)
                    on conflict (address) do update set received = log_senders.received + excluded.received,
                      not_understood = log_senders.not_understood + excluded.not_understood,
                      last_unparsed = coalesce(excluded.last_unparsed, log_senders.last_unparsed),
                      format = coalesce(excluded.format, log_senders.format),
                      last_seen_at = greatest(log_senders.last_seen_at, excluded.last_seen_at), updated_at = now()""",
                            (address, received, unread, sample, fmt, seen))
            for address, n in stored.items():
                cur.execute("update log_senders set stored = stored + %s where address = %s", (n, address))
            cur.execute("""insert into engine_state (key, value) values ('receiver_heartbeat', %s)
                on conflict (key) do update set value = excluded.value, updated_at = now()""",
                        (Jsonb({"at": datetime.now(timezone.utc).isoformat(), "waiting": len(self.buffer), "lost": self.lost,
                                "udp": self.counts["udp"], "tcp": self.counts["tcp"], "port": int(os.environ.get("HTM_RECEIVER_PORT", "5514")),
                                "gateway": self.gateway}),))
        self.conn.commit()


def frames(stream: bytes) -> tuple[list[bytes], bytes]:
    """Splits a TCP stream into messages. Accepts octet counting ("57 <34>...") and newline framing."""
    out = []
    while stream:
        head, space, rest = stream.partition(b" ")
        if space and head.isdigit() and 0 < len(head) <= 6 and rest[:1] == b"<":
            n = int(head)
            if len(rest) < n:
                break
            out.append(rest[:n])
            stream = rest[n:]
            continue
        line, nl, rest = stream.partition(b"\n")
        if not nl:
            break
        if line.strip(b"\r\x00"):
            out.append(line)
        stream = rest
    return out, stream


def serve(receiver: Receiver, port: int, stop: threading.Event) -> None:
    # IPv4 only: containers often have IPv6 switched off, and hospital networks address devices over IPv4.
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 * 1024 * 1024)
    udp.bind(("0.0.0.0", port))
    udp.settimeout(1.0)

    def address_of(addr) -> str:
        host = addr[0]
        return host[7:] if host.startswith("::ffff:") else host

    def udp_loop() -> None:
        while not stop.is_set():
            try:
                data, addr = udp.recvfrom(65535)
            except socket.timeout:
                continue
            except OSError:
                continue
            receiver.counts["udp"] += 1
            receiver.handle(address_of(addr), data)

    clients = threading.BoundedSemaphore(MAX_TCP_CLIENTS)

    class Handler(socketserver.BaseRequestHandler):
        def handle(self) -> None:
            if not clients.acquire(blocking=False):
                return
            try:
                self.request.settimeout(300)
                address = address_of(self.client_address)
                pending = b""
                limit = int(receiver.settings.get("receiver.max_message_bytes", 8192)) * 4
                while not stop.is_set():
                    chunk = self.request.recv(65536)
                    if not chunk:
                        break
                    messages, pending = frames(pending + chunk)
                    if len(pending) > limit:
                        # A line longer than any real message. Keep the start and move on.
                        messages.append(pending[:limit])
                        pending = b""
                    for m in messages:
                        receiver.counts["tcp"] += 1
                        receiver.handle(address, m)
            except OSError:
                pass
            finally:
                clients.release()

    class Server(socketserver.ThreadingTCPServer):
        allow_reuse_address = True
        daemon_threads = True

    tcp = Server(("0.0.0.0", port), Handler)
    threading.Thread(target=udp_loop, daemon=True).start()
    threading.Thread(target=tcp.serve_forever, kwargs={"poll_interval": 1.0}, daemon=True).start()
    log(f"listening for syslog on port {port}, UDP and TCP")


def main() -> int:
    port = int(os.environ.get("HTM_RECEIVER_PORT", "5514"))
    client = ApiClient(os.environ.get("HTM_API_URL", ""), os.environ.get("HTM_COLLECTOR_ID", "hospital_service"),
                       os.environ.get("HTM_COLLECTOR_SECRET", ""))
    stop = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: stop.set())
    signal.signal(signal.SIGINT, lambda *_: stop.set())
    receiver = Receiver(connect(), client)
    receiver.refresh()
    serve(receiver, port, stop)
    last_refresh = time.time()
    while not stop.is_set():
        stop.wait(float(receiver.settings.get("receiver.batch_seconds", 5)))
        try:
            if time.time() - last_refresh >= 10:
                receiver.refresh()
                last_refresh = time.time()
            receiver.flush()
        except psycopg.Error as err:
            log(f"database error: {err}")
            try:
                receiver.conn.close()
            except psycopg.Error:
                pass
            time.sleep(5)
            try:
                receiver.conn = connect()
            except psycopg.Error as again:
                log(f"database still unreachable: {again}")
    receiver.flush()
    log("stopped")
    return 0


if __name__ == "__main__":
    sys.exit(main())
