"""Reads syslog messages from routers, firewalls and servers.

Each message is first split into its syslog header and text, then matched against the log formats
the platform understands. A match becomes a record for one of the platform's log sources (firewall,
vpn or linux), in the same shape a collector would send it. Anything else is counted as not understood,
so an administrator can see it on the Sources page.

Pure functions only, so every format can be tested with real example messages.
"""

from __future__ import annotations

import ipaddress
import re
import shlex
from dataclasses import dataclass, field

# Syslog header

PRI = re.compile(rb"^<(\d{1,3})>")
RFC5424 = re.compile(r"^1 (\S+) (\S+) (\S+) (\S+) (\S+) (-|(?:\[(?:[^\]\\]|\\.)*\])+) ?(.*)$", re.S)
BSD_TIME = r"(?:[A-Z][a-z]{2} {1,2}\d{1,2}(?: \d{4})? \d{2}:\d{2}:\d{2}(?:\.\d+)?|\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)"
RFC3164 = re.compile(rf"^({BSD_TIME}):?(?: |$)", re.S)
HOSTNAME = re.compile(r"^[A-Za-z0-9][\w.\-]{0,62}$")
TAG = re.compile(r"^(?P<app>[\w./\-]{1,48})(?:\[(?P<pid>\d+)\])?: ?(?P<msg>.*)$", re.S)


@dataclass
class Syslog:
    facility: int | None = None
    severity: int | None = None
    device_time: str | None = None
    hostname: str | None = None
    app: str | None = None
    msg: str = ""


def split_syslog(data: bytes, limit: int = 8192) -> Syslog:
    """Splits one syslog message into header fields and text. Never raises."""
    data = data[:limit].rstrip(b"\r\n\x00")
    out = Syslog()
    m = PRI.match(data)
    if m:
        pri = int(m.group(1))
        if pri <= 191:
            out.facility, out.severity = pri // 8, pri % 8
        data = data[m.end():]
    text = data.decode("utf-8", "replace").lstrip("﻿")
    m5 = RFC5424.match(text)
    if m5:
        time, host, app, _pid, _msgid, _sd, msg = m5.groups()
        out.device_time = None if time == "-" else time
        out.hostname = None if host == "-" else host
        out.app = None if app == "-" else app
        out.msg = msg.lstrip("﻿")
        return out
    m3 = RFC3164.match(text)
    if m3:
        out.device_time = m3.group(1)
        rest = text[m3.end(1):].lstrip(": ")
        lead = re.match(r"^([\w./\-]{1,48})(?:\[\d+\])?: ", rest)
        if lead:
            # "tag[pid]: message", with no host name.
            tag = TAG.match(rest)
            out.app, out.msg = tag.group("app"), tag.group("msg")
            return out
        first, _, after = rest.partition(" ")
        if after and HOSTNAME.match(first):
            out.hostname = first
            if after.startswith(":"):
                # Cisco style: "host : %ASA-..."
                out.msg = after.lstrip(": ")
            elif tag := re.match(r"^([\w./\-]{1,48})(?:\[\d+\])?: ", after) and TAG.match(after):
                out.app, out.msg = tag.group("app"), tag.group("msg")
            else:
                out.msg = after
        else:
            out.msg = rest
        return out
    tag = TAG.match(text)
    if tag and not text.startswith(("date=", "logver=")):
        out.app, out.msg = tag.group("app"), tag.group("msg")
    else:
        out.msg = text
    return out


# What a parser returns

@dataclass
class Parsed:
    format: str                      # the device family, shown to the administrator
    source: str | None               # the platform source the record goes to, or None to count it and keep nothing
    payload: dict = field(default_factory=dict)


def _ip(v) -> str | None:
    if not v:
        return None
    v = str(v).strip().strip("[]")
    try:
        return str(ipaddress.ip_address(v))
    except ValueError:
        return None


def _int(v) -> int | None:
    try:
        n = int(str(v).strip())
        return n if n >= 0 else None
    except (TypeError, ValueError):
        return None


PROTOCOLS = {"1": "icmp", "6": "tcp", "17": "udp", "47": "gre", "50": "esp", "58": "icmpv6"}


def _proto(v) -> str | None:
    if v is None:
        return None
    v = str(v).strip().lower()
    return PROTOCOLS.get(v, v) or None


def _flow(fmt: str, action: str, src, dst, spt=None, dpt=None, proto=None, sent=None, rcvd=None, rule=None) -> Parsed | None:
    src, dst = _ip(src), _ip(dst)
    if not src or not dst:
        return None
    return Parsed(fmt, "firewall", {
        "action": action, "src": src, "dst": dst, "spt": _int(spt), "dpt": _int(dpt), "proto": _proto(proto),
        "sent": _int(sent), "rcvd": _int(rcvd), "rule": rule,
    })


DENY_WORDS = re.compile(r"(?i)\b(drop|dropped|deny|denied|reject|rejected|block|blocked)\b")
ALLOW_WORDS = re.compile(r"(?i)\b(accept|accepted|allow|allowed|pass|permit|permitted)\b")
EDGE_SUFFIX = re.compile(r"\[[\w.\-]+-([ADR])\]")


def _action_from_words(text: str) -> str:
    edge = EDGE_SUFFIX.search(text)
    if edge:
        return "allow" if edge.group(1) == "A" else "deny"
    if DENY_WORDS.search(text):
        return "deny"
    if ALLOW_WORDS.search(text):
        return "allow"
    return "unknown"


# Cisco ASA and Firepower Threat Defense

ASA = re.compile(r"%(?:ASA|FTD)-\d-(\d{6}): (.*)", re.S)
ADDR = r"(?:(\S+?):)?([0-9a-fA-F:.]+)/(\d+)"
ASA_106001 = re.compile(rf"Inbound (\w+) connection denied from ([0-9a-fA-F:.]+)/(\d+) to ([0-9a-fA-F:.]+)/(\d+)")
ASA_106006 = re.compile(r"Deny (?:inbound|outbound) (\w+) from ([0-9a-fA-F:.]+)/(\d+) to ([0-9a-fA-F:.]+)/(\d+)")
ASA_106015 = re.compile(r"Deny (\w+) \(no connection\) from ([0-9a-fA-F:.]+)/(\d+) to ([0-9a-fA-F:.]+)/(\d+)")
ASA_106023 = re.compile(rf"Deny (\w+) src {ADDR} dst {ADDR}(?: \(type \d+, code \d+\))? by access-group \"([^\"]+)\"")
ASA_106100 = re.compile(r"access-list (\S+) (permitted|denied) (\w+) [\w-]+/([0-9a-fA-F:.]+)\((\d+)\)(?:\([^)]*\))? -> [\w-]+/([0-9a-fA-F:.]+)\((\d+)\)")
ASA_BUILT = re.compile(rf"Built (inbound|outbound) (TCP|UDP) connection \d+ for {ADDR} \(\S+\)(?:\([^)]*\))? to {ADDR}")


def cisco_asa(s: Syslog) -> Parsed | None:
    m = ASA.search(s.msg)
    if not m:
        return None
    code, text = m.group(1), m.group(2)
    fmt = "Cisco ASA"
    if code == "106001" and (x := ASA_106001.search(text)):
        return _flow(fmt, "deny", x.group(2), x.group(4), x.group(3), x.group(5), x.group(1))
    if code in ("106006", "106007") and (x := ASA_106006.search(text)):
        return _flow(fmt, "deny", x.group(2), x.group(4), x.group(3), x.group(5), x.group(1))
    if code == "106015" and (x := ASA_106015.search(text)):
        return _flow(fmt, "deny", x.group(2), x.group(4), x.group(3), x.group(5), x.group(1))
    if code == "106023" and (x := ASA_106023.search(text)):
        return _flow(fmt, "deny", x.group(3), x.group(6), x.group(4), x.group(7), x.group(1), rule=x.group(8))
    if code == "106100" and (x := ASA_106100.search(text)):
        return _flow(fmt, "allow" if x.group(2) == "permitted" else "deny", x.group(4), x.group(6), x.group(5), x.group(7), x.group(3), rule=x.group(1))
    if code in ("302013", "302015") and (x := ASA_BUILT.search(text)):
        # "for" names the outside end of the connection, "to" the inside end. Who started it depends on the direction.
        a_ip, a_port, b_ip, b_port = x.group(4), x.group(5), x.group(7), x.group(8)
        if x.group(1) == "inbound":
            return _flow(fmt, "allow", a_ip, b_ip, a_port, b_port, x.group(2))
        return _flow(fmt, "allow", b_ip, a_ip, b_port, a_port, x.group(2))
    # A Cisco message the platform does not need, such as a connection being torn down.
    return Parsed(fmt, None)


# Key and value logs: FortiGate, Sophos, SonicWall and others

KV = re.compile(r'([A-Za-z_][\w.\-]*)=("(?:[^"\\]|\\.)*"|\S*)')


def key_values(text: str) -> dict[str, str]:
    out = {}
    for k, v in KV.findall(text):
        if v.startswith('"') and v.endswith('"') and len(v) >= 2:
            v = v[1:-1].replace('\\"', '"')
        out[k.lower()] = v
    return out


def _first(kv: dict, *keys):
    for k in keys:
        if kv.get(k) not in (None, "", "N/A", "-"):
            return kv[k]
    return None


FORTI_ALLOW = {"accept", "close", "timeout", "server-rst", "client-rst", "start", "pass"}
FORTI_DENY = {"deny", "block", "ip-conn", "dropped", "reset"}
VPN_EVENTS = {
    "ssl-login-fail": "auth_failed", "ssl-new-con": None, "tunnel-up": "session_start", "tunnel-down": "session_end",
    "negotiate": None, "login-fail": "auth_failed",
}


def fortigate(s: Syslog) -> Parsed | None:
    text = s.msg
    if "devid=" not in text and "logid=" not in text:
        return None
    kv = key_values(text)
    if "type" not in kv:
        return None
    fmt = "Fortinet FortiGate"
    device = kv.get("devname")
    if kv["type"] == "traffic":
        action = (kv.get("action") or "").lower()
        verdict = "allow" if action in FORTI_ALLOW else "deny" if action in FORTI_DENY else "unknown"
        p = _flow(fmt, verdict, kv.get("srcip"), kv.get("dstip"), kv.get("srcport"), kv.get("dstport"), kv.get("proto"),
                  kv.get("sentbyte"), kv.get("rcvdbyte"), rule=kv.get("policyid"))
        if p:
            p.payload["fw"] = device
        return p
    if kv["type"] == "event" and kv.get("subtype") == "vpn":
        event = VPN_EVENTS.get((kv.get("action") or "").lower())
        client = _ip(_first(kv, "remip", "srcip"))
        if event and client:
            return Parsed(fmt, "vpn", {"event": event, "user": _first(kv, "user", "xauthuser"), "client_ip": client, "gateway": device,
                                       "bytes_out": _int(kv.get("sentbyte")), "bytes_in": _int(kv.get("rcvdbyte"))})
    return Parsed(fmt, None)


def generic_key_values(s: Syslog) -> Parsed | None:
    """Firewall logs written as key=value pairs by other vendors, such as Sophos and SonicWall."""
    kv = key_values(s.msg)
    src = _first(kv, "src_ip", "srcip", "src", "source_ip", "sourceip")
    dst = _first(kv, "dst_ip", "dstip", "dst", "destination_ip", "destip", "dstaddr")
    if not (_ip(src) and _ip(dst)):
        return None
    word = (_first(kv, "action", "status", "fw_action", "fw_rule_action", "disposition") or "").lower()
    verdict = "allow" if word in ("allow", "allowed", "accept", "accepted", "permit", "pass", "forwarded") else \
        "deny" if word in ("deny", "denied", "drop", "dropped", "block", "blocked", "reject", "rejected") else _action_from_words(s.msg)
    family = "Sophos" if "log_type=" in s.msg or "device_name=" in s.msg else "SonicWall" if " fw=" in f" {s.msg}" and "sn=" in s.msg else "Key and value firewall"
    p = _flow(family, verdict, src, dst, _first(kv, "src_port", "srcport", "spt", "sport"), _first(kv, "dst_port", "dstport", "dpt", "dport"),
              _first(kv, "protocol", "proto"), _first(kv, "sent_bytes", "sentbyte", "bytes_sent", "sent", "bytes_out"),
              _first(kv, "recv_bytes", "rcvdbyte", "bytes_received", "rcvd", "bytes_in"), rule=_first(kv, "fw_rule_id", "rule", "policy", "rule_id"))
    if p:
        p.payload["fw"] = _first(kv, "device_name", "devname", "fw")
    return p


# pfSense and OPNsense

def pf_filterlog(s: Syslog) -> Parsed | None:
    if s.app != "filterlog":
        return None
    f = s.msg.split(",")
    fmt = "pfSense or OPNsense"
    if len(f) < 9:
        return Parsed(fmt, None)
    rule, iface, action, version = f[3], f[4], f[6], f[8]
    verdict = "allow" if action == "pass" else "deny" if action in ("block", "reject") else "unknown"
    try:
        if version == "4" and len(f) >= 20:
            proto, src, dst = f[16], f[18], f[19]
            ports = f[20:22] if proto in ("tcp", "udp") and len(f) >= 22 else [None, None]
        elif version == "6" and len(f) >= 17:
            proto, src, dst = f[12], f[15], f[16]
            ports = f[17:19] if proto in ("tcp", "udp") and len(f) >= 19 else [None, None]
        else:
            return Parsed(fmt, None)
    except IndexError:
        return Parsed(fmt, None)
    return _flow(fmt, verdict, src, dst, ports[0], ports[1], proto, rule=f"{rule} on {iface}") or Parsed(fmt, None)


# Linux netfilter: OpenWrt, Ubiquiti, UFW, Synology and most Linux based routers

NF = re.compile(r"\bIN=(\S*) OUT=(\S*).*?\bSRC=([0-9a-fA-F:.]+) DST=([0-9a-fA-F:.]+)\b.*?\bPROTO=(\w+)(?:.*?\bSPT=(\d+) DPT=(\d+))?", re.S)


def netfilter(s: Syslog) -> Parsed | None:
    m = NF.search(s.msg)
    if not m:
        return None
    before = s.msg[:m.start()]
    fmt = "Ubiquiti" if EDGE_SUFFIX.search(before) else "UFW" if "[UFW " in before else "Linux netfilter (OpenWrt and similar)"
    return _flow(fmt, _action_from_words(before), m.group(3), m.group(4), m.group(6), m.group(7), m.group(5), rule=before.strip(" :[]")[:80] or None)


# MikroTik RouterOS

MIKROTIK = re.compile(r"(?:^|\s)(?:(?P<prefix>.*?)\s)?(?P<chain>forward|input|output|srcnat|dstnat|prerouting|postrouting|[\w-]+): in:(?P<in>\S+) out:(?P<out>[^,]+),"
                      r".*?proto (?P<proto>\w+)(?: \([^)]*\))?, (?P<src>[0-9a-fA-F.:]+?)(?::(?P<spt>\d+))?->(?P<dst>[0-9a-fA-F.:]+?)(?::(?P<dpt>\d+))?(?:,|$)", re.S)


def mikrotik(s: Syslog) -> Parsed | None:
    m = MIKROTIK.search(s.msg)
    if not m:
        return None
    words = f"{s.app or ''} {m.group('prefix') or ''}"
    return _flow("MikroTik", _action_from_words(words), m.group("src"), m.group("dst"), m.group("spt"), m.group("dpt"), m.group("proto"),
                 rule=(m.group("prefix") or m.group("chain")).strip()[:80])


# Linux servers and network devices with a secure shell

DROPBEAR = re.compile(r"^(?:Bad password attempt for|Login attempt for nonexistent user|Password auth succeeded for) '?([^' ]+)'? from ([0-9a-fA-F:.]+):(\d+)")


def linux_auth(s: Syslog) -> Parsed | None:
    app = (s.app or "").lower()
    msg = s.msg
    if app == "dropbear":
        m = DROPBEAR.match(msg)
        if not m:
            return Parsed("Linux or router secure shell", None)
        ok = msg.startswith("Password auth succeeded")
        # Written the way OpenSSH writes it, so the same reader understands both.
        msg = f"{'Accepted' if ok else 'Failed'} password for {m.group(1)} from {m.group(2)} port {m.group(3)} ssh2"
        app = "sshd"
    if app in ("sshd", "sudo", "cron", "crond"):
        return Parsed("Linux server", "linux", {"program": "cron" if app == "crond" else app, "msg": msg, "host": s.hostname})
    return None


# In order: specific formats first, the broadest last.
PARSERS = (cisco_asa, pf_filterlog, fortigate, netfilter, mikrotik, linux_auth, generic_key_values)


def recognise(s: Syslog) -> Parsed | None:
    for parse in PARSERS:
        try:
            p = parse(s)
        except (ValueError, IndexError):
            p = None
        if p is not None:
            return p
    return None


# Zones, so the platform's network rules apply to router logs

# Addresses that never leave a hospital's own network. Everything else is treated as the internet.
INTERNAL_NETWORKS = [ipaddress.ip_network(n) for n in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16", "127.0.0.0/8", "fc00::/7", "fe80::/10", "::1/128")]


def zone_for(ip: str | None, inventory: dict[str, str]) -> str | None:
    """The zone of an address: the zone recorded for it in the inventory, "internet" for a public address,
    or "internal" for a private address the inventory does not list."""
    if not ip:
        return None
    if ip in inventory:
        return inventory[ip]
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None
    return "internal" if any(addr in net for net in INTERNAL_NETWORKS if net.version == addr.version) else "internet"


def tokens(text: str) -> list[str]:
    """Splits text the way a shell would, falling back to spaces. Used for messages that quote values."""
    try:
        return shlex.split(text)
    except ValueError:
        return text.split()
