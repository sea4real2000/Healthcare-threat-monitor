"""The log receiver reads the formats routers, firewalls and servers send.

The example messages follow each vendor's documented layout. They are not captured from real devices,
so a device that writes its logs differently may still need a new parser.
"""

import unittest

from receiver.__main__ import Receiver, Sender, frames
from receiver.parsers import recognise, split_syslog, zone_for


def parse(line: str):
    return recognise(split_syslog(line.encode()))


class Header(unittest.TestCase):
    def test_rfc5424(self):
        s = split_syslog(b"<134>1 2026-10-22T10:15:04.123456+01:00 pfsense.hosp.local filterlog 52134 - - 5,,,1000000103,igb1")
        self.assertEqual((s.facility, s.severity, s.hostname, s.app), (16, 6, "pfsense.hosp.local", "filterlog"))
        self.assertTrue(s.msg.startswith("5,,,1000000103"))

    def test_bsd_with_host_and_tag(self):
        s = split_syslog(b"<38>Oct 22 10:15:10 web01 sshd[2211]: Failed password for root from 203.0.113.45 port 51514 ssh2")
        self.assertEqual((s.hostname, s.app), ("web01", "sshd"))
        self.assertTrue(s.msg.startswith("Failed password"))

    def test_bsd_without_host(self):
        s = split_syslog(b"<134>Oct 22 10:15:04 filterlog[52134]: 5,,,1000000103,igb1,match,block")
        self.assertEqual((s.hostname, s.app), (None, "filterlog"))

    def test_cisco_header_with_year(self):
        s = split_syslog(b"<166>Oct 22 2026 10:15:02 asa-edge : %ASA-6-302013: Built inbound TCP connection 1")
        self.assertEqual(s.hostname, "asa-edge")
        self.assertTrue(s.msg.startswith("%ASA-6-302013"))

    def test_no_header_at_all(self):
        s = split_syslog(b'<189>date=2026-10-22 time=10:15:03 devname="FGT-HQ" type="traffic"')
        self.assertEqual((s.hostname, s.app), (None, None))
        self.assertTrue(s.msg.startswith("date="))

    def test_garbage_never_raises(self):
        for data in (b"", b"<999>", b"\xff\xfe\x00", b"<13>" + b"x" * 20000):
            split_syslog(data)
        self.assertEqual(len(split_syslog(b"<13>" + b"x" * 20000, limit=100).msg), 96)


class Formats(unittest.TestCase):
    def flow(self, line, fmt, action, src, dst, dpt, proto="tcp", **extra):
        p = parse(line)
        self.assertIsNotNone(p, line)
        self.assertEqual((p.format, p.source), (fmt, "firewall"), line)
        got = p.payload
        self.assertEqual((got["action"], got["src"], got["dst"], got["dpt"], got["proto"]), (action, src, dst, dpt, proto), line)
        for k, v in extra.items():
            self.assertEqual(got[k], v, (line, k))

    def test_cisco_asa(self):
        self.flow('<164>Oct 22 2026 10:15:01: %ASA-4-106023: Deny tcp src outside:203.0.113.45/51514 dst inside:10.20.0.15/445 '
                  'by access-group "outside_access_in" [0x0, 0x0]', "Cisco ASA", "deny", "203.0.113.45", "10.20.0.15", 445,
                  spt=51514, rule="outside_access_in")
        self.flow("<166>Oct 22 2026 10:15:02 asa-edge : %ASA-6-302013: Built inbound TCP connection 99117 for outside:203.0.113.8/40112 "
                  "(203.0.113.8/40112) to dmz:10.30.0.5/443 (198.51.100.10/443)", "Cisco ASA", "allow", "203.0.113.8", "10.30.0.5", 443)
        # An outbound connection was started by the inside machine.
        self.flow("<166>Oct 22 2026 10:15:02: %ASA-6-302013: Built outbound TCP connection 4211 for outside:93.184.216.34/443 "
                  "(93.184.216.34/443) to inside:10.10.1.21/52344 (198.51.100.10/52344)", "Cisco ASA", "allow", "10.10.1.21", "93.184.216.34", 443)
        self.flow("<166>Oct 22 2026 10:15:02: %ASA-6-106100: access-list inside_in permitted tcp inside/10.10.1.21(52344) -> "
                  "outside/93.184.216.34(443) hit-cnt 1 first hit [0x6a1b2c3d, 0x0]", "Cisco ASA", "allow", "10.10.1.21", "93.184.216.34", 443)
        self.flow("<162>Oct 22 2026 10:15:02: %ASA-2-106001: Inbound TCP connection denied from 203.0.113.45/51514 to 10.20.0.15/3389 "
                  "flags SYN  on interface outside", "Cisco ASA", "deny", "203.0.113.45", "10.20.0.15", 3389)
        teardown = parse("<166>Oct 22 2026 10:15:40: %ASA-6-302014: Teardown TCP connection 4211 for outside:93.184.216.34/443 to "
                         "inside:10.10.1.21/52344 duration 0:00:38 bytes 18000 TCP FINs")
        self.assertEqual((teardown.format, teardown.source), ("Cisco ASA", None))

    def test_fortigate(self):
        base = ('<189>date=2026-10-22 time=10:15:03 devname="FGT-HQ" devid="FG100F0000000001" eventtime=1792674903000000000 '
                'tz="+0100" logid="0000000013" type="traffic" subtype="forward" level="notice" vd="root" srcip=10.10.1.21 '
                'srcport=52344 srcintf="port1" srcintfrole="lan" dstip=93.184.216.34 dstport=443 dstintf="wan1" dstintfrole="wan" '
                'proto=6 action="{action}" policyid=3 policytype="policy" service="HTTPS" duration=30 sentbyte=5120 rcvdbyte=18000')
        self.flow(base.format(action="close"), "Fortinet FortiGate", "allow", "10.10.1.21", "93.184.216.34", 443, sent=5120, rcvd=18000, fw="FGT-HQ")
        self.flow(base.format(action="deny"), "Fortinet FortiGate", "deny", "10.10.1.21", "93.184.216.34", 443)
        vpn = parse('<185>date=2026-10-22 time=10:16:00 devname="FGT-HQ" devid="FG100F0000000001" logid="0101039426" type="event" '
                    'subtype="vpn" level="alert" vd="root" logdesc="SSL VPN login fail" action="ssl-login-fail" tunneltype="ssl-web" '
                    'remip=198.51.100.77 user="nurse.ade" group="N/A" reason="sslvpn_login_permission_denied" msg="SSL user failed to logged in"')
        self.assertEqual((vpn.source, vpn.payload["event"], vpn.payload["user"], vpn.payload["client_ip"]),
                         ("vpn", "auth_failed", "nurse.ade", "198.51.100.77"))
        other = parse('<189>date=2026-10-22 time=10:16:00 devname="FGT-HQ" devid="FG1" logid="0100032001" type="event" subtype="system" '
                      'level="information" logdesc="Admin login successful" user="admin"')
        self.assertEqual((other.format, other.source), ("Fortinet FortiGate", None))

    def test_pfsense_and_opnsense(self):
        self.flow("<134>1 2026-10-22T10:15:04.123456+01:00 pfsense.hosp.local filterlog 52134 - - 5,,,1000000103,igb1,match,block,in,4,"
                  "0x0,,64,0,0,DF,6,tcp,60,203.0.113.45,10.20.0.15,51514,445,0,S,123456789,,64240,,mss;sackOK;TS;nop;wscale",
                  "pfSense or OPNsense", "deny", "203.0.113.45", "10.20.0.15", 445, spt=51514)
        self.flow("<134>Oct 22 10:15:04 filterlog[52134]: 7,,,1000000105,igb0,match,pass,out,4,0x0,,127,4321,0,none,17,udp,76,"
                  "10.10.1.21,8.8.8.8,53001,53,56", "pfSense or OPNsense", "allow", "10.10.1.21", "8.8.8.8", 53, proto="udp")
        self.flow("<134>Oct 22 10:15:04 filterlog[52134]: 9,,,1000000107,igb1,match,block,in,6,0x00,0x00000,64,tcp,6,40,"
                  "2001:db8::45,2001:db8:1::15,51514,22,0,S", "pfSense or OPNsense", "deny", "2001:db8::45", "2001:db8:1::15", 22)
        icmp = parse("<134>Oct 22 10:15:04 filterlog[52134]: 9,,,1000000107,igb1,match,block,in,4,0x0,,64,0,0,none,1,icmp,84,"
                     "203.0.113.45,10.20.0.15,request,1234,1")
        self.assertEqual((icmp.payload["proto"], icmp.payload["dpt"]), ("icmp", None))

    def test_linux_netfilter_family(self):
        self.flow("<4>Oct 22 10:15:05 OpenWrt kernel: [12345.678901] drop wan in: IN=wan OUT= MAC=aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:08:00 "
                  "SRC=203.0.113.45 DST=192.168.1.1 LEN=60 TOS=0x00 PREC=0x00 TTL=50 ID=54321 DF PROTO=TCP SPT=51514 DPT=22 "
                  "WINDOW=64240 RES=0x00 SYN URGP=0", "Linux netfilter (OpenWrt and similar)", "deny", "203.0.113.45", "192.168.1.1", 22)
        self.flow("<4>Oct 22 10:15:06 srv01 kernel: [ 1234.5678] [UFW BLOCK] IN=eth0 OUT= MAC=00:11:22:33:44:55 SRC=10.10.1.50 "
                  "DST=10.20.0.15 LEN=40 TOS=0x00 PREC=0x00 TTL=64 ID=1 PROTO=TCP SPT=40000 DPT=3389 WINDOW=1024 RES=0x00 SYN URGP=0",
                  "UFW", "deny", "10.10.1.50", "10.20.0.15", 3389)
        self.flow("<4>Oct 22 10:15:07 ubnt kernel: [WAN_LOCAL-default-D]IN=eth0 OUT= MAC=00:11:22:33:44:55 SRC=203.0.113.9 "
                  "DST=198.51.100.10 LEN=40 TOS=0x00 PREC=0x00 TTL=242 ID=54321 PROTO=TCP SPT=48000 DPT=23 WINDOW=1024 RES=0x00 SYN URGP=0",
                  "Ubiquiti", "deny", "203.0.113.9", "198.51.100.10", 23)
        icmp = parse("<4>Oct 22 10:15:07 OpenWrt kernel: [1.0] accept lan forward: IN=br-lan OUT=wan SRC=192.168.1.20 DST=1.1.1.1 "
                     "LEN=84 TOS=0x00 PREC=0x00 TTL=63 ID=1 DF PROTO=ICMP TYPE=8 CODE=0 ID=1 SEQ=1")
        self.assertEqual((icmp.payload["action"], icmp.payload["proto"], icmp.payload["dpt"]), ("allow", "icmp", None))

    def test_mikrotik(self):
        self.flow("<134>Oct 22 10:15:08 MikroTik firewall,info DROP-IN input: in:ether1 out:(unknown 0), connection-state:new "
                  "src-mac 00:11:22:33:44:55, proto TCP (SYN), 203.0.113.45:51514->198.51.100.10:8291, len 60",
                  "MikroTik", "deny", "203.0.113.45", "198.51.100.10", 8291, spt=51514)
        self.flow("<134>firewall,info forward: in:bridge out:ether1, connection-state:new src-mac 00:11:22:33:44:66, "
                  "proto UDP, 192.168.88.20:53001->8.8.8.8:53, NAT (192.168.88.20:53001->198.51.100.10:53001)->8.8.8.8:53, len 60",
                  "MikroTik", "unknown", "192.168.88.20", "8.8.8.8", 53, proto="udp")
        icmp = parse("<134>firewall,info forward: in:bridge out:ether1, proto ICMP (type 8, code 0), 192.168.88.20->10.20.0.15, len 84")
        self.assertEqual((icmp.payload["src"], icmp.payload["dst"], icmp.payload["dpt"]), ("192.168.88.20", "10.20.0.15", None))

    def test_sophos_key_values(self):
        self.flow('<30>device_name="SFW" timestamp="2026-10-22T10:15:09+0100" device_model="XGS2100" device_serial_id="X1" '
                  'log_id="010101600001" log_type="Firewall" log_component="Firewall Rule" log_subtype="Denied" log_version=1 '
                  'severity="Information" fw_rule_id="5" fw_rule_name="Block guest" src_ip="10.40.0.20" dst_ip="10.20.0.15" '
                  'protocol="TCP" src_port=50000 dst_port=445 sent_bytes=0 recv_bytes=0 status="Deny"',
                  "Sophos", "deny", "10.40.0.20", "10.20.0.15", 445, rule="5")

    def test_linux_servers(self):
        ssh = parse("<38>Oct 22 10:15:10 web01 sshd[2211]: Failed password for invalid user admin from 203.0.113.45 port 51514 ssh2")
        self.assertEqual((ssh.source, ssh.payload["program"], ssh.payload["host"]), ("linux", "sshd", "web01"))
        bear = parse("<38>Oct 22 10:15:11 OpenWrt dropbear[1500]: Bad password attempt for 'root' from 203.0.113.45:51514")
        self.assertEqual((bear.source, bear.payload["msg"]), ("linux", "Failed password for root from 203.0.113.45 port 51514 ssh2"))
        sudo = parse("<85>Oct 22 10:15:12 web01 sudo:    alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/systemctl stop backup")
        self.assertEqual((sudo.source, sudo.payload["program"]), ("linux", "sudo"))

    def test_unknown_messages_are_not_guessed(self):
        self.assertIsNone(parse("<14>Oct 22 10:15:13 printer01 toner low on tray 2"))
        self.assertIsNone(parse("<30>Oct 22 10:15:13 web01 systemd[1]: Started Daily apt download activities."))
        self.assertIsNone(parse("not even syslog"))


class Zones(unittest.TestCase):
    def test_zone_for(self):
        inventory = {"10.20.0.15": "server"}
        self.assertEqual(zone_for("10.20.0.15", inventory), "server")
        self.assertEqual(zone_for("10.99.0.1", inventory), "internal")
        self.assertEqual(zone_for("93.184.216.34", inventory), "internet")
        self.assertIsNone(zone_for(None, inventory))


class Framing(unittest.TestCase):
    def test_octet_counting_and_newlines(self):
        a, b = b"<34>1 - h app - - - first", b"<34>Oct 22 10:00:00 h app: second"
        stream = str(len(a)).encode() + b" " + a + b + b"\n" + b"<34>partial"
        got, rest = frames(stream)
        self.assertEqual(got, [a, b])
        self.assertEqual(rest, b"<34>partial")
        # Digits at the start of a newline framed message are not mistaken for a length.
        got, rest = frames(b"12 apples were counted\n")
        self.assertEqual((got, rest), ([b"12 apples were counted"], b""))


DENY = b"<4>Oct 22 10:15:06 srv01 kernel: [UFW BLOCK] IN=eth0 OUT= SRC=203.0.113.45 DST=10.20.0.15 LEN=40 PROTO=TCP SPT=40000 DPT=3389"


class Accepting(unittest.TestCase):
    def receiver(self, **settings):
        r = Receiver(conn=None, client=None)
        r.settings = {"receiver.max_message_bytes": 8192, "receiver.sender_per_minute": 60000, **settings}
        r.zones = {"10.20.0.15": "server"}
        return r

    def test_only_accepted_devices_are_kept(self):
        r = self.receiver()
        r.handle("10.0.0.1", DENY)
        self.assertEqual((len(r.buffer), r.senders["10.0.0.1"].state, r.senders["10.0.0.1"].format), (0, "pending", "UFW"))
        r.senders["10.0.0.1"].state = "accepted"
        r.senders["10.0.0.1"].name = "Edge firewall"
        r.handle("10.0.0.1", DENY)
        address, record = r.buffer[0]
        p = record["payload"]
        self.assertEqual((record["source"], p["fw"], p["src_zone"], p["dst_zone"], p["dpt"]), ("firewall", "Edge firewall", "internet", "server", 3389))
        self.assertTrue(p["id"].startswith("rx-") and p["ts"])
        r.senders["10.0.0.1"].state = "blocked"
        r.handle("10.0.0.1", DENY)
        self.assertEqual((len(r.buffer), r.senders["10.0.0.1"].received), (1, 3))

    def test_unread_messages_are_counted_with_a_sample(self):
        r = self.receiver()
        r.handle("10.0.0.9", b"<14>Oct 22 10:15:13 printer01 toner low on tray 2")
        s = r.senders["10.0.0.9"]
        self.assertEqual((s.not_understood, s.last_unparsed), (1, "toner low on tray 2"))

    def test_a_flood_from_one_device_is_capped(self):
        r = self.receiver(**{"receiver.sender_per_minute": 3})
        r.senders["10.0.0.1"] = Sender("10.0.0.1", state="accepted")
        for _ in range(10):
            r.handle("10.0.0.1", DENY)
        self.assertEqual((len(r.buffer), r.senders["10.0.0.1"].dropped), (3, 7))


if __name__ == "__main__":
    unittest.main()
