"""Tests for the dataset loader and the webhook connector. No database, and no network beyond this machine."""

import hashlib
import hmac
import json
import random
import tempfile
import threading
import unittest
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

from connectors import webhook_connector
from simulator import dataset, scenarios
from simulator.generators import Generators
from simulator.hospital import build_hospital, load_config

# Column names as published on the dataset's page.
HEADER = ("Header-Length,Protocol Type,Duration,Rate,Srate,fin_flag_number,syn_flag_number,rst_flag_number,psh_flag_number,ack_flag_number,"
          "ece_flag_number,cwr_flag_number,ack_count,syn_count,fin_count,rst_count,HTTP,HTTPS,DNS,Telnet,SMTP,SSH,IRC,TCP,UDP,DHCP,ARP,ICMP,IGMP,IPv,LLC,"
          "Tot sum,Min,Max,AVG,Std,Tot size,IAT,Number,Magnitue,Radius,Covariance,Variance,Weight")


def row(rate, number=9.5, tot=525, syn=0.0, rst=0.0, tcp=0, udp=0, icmp=0):
    values = dict.fromkeys(HEADER.split(","), 0)
    values.update({"Rate": rate, "Srate": rate, "Number": number, "Tot sum": tot, "syn_count": syn, "rst_count": rst, "TCP": tcp, "UDP": udp, "ICMP": icmp})
    return ",".join(str(values[c]) for c in HEADER.split(","))


class DatasetTest(unittest.TestCase):
    def folder(self, tmp):
        root = Path(tmp)
        (root / "train").mkdir()
        (root / "train" / "Benign_train.pcap.csv").write_text("\n".join([HEADER, row(6.4, tcp=1), row(133.1, udp=1)]), encoding="utf-8")
        (root / "train" / "Recon-Port_Scan_train.pcap.csv").write_text("\n".join([HEADER] + [row(40.0, number=4, tot=240, syn=2.0, tcp=1)] * 3 + [HEADER, ""]), encoding="utf-8")
        (root / "train" / "TCP_IP-DDoS-UDP1_train.pcap.csv").write_text("\n".join([HEADER, row(19759.2, udp=1), row(40008.5, udp=1)]), encoding="utf-8")
        (root / "train" / "MQTT-DoS-Connect_Flood_train.pcap.csv").write_text("\n".join([HEADER, row(15744.5, syn=1.5, tcp=1)]), encoding="utf-8")
        (root / "notes.csv").write_text("a,b\n1,2\n", encoding="utf-8")
        return root

    def test_class_comes_from_the_file_name(self):
        cases = {"Benign_test.pcap.csv": "benign", "Recon-OS_Scan_train.pcap.csv": "recon", "Recon-Ping_Sweep_train.pcap.csv": "recon",
                 "ARP_Spoofing_train.pcap.csv": "spoofing", "MQTT-DDoS-Publish_Flood_train.pcap.csv": "mqtt", "TCP_IP-DDoS-SYN1_train.pcap.csv": "ddos",
                 "TCP_IP-DoS-ICMP2_train.pcap.csv": "dos", "readme.csv": None}
        for name, expected in cases.items():
            self.assertEqual(dataset.classify(name), expected, name)

    def test_loads_rows_by_class_and_skips_other_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            data = dataset.load(self.folder(tmp))
            self.assertEqual({k: len(v) for k, v in data.items()}, {"benign": 2, "recon": 3, "ddos": 2, "mqtt": 1})
            flood = data["ddos"][0]
            self.assertEqual((flood.rate_pps, flood.packets, flood.bytes, flood.protocol), (19759.2, 10, 525, "udp"))
            self.assertEqual((data["recon"][0].packets, data["recon"][0].syn), (4, 2))
            self.assertEqual(dataset.summary(data)["ddos"], {"rows": 2, "median_rate_pps": 40008.5, "highest_rate_pps": 40008.5})

    def test_rejects_a_folder_with_nothing_usable(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(ValueError):
                dataset.load(tmp)
            bad = Path(tmp) / "Benign_x.csv"
            bad.write_text("a,b\n1,2\n", encoding="utf-8")
            with self.assertRaises(ValueError):
                dataset.read_file(bad)
        with self.assertRaises(ValueError):
            dataset.load("/no/such/folder")

    def test_device_scenario_takes_its_traffic_from_the_dataset(self):
        hospital = build_hospital(load_config())
        with tempfile.TemporaryDirectory() as tmp:
            data = dataset.load(self.folder(tmp))
        t0 = datetime(2026, 10, 9, 10, tzinfo=timezone.utc)
        plain = scenarios.build("device_compromise", Generators(hospital, random.Random(4), "a"), t0)
        gen = Generators(hospital, random.Random(4), "a")
        gen.device_dataset = data
        shaped = scenarios.build("device_compromise", gen, t0)
        rates = {round(s[2]["rate_pps"] / 1000) for s in shaped.steps if s[3] == "impact"}
        self.assertTrue(rates <= {16, 20, 40}, rates)  # only the three flood rates in the files
        recon = [s[2] for s in shaped.steps if s[3] == "discovery"]
        self.assertTrue(all(r["packets"] == 4 and r["flags"]["syn"] == 2 for r in recon))
        self.assertNotEqual([s[2]["packets"] for s in plain.steps if s[3] == "impact"], [s[2]["packets"] for s in shaped.steps if s[3] == "impact"])
        self.assertEqual(shaped.hosts, plain.hosts)


class Target(BaseHTTPRequestHandler):
    seen: list = []
    status = 200

    def do_POST(self):
        body = self.rfile.read(int(self.headers["content-length"]))
        Target.seen.append((self.path, {k.lower(): v for k, v in self.headers.items()}, body))
        self.send_response(Target.status)
        self.end_headers()

    def log_message(self, *args):
        pass


class FakeApi:
    def __init__(self, actions):
        self.actions, self.acks = actions, []

    def request(self, method, path, payload=None):
        if method == "GET":
            return {"actions": [a for a in self.actions if a["id"] not in {x[0] for x in self.acks}]}
        self.acks.append((path.split("/")[-2], payload))
        return {"ok": True}


class ConnectorTest(unittest.TestCase):
    ACTION = {"id": "7", "action": "isolate", "asset_id": "WSED001", "asset_ip": "10.20.1.11", "asset_kind": "workstation",
              "incident_id": "3", "requested_by_name": "Lead Analyst", "requested_at": "2026-10-09T10:00:00Z"}

    def setUp(self):
        Target.seen, Target.status = [], 200
        self.server = HTTPServer(("127.0.0.1", 0), Target)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.url = f"http://127.0.0.1:{self.server.server_port}/hooks/isolate"

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()

    def test_delivers_signed_request_and_acknowledges(self):
        api = FakeApi([self.ACTION])
        connector = webhook_connector.Connector(api, self.url, key="k" * 32, auth="Bearer abc")
        self.assertEqual(connector.poll_once(), 1)
        path, headers, body = Target.seen[0]
        sent = json.loads(body)
        self.assertEqual((sent["action"], sent["asset"]["id"], sent["asset"]["ip"], sent["approved_by"]), ("isolate", "WSED001", "10.20.1.11", "Lead Analyst"))
        self.assertEqual(headers["authorization"], "Bearer abc")
        canonical = ":".join(["v1", headers["x-htm-timestamp"], "POST", "/hooks/isolate", hashlib.sha256(body).hexdigest()])
        self.assertEqual(headers["x-htm-signature"], hmac.new(b"k" * 32, canonical.encode(), hashlib.sha256).hexdigest())
        self.assertEqual(api.acks, [("7", {"status": "acknowledged", "note": "target accepted, http 200"})])
        self.assertEqual(connector.poll_once(), 0)

    def test_a_refusing_target_is_retried_then_reported_as_failed(self):
        Target.status = 503
        api = FakeApi([self.ACTION])
        connector = webhook_connector.Connector(api, self.url)
        results = [connector.poll_once() for _ in range(webhook_connector.MAX_ATTEMPTS)]
        self.assertEqual(results, [0] * (webhook_connector.MAX_ATTEMPTS - 1) + [1])
        self.assertEqual(api.acks, [("7", {"status": "failed", "note": "target refused, http 503"})])

    def test_an_unreachable_target_never_acknowledges_as_done(self):
        api = FakeApi([self.ACTION])
        connector = webhook_connector.Connector(api, "http://127.0.0.1:9/none")
        for _ in range(webhook_connector.MAX_ATTEMPTS):
            connector.poll_once()
        self.assertEqual(api.acks[0][1]["status"], "failed")

    def test_needs_a_target(self):
        with self.assertRaises(ValueError):
            webhook_connector.Connector(FakeApi([]), "")


if __name__ == "__main__":
    unittest.main()
