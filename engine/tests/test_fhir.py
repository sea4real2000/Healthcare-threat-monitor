"""The FHIR connection reads AuditEvents page by page and signs in the way SMART Backend Services asks."""

import base64
import io
import json
import time
import unittest
import urllib.error
import urllib.parse

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from connectors.records_fhir import FhirClient, FhirError, for_platform, signed_assertion, summary

BASE = "https://ehr.example/fhir"


def b64d(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


class Response(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def event(i: int, when: str) -> dict:
    return {"resourceType": "AuditEvent", "id": f"e{i}", "recorded": when, "action": "R", "outcome": "0",
            "agent": [{"who": {"display": "app"}}, {"who": {"identifier": {"value": f"user{i}"}}, "requestor": True}],
            "entity": [{"what": {"reference": f"{BASE}/Patient/P{i}/_history/1"}}]}


class FakeServer:
    """Answers like a FHIR server that does not sort, in pages of two."""

    def __init__(self, events, next_url=None):
        self.events, self.requests, self.next_url = events, [], next_url

    def __call__(self, req, timeout):
        self.requests.append(req.full_url)
        url = urllib.parse.urlsplit(req.full_url)
        q = urllib.parse.parse_qs(url.query)
        if url.path.endswith("/metadata"):
            return Response(json.dumps({"resourceType": "CapabilityStatement", "rest": [{"resource": [{"type": "Patient"}]}]}).encode())
        offset = int(q.get("_offset", ["0"])[0])
        page = self.events[offset:offset + 2]
        links = []
        if offset + 2 < len(self.events):
            links.append({"relation": "next", "url": self.next_url or f"{BASE}/AuditEvent?_offset={offset + 2}"})
        return Response(json.dumps({"resourceType": "Bundle", "entry": [{"resource": e} for e in reversed(page)], "link": links}).encode())


def client(opener, **over) -> FhirClient:
    src = {"base_url": BASE, "auth_kind": "none", "encrypt": True, "password_sealed": None, **over}
    return FhirClient(src, opener=opener)


class Paging(unittest.TestCase):
    def test_reads_every_page_then_moves_to_the_newest_time(self):
        server = FakeServer([event(1, "2026-10-22T10:00:00Z"), event(2, "2026-10-22T10:05:00Z"), event(3, "2026-10-22T10:03:00Z")])
        items = list(client(server).read({"since": "2026-10-22T09:00:00Z"}, 2, 10))
        pages, checkpoint = items[:-1], items[-1]
        self.assertEqual(sum(len(p) for p in pages), 3)
        self.assertEqual(checkpoint, {"since": "2026-10-22T10:05:00Z", "next": None, "newest": None})
        # Asks a minute before the last position, so a record written late is not missed. Repeats are dropped on storing.
        self.assertIn("date=ge2026-10-22T08%3A59%3A00Z", server.requests[0])

    def test_more_pages_than_one_poll_reads_carry_on_next_time(self):
        server = FakeServer([event(i, f"2026-10-22T10:0{i}:00Z") for i in range(5)])
        first = list(client(server).read({"since": "2026-10-22T09:00:00Z"}, 2, 1))
        self.assertEqual(first[-1]["next"], f"{BASE}/AuditEvent?_offset=2")
        self.assertEqual(first[-1]["since"], "2026-10-22T09:00:00Z")
        rest = list(client(server).read(first[-1], 2, 10))
        self.assertEqual(rest[-1]["since"], "2026-10-22T10:04:00Z")

    def test_a_next_link_to_another_server_is_refused(self):
        server = FakeServer([event(i, "2026-10-22T10:00:00Z") for i in range(4)], next_url="https://attacker.example/steal")
        with self.assertRaises(FhirError) as caught:
            list(client(server).read({"since": "2026-10-22T09:00:00Z"}, 2, 10))
        self.assertIn("another server", str(caught.exception))
        self.assertFalse(any("attacker" in r for r in server.requests))

    def test_a_server_without_audit_events_is_explained(self):
        with self.assertRaises(FhirError) as caught:
            client(FakeServer([])).check()
        self.assertIn("does not offer AuditEvent", str(caught.exception))

    def test_plain_http_needs_encryption_switched_off(self):
        with self.assertRaises(FhirError):
            FhirClient({"base_url": "http://ehr.example/fhir", "auth_kind": "none", "encrypt": True, "password_sealed": None})
        FhirClient({"base_url": "http://ehr.example/fhir", "auth_kind": "none", "encrypt": False, "password_sealed": None})


class SigningIn(unittest.TestCase):
    def test_the_signed_assertion_verifies_with_the_public_key(self):
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()).decode()
        jwt = signed_assertion(pem, "client-1", "https://ehr.example/token", "kid-1", now=time.time())
        head, body, sig = jwt.split(".")
        key.public_key().verify(b64d(sig), f"{head}.{body}".encode(), padding.PKCS1v15(), hashes.SHA384())
        header, claims = json.loads(b64d(head)), json.loads(b64d(body))
        self.assertEqual((header["alg"], header["kid"]), ("RS384", "kid-1"))
        self.assertEqual((claims["iss"], claims["sub"], claims["aud"]), ("client-1", "client-1", "https://ehr.example/token"))
        self.assertLessEqual(claims["exp"] - time.time(), 300)

    def test_a_refused_sign_in_says_what_to_check(self):
        def refuse(req, timeout):
            raise urllib.error.HTTPError(req.full_url, 401, "no", {}, io.BytesIO(b'{"error":"invalid_client"}'))
        c = FhirClient({"base_url": BASE, "auth_kind": "token", "encrypt": True, "password_sealed": None}, opener=refuse)
        c.credential = "abc"
        with self.assertRaises(FhirError) as caught:
            c.get(f"{BASE}/metadata")
        self.assertIn("refused access", str(caught.exception))


class Shaping(unittest.TestCase):
    def test_summary_and_ids(self):
        ev = event(7, "2026-10-22T10:00:00Z")
        self.assertEqual(summary(ev), {"time": "2026-10-22T10:00:00Z", "user": "user7", "patient": "P7", "action": "R", "outcome": "0"})
        out = for_platform(dict(ev, meta={"versionId": "3"}, text={"div": "x"}), 12)
        self.assertEqual(out["id"], "fhir12-e7")
        self.assertNotIn("meta", out)
        self.assertNotIn("text", out)


if __name__ == "__main__":
    unittest.main()
