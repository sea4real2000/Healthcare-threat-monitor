"""The background service unseals database passwords the console sealed."""
import json
import unittest
from pathlib import Path

from connectors.sealing import unseal

VECTOR = json.loads((Path(__file__).resolve().parents[2] / "shared" / "sealed_vector.json").read_text())


class Sealing(unittest.TestCase):
    def test_unseals_the_console_vector(self):
        self.assertEqual(unseal(VECTOR["sealed"], VECTOR["purpose"], VECTOR["secret"]), VECTOR["plain"])

    def test_wrong_key_or_purpose_is_refused(self):
        with self.assertRaises(Exception):
            unseal(VECTOR["sealed"], VECTOR["purpose"], "another_secret_of_enough_length_0123456789")
        with self.assertRaises(Exception):
            unseal(VECTOR["sealed"], "totp", VECTOR["secret"])

    def test_short_secret_is_refused(self):
        with self.assertRaises(RuntimeError):
            unseal(VECTOR["sealed"], VECTOR["purpose"], "short")


if __name__ == "__main__":
    unittest.main()


class PlainMessages(unittest.TestCase):
    def test_changed_secrets_get_a_plain_sentence(self):
        from connectors.records_db import plain_message
        try:
            unseal(VECTOR["sealed"], VECTOR["purpose"], "another_secret_of_enough_length_0123456789")
        except Exception as err:  # the real error the worker sees
            self.assertIn("Enter the password for this connection again", plain_message(err))
        else:
            self.fail("expected the wrong key to be refused")

    def test_slow_query_is_not_reported_as_unreachable(self):
        from connectors.records_db import plain_message
        msg = plain_message(Exception("canceling statement due to statement timeout"))
        self.assertIn("took too long", msg)
        self.assertIn("Could not reach", plain_message(Exception("connection timed out")))
