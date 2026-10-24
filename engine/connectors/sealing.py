"""Unseals a secret sealed by the console (web/lib/crypto.ts): AES 256 GCM with a key derived by HKDF SHA 256."""
from __future__ import annotations

import base64
import os

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


def _key(purpose: str, secret: str) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=f"htm:{purpose}".encode()).derive(secret.encode())


def unseal(sealed: str, purpose: str, secret: str | None = None) -> str:
    secret = secret if secret is not None else os.environ.get("SOURCES_SECRET", "")
    if len(secret) < 32:
        raise RuntimeError("SOURCES_SECRET must be set and at least 32 characters long")
    version, iv, tag, body = sealed.split(".")
    if version != "v1":
        raise ValueError("unknown sealed format")
    data = base64.b64decode(body) + base64.b64decode(tag)
    return AESGCM(_key(purpose, secret)).decrypt(base64.b64decode(iv), data, None).decode("utf-8")
