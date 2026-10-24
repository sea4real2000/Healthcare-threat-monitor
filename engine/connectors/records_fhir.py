"""Reads AuditEvent resources from a patient record system's FHIR server.

FHIR is the standard many record systems offer for exchanging data. Its AuditEvent resource records who
opened which patient record, and when. The platform asks the server for new AuditEvents every poll and
passes them through the signed ingestion path, where the existing reader for patient record access maps them.

Signing in, as the server requires:
  none            for a test server
  token           a fixed access token the vendor issued
  client_secret   OAuth client credentials with a client ID and secret
  private_key     SMART Backend Services: a key pair the console made, whose public half the vendor registers.
                  Each request for an access token is signed with the private half (RS384).

Only the server's own address is ever requested. A "next page" link that points anywhere else is refused.
"""

from __future__ import annotations

import base64
import json
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from datetime import datetime, timedelta, timezone

from connectors.sealing import unseal

USER_AGENT = "healthcare-threat-monitor/0.7"
OVERLAP_SECONDS = 60
MAX_BODY_BYTES = 20 * 1024 * 1024


class FhirError(Exception):
    """A problem worded for the administrator."""


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def signed_assertion(private_pem: str, client_id: str, token_url: str, kid: str | None, now: float | None = None) -> str:
    """The signed request for an access token that SMART Backend Services asks for."""
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding

    key = serialization.load_pem_private_key(private_pem.encode(), password=None)
    issued = int(now if now is not None else time.time())
    header = {"alg": "RS384", "typ": "JWT"}
    if kid:
        header["kid"] = kid
    claims = {"iss": client_id, "sub": client_id, "aud": token_url, "exp": issued + 300, "jti": str(uuid.uuid4())}
    signing_input = f"{_b64url(json.dumps(header, separators=(',', ':')).encode())}.{_b64url(json.dumps(claims, separators=(',', ':')).encode())}"
    signature = key.sign(signing_input.encode("ascii"), padding.PKCS1v15(), hashes.SHA384())
    return f"{signing_input}.{_b64url(signature)}"


def _origin(url: str) -> tuple[str, str, int | None]:
    p = urllib.parse.urlsplit(url)
    return p.scheme, (p.hostname or "").lower(), p.port


def first_text(*values) -> str | None:
    for v in values:
        if isinstance(v, str) and v.strip():
            return v.strip()
    return None


def summary(resource: dict) -> dict:
    """Who, which patient, what and when, for the preview the administrator checks."""
    agents = resource.get("agent") or []
    agent = next((a for a in agents if isinstance(a, dict) and a.get("requestor")), agents[0] if agents else {})
    who = agent.get("who") or {} if isinstance(agent, dict) else {}
    user = first_text((who.get("identifier") or {}).get("value"), agent.get("altId") if isinstance(agent, dict) else None,
                      who.get("display"), who.get("reference"), agent.get("name") if isinstance(agent, dict) else None)
    patient = None
    for entity in resource.get("entity") or []:
        ref = ((entity or {}).get("what") or {}).get("reference") or ""
        if "Patient/" in ref:
            patient = ref.split("Patient/", 1)[1].split("/")[0]
            break
    return {"time": resource.get("recorded"), "user": user, "patient": patient, "action": resource.get("action"),
            "outcome": resource.get("outcome")}


class FhirClient:
    def __init__(self, src: dict, secret: str | None = None, opener=None) -> None:
        base = (src.get("base_url") or "").strip().rstrip("/")
        scheme, host, _ = _origin(base)
        if scheme not in ("https", "http") or not host:
            raise FhirError("The FHIR address must start with https:// and name the server.")
        if scheme == "http" and src.get("encrypt", True):
            raise FhirError("The FHIR address starts with http://, which is not encrypted. Use https://, or turn off encryption for this connection.")
        self.base = base
        self.src = src
        self.auth = src.get("auth_kind") or "none"
        self.credential = unseal(src["password_sealed"], "record_source", secret) if src.get("password_sealed") else None
        self.token: str | None = None
        self.token_expires = 0.0
        self.token_url = src.get("token_url") or None
        context = ssl.create_default_context()
        custom = (src.get("ca_certificate") or "").strip()
        if custom:
            # A hospital's own certificate authority, for a server inside its network.
            context.load_verify_locations(cadata=custom)
        self.context = context
        self.opener = opener

    # Requests

    def _open(self, req: urllib.request.Request, timeout: float = 30):
        if self.opener:
            return self.opener(req, timeout)
        return urllib.request.urlopen(req, timeout=timeout, context=self.context if req.full_url.startswith("https") else None)

    def _same_server(self, url: str) -> bool:
        return _origin(url) == _origin(self.base)

    def _access_token(self) -> str | None:
        if self.auth == "none":
            return None
        if self.auth == "token":
            return self.credential
        if self.token and time.time() < self.token_expires - 60:
            return self.token
        if not self.token_url:
            self.token_url = self.discover_token_url()
        form = {"grant_type": "client_credentials"}
        scope = self.src.get("scope") or "system/AuditEvent.read"
        form["scope"] = scope
        headers = {"Content-Type": "application/x-www-form-urlencoded", "Accept": "application/json", "User-Agent": USER_AGENT}
        client_id = self.src.get("client_id") or ""
        if self.auth == "client_secret":
            basic = base64.b64encode(f"{urllib.parse.quote(client_id)}:{urllib.parse.quote(self.credential or '')}".encode()).decode()
            headers["Authorization"] = f"Basic {basic}"
        elif self.auth == "private_key":
            kid = (self.src.get("public_jwk") or {}).get("kid")
            form["client_assertion_type"] = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
            form["client_assertion"] = signed_assertion(self.credential or "", client_id, self.token_url, kid)
        else:
            raise FhirError("Choose how the platform signs in to the FHIR server.")
        req = urllib.request.Request(self.token_url, data=urllib.parse.urlencode(form).encode(), headers=headers, method="POST")
        try:
            with self._open(req) as resp:
                body = json.loads(resp.read(MAX_BODY_BYTES))
        except urllib.error.HTTPError as err:
            detail = err.read(2000).decode("utf-8", "replace")
            raise FhirError(f"The FHIR server's sign in refused the platform ({err.code}). Check the client ID and that the vendor has "
                            f"registered it with the scope {scope}. The server said: {detail[:200]}") from None
        token = body.get("access_token")
        if not isinstance(token, str) or not token:
            raise FhirError("The FHIR server's sign in answered without an access token.")
        self.token = token
        self.token_expires = time.time() + float(body.get("expires_in") or 300)
        return token

    def get(self, url: str) -> dict:
        if not self._same_server(url):
            raise FhirError("The FHIR server pointed to another server for the next page. The platform only reads from the address you entered.")
        headers = {"Accept": "application/fhir+json, application/json", "User-Agent": USER_AGENT}
        token = self._access_token()
        if token:
            headers["Authorization"] = f"Bearer {token}"
        req = urllib.request.Request(url, headers=headers)
        try:
            with self._open(req) as resp:
                raw = resp.read(MAX_BODY_BYTES + 1)
        except urllib.error.HTTPError as err:
            if err.code in (401, 403):
                raise FhirError(f"The FHIR server refused access ({err.code}). Check the sign in details, and that the account may read AuditEvent.") from None
            if err.code == 404:
                raise FhirError("The FHIR server answered that this address does not exist. Check the FHIR address.") from None
            raise FhirError(f"The FHIR server reported a problem ({err.code}).") from None
        except urllib.error.URLError as err:
            reason = str(getattr(err, "reason", err))
            if "CERTIFICATE_VERIFY_FAILED" in reason:
                raise FhirError("The FHIR server's certificate is not trusted. If it comes from your hospital's own certificate authority, "
                                "paste that authority's certificate into this connection.") from None
            raise FhirError(f"Could not reach the FHIR server: {reason}") from None
        if len(raw) > MAX_BODY_BYTES:
            raise FhirError("The FHIR server sent a page larger than the platform accepts. Lower the page size under Settings, FHIR connections.")
        try:
            return json.loads(raw)
        except ValueError:
            raise FhirError("The FHIR server answered with something that is not FHIR JSON. Check the FHIR address.") from None

    def discover_token_url(self) -> str:
        """Finds where to ask for access tokens, from the server's SMART configuration."""
        try:
            config = self.get_unauthenticated(f"{self.base}/.well-known/smart-configuration")
            url = config.get("token_endpoint")
        except FhirError:
            url = None
        if not isinstance(url, str) or not url.startswith("https://") and not url.startswith("http://"):
            raise FhirError("The FHIR server does not say where to sign in. Enter the token address the vendor gave you.")
        return url

    def get_unauthenticated(self, url: str) -> dict:
        req = urllib.request.Request(url, headers={"Accept": "application/json", "User-Agent": USER_AGENT})
        try:
            with self._open(req, timeout=15) as resp:
                return json.loads(resp.read(MAX_BODY_BYTES))
        except (urllib.error.URLError, ValueError) as err:
            raise FhirError(f"Could not read {url}: {err}") from None

    # What the console's steps ask for

    def check(self) -> list[dict]:
        """Checks the server offers AuditEvent and returns a few recent ones for the preview."""
        meta = self.get(f"{self.base}/metadata")
        if meta.get("resourceType") != "CapabilityStatement":
            raise FhirError("The address answered, but not as a FHIR server. Check the FHIR address.")
        offered = {r.get("type") for rest in meta.get("rest") or [] for r in rest.get("resource") or []}
        if "AuditEvent" not in offered:
            raise FhirError("This FHIR server does not offer AuditEvent, the record of who opened which patient record. Ask the vendor whether it can.")
        since = (datetime.now(timezone.utc) - timedelta(days=7)).strftime("%Y-%m-%dT%H:%M:%SZ")
        query = {"date": f"ge{since}", "_count": 5}
        try:
            # The most recent first, where the server can sort. A server that cannot is asked again without sorting.
            page = self.get(f"{self.base}/AuditEvent?{urllib.parse.urlencode({**query, '_sort': '-date'})}")
        except FhirError as err:
            if "(400)" not in str(err):
                raise
            page = self.get(f"{self.base}/AuditEvent?{urllib.parse.urlencode(query)}")
        return [summary(e["resource"]) for e in page.get("entry") or [] if isinstance(e, dict) and (e.get("resource") or {}).get("resourceType") == "AuditEvent"][:5]

    def read(self, checkpoint: dict, page_size: int, max_pages: int):
        """Yields pages of AuditEvents after the checkpoint, and finally the checkpoint to save.

        A server may not sort, so the position only moves past a time once every page up to it has been read.
        The next page link is kept between polls when there are more pages than one poll reads.
        """
        since = checkpoint.get("since")
        url = checkpoint.get("next")
        newest = checkpoint.get("newest") or since
        if not url:
            start = datetime.fromisoformat(since.replace("Z", "+00:00")) - timedelta(seconds=OVERLAP_SECONDS)
            query = urllib.parse.urlencode({"date": f"ge{start.strftime('%Y-%m-%dT%H:%M:%SZ')}", "_count": page_size})
            url = f"{self.base}/AuditEvent?{query}"
        pages = 0
        while url and pages < max_pages:
            bundle = self.get(url)
            if bundle.get("resourceType") != "Bundle":
                raise FhirError("The FHIR server answered a search with something other than a list of results.")
            events = [e["resource"] for e in bundle.get("entry") or []
                      if isinstance(e, dict) and isinstance(e.get("resource"), dict) and e["resource"].get("resourceType") == "AuditEvent"]
            for ev in events:
                rec = ev.get("recorded")
                if isinstance(rec, str) and (newest is None or _after(rec, newest)):
                    newest = rec
            yield events
            pages += 1
            url = next((link.get("url") for link in bundle.get("link") or [] if link.get("relation") == "next"), None)
        if url:
            yield {"since": since, "next": url, "newest": newest}
        else:
            yield {"since": newest or since, "next": None, "newest": None}


def _after(a: str, b: str) -> bool:
    try:
        return datetime.fromisoformat(a.replace("Z", "+00:00")) > datetime.fromisoformat(b.replace("Z", "+00:00"))
    except ValueError:
        return False


def for_platform(resource: dict, source_id: int) -> dict:
    """An AuditEvent ready for the ingestion path, with an ID that cannot collide with another server's."""
    out = dict(resource)
    out["id"] = f"fhir{source_id}-{resource.get('id') or uuid.uuid5(uuid.NAMESPACE_URL, json.dumps(resource, sort_keys=True))}"
    out.pop("meta", None)
    out.pop("text", None)
    return out
