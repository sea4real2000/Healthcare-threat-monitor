"""Read only connections to a hospital's own patient record databases.

An administrator sets a connection up in the console, under Sources. This module does the
database side, step by step, as the console asks:

  discover   sign in and list the tables the account can see
  preview    read the chosen table's columns and five example rows
  activate   check the column matching and start from the chosen point in time

Once active, new rows are read every few seconds, converted to AuditEvents and sent through the
same signed ingest API every other source uses. The database is only ever read: every session is
switched to read only, statements are time limited, and table and column names are taken only from
what the database itself listed.
"""
from __future__ import annotations

import re
import ssl
import time
import uuid
from datetime import date, datetime, timedelta, timezone
from decimal import Decimal

import psycopg
from psycopg import sql as pgsql
from psycopg.types.json import Jsonb

from connectors.records_convert import RowError, to_audit_event
from connectors.sealing import unseal

MAX_TABLES = 500
PREVIEW_ROWS = 5
MAX_BATCHES_PER_CYCLE = 20
STATEMENT_TIMEOUT_MS = 30000


class SourceError(Exception):
    """An error with a message written for the person setting the connection up."""


def plain_message(err: Exception) -> str:
    """Turns a driver error into one sentence an administrator can act on."""
    if isinstance(err, SourceError) or type(err).__name__ == "FhirError":
        return str(err)
    text = str(err)
    low = text.lower()
    code = err.args[0] if getattr(err, "args", None) and isinstance(err.args[0], int) else None
    if type(err).__name__ == "InvalidTag":
        return ("The saved password could not be unlocked, because this installation's secrets have changed since it was saved, "
                "for example after a restore without the secrets backup. Enter the password for this connection again.")
    if "canceling statement due to statement timeout" in low or "max_statement_time" in low or "maximum statement execution time" in low:
        return "The database took too long to answer. An index on the column used to read entries in order would help."
    if code == 1044 or re.search(r"access denied for user .* to database", low):
        return "The account is not allowed to use that database, or the database does not exist. Check the database name."
    if code == 1045 or "password authentication failed" in low or "access denied for user" in low:
        return "The database refused the user name or password."
    if code in (1049,) or re.search(r'database ".*" does not exist|unknown database', low):
        return "That database does not exist on the server. Check the database name."
    if code == 1142 or "permission denied" in low or "command denied" in low:
        return "The account can sign in but is not allowed to read that table. Ask the database owner for read access to it."
    if code == 1146 or re.search(r'relation ".*" does not exist|doesn.t exist', low):
        return "The table no longer exists. Choose the table again."
    if "could not translate host name" in low or "name or service not known" in low or "getaddrinfo" in low or code == 2005:
        return "The database address could not be found. Check the host name."
    if "ssl" in low or "tls" in low:
        return "The encrypted connection could not be set up. Turn encryption off for this connection, or ask the database owner to enable it."
    if code == 2003 or "connection refused" in low or "timeout" in low or "timed out" in low or "could not connect" in low or "can't connect" in low:
        return "Could not reach the database. Check the address and port, and that this server is allowed through any firewall."
    first = text.strip().splitlines()[0] if text.strip() else type(err).__name__
    return f"The database reported a problem: {first[:200]}"


def _display(value) -> str:
    if value is None:
        return ""
    if isinstance(value, (datetime, date)):
        return value.isoformat(sep=" ")
    if isinstance(value, (bytes, bytearray, memoryview)):
        return "(binary)"
    return str(value)[:80]


def _checkpoint_dump(value):
    if value is None:
        return None
    if isinstance(value, bool):
        raise SourceError("The column used to read entries in order must hold numbers or times, not yes or no values.")
    if isinstance(value, int):
        return {"t": "int", "v": value}
    if isinstance(value, Decimal):
        return {"t": "int", "v": int(value)} if value == value.to_integral_value() else {"t": "text", "v": str(value)}
    if isinstance(value, datetime):
        return {"t": "datetime", "v": value.isoformat()}
    if isinstance(value, date):
        return {"t": "date", "v": value.isoformat()}
    return {"t": "text", "v": str(value)}


def _checkpoint_load(cp):
    if not cp:
        return None
    t, v = cp.get("t"), cp.get("v")
    if t == "int":
        return int(v)
    if t == "datetime":
        return datetime.fromisoformat(v)
    if t == "date":
        return date.fromisoformat(v)
    return v


class Connection:
    """One short lived, read only session with a hospital database."""

    def __init__(self, src: dict, secret: str | None = None) -> None:
        self.kind = src["kind"]
        password = unseal(src["password_sealed"], "record_source", secret)
        if self.kind == "postgres":
            self.conn = psycopg.connect(
                host=src["host"], port=src["port"], dbname=src["database_name"], user=src["username"], password=password,
                sslmode="require" if src["encrypt"] else "prefer", connect_timeout=10, autocommit=True,
                options=f"-c default_transaction_read_only=on -c statement_timeout={STATEMENT_TIMEOUT_MS}",
            )
        elif self.kind == "mysql":
            import pymysql

            context = None
            if src["encrypt"]:
                # Encrypts the connection. Like PostgreSQL's "require", it does not check the server's certificate.
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
            self.conn = pymysql.connect(
                host=src["host"], port=src["port"], database=src["database_name"], user=src["username"], password=password,
                connect_timeout=10, read_timeout=60, ssl=context, autocommit=True, charset="utf8mb4",
            )
            with self.conn.cursor() as cur:
                cur.execute("SET SESSION TRANSACTION READ ONLY")
                for limit in (f"SET SESSION max_execution_time = {STATEMENT_TIMEOUT_MS}", f"SET SESSION max_statement_time = {STATEMENT_TIMEOUT_MS / 1000}"):
                    try:
                        cur.execute(limit)  # MySQL knows the first, MariaDB the second.
                    except Exception:
                        pass
        else:
            raise SourceError("That kind of database is not supported.")

    def close(self) -> None:
        try:
            self.conn.close()
        except Exception:
            pass

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    def _rows(self, query, params=()):
        with self.conn.cursor() as cur:
            cur.execute(query, params)
            names = [d[0] for d in cur.description]
            return names, cur.fetchall()

    # Naming

    def _table(self, name: str):
        if self.kind == "postgres":
            schema, _, table = name.partition(".")
            return pgsql.SQL("{}.{}").format(pgsql.Identifier(schema), pgsql.Identifier(table))
        return "`" + name.replace("`", "``") + "`"

    def _col(self, name: str):
        if self.kind == "postgres":
            return pgsql.Identifier(name)
        return "`" + name.replace("`", "``") + "`"

    def _q(self, template: str, **parts):
        """Builds a statement from a template with {name} slots filled by quoted identifiers."""
        if self.kind == "postgres":
            return pgsql.SQL(template).format(**parts)
        return template.format(**parts)

    # Steps

    def tables(self) -> list[str]:
        if self.kind == "postgres":
            _, rows = self._rows(
                """select table_schema || '.' || table_name from information_schema.tables
                   where table_schema not in ('pg_catalog', 'information_schema') and table_type in ('BASE TABLE', 'VIEW')
                   order by 1 limit %s""", (MAX_TABLES,))
        else:
            _, rows = self._rows(
                """select table_name from information_schema.tables where table_schema = database()
                   and table_type in ('BASE TABLE', 'VIEW') order by 1 limit %s""", (MAX_TABLES,))
        return [r[0] for r in rows]

    def columns(self, table: str) -> list[dict]:
        if self.kind == "postgres":
            schema, _, name = table.partition(".")
            _, rows = self._rows(
                """select column_name, data_type from information_schema.columns
                   where table_schema = %s and table_name = %s order by ordinal_position""", (schema, name))
        else:
            _, rows = self._rows(
                """select column_name, data_type from information_schema.columns
                   where table_schema = database() and table_name = %s order by ordinal_position""", (table,))
        return [{"name": r[0], "type": str(r[1])} for r in rows]

    def preview(self, table: str) -> list[dict]:
        names, rows = self._rows(self._q("select * from {t} limit " + str(PREVIEW_ROWS), t=self._table(table)))
        return [{n: _display(v) for n, v in zip(names, row)} for row in rows]

    def start_point(self, table: str, order: str, time_col: str, backfill_days: int):
        """Where reading begins: the first entry inside the backfill window, or only new entries when there is none.

        Returns (value, inclusive). Entry numbers and times need not run in the same order, so the window
        is found by time and reading starts from the lowest entry number inside it.
        """
        if backfill_days > 0:
            cutoff = datetime.now(timezone.utc) - timedelta(days=backfill_days)
            # Compare with a plain date and time, which works whether the column stores a zone or not.
            _, rows = self._rows(self._q("select min({o}) from {t} where {tc} >= %s", o=self._col(order), t=self._table(table), tc=self._col(time_col)),
                                 (cutoff.replace(tzinfo=None),))
            if rows and rows[0][0] is not None:
                return rows[0][0], True
        _, rows = self._rows(self._q("select max({o}) from {t}", o=self._col(order), t=self._table(table)))
        return (rows[0][0] if rows else None), False

    def read_after(self, table: str, mapping: dict, after, limit: int, inclusive: bool = False) -> list[dict]:
        fields = [f for f in ("time", "user", "patient", "action", "outcome", "workstation") if mapping.get(f)]
        order = mapping["order"]
        cols = [order] + [mapping[f] for f in fields]
        if self.kind == "postgres":
            select = pgsql.SQL(", ").join(pgsql.Identifier(c) for c in cols)
            query = pgsql.SQL("select {s} from {t}").format(s=select, t=self._table(table))
            if after is not None:
                query += pgsql.SQL(" where {o} >= %s" if inclusive else " where {o} > %s").format(o=pgsql.Identifier(order))
            query += pgsql.SQL(" order by {o} limit %s").format(o=pgsql.Identifier(order))
        else:
            select = ", ".join(self._col(c) for c in cols)
            query = f"select {select} from {self._table(table)}"
            if after is not None:
                query += f" where {self._col(order)} {'>=' if inclusive else '>'} %s"
            query += f" order by {self._col(order)} limit %s"
        params = ((after,) if after is not None else ()) + (limit,)
        _, rows = self._rows(query, params)
        out = []
        for row in rows:
            item = {"_order": row[0]}
            for f, v in zip(fields, row[1:]):
                item[f] = v
            out.append(item)
        return out


class RecordSources:
    """Runs the steps the console asks for and keeps active connections flowing."""

    def __init__(self, conn: psycopg.Connection, client, log) -> None:
        self.conn = conn
        self.client = client
        self.log = log
        self.last_poll: dict[int, float] = {}

    def _update(self, source_id: int, **fields) -> None:
        sets = pgsql.SQL(", ").join(pgsql.SQL("{} = %s").format(pgsql.Identifier(k)) for k in fields)
        values = [Jsonb(v) if isinstance(v, (list, dict)) else v for v in fields.values()]
        with self.conn.cursor() as cur:
            cur.execute(pgsql.SQL("update record_sources set {s}, updated_at = now() where id = %s").format(s=sets), values + [source_id])
        self.conn.commit()

    def _fail(self, src: dict, err: Exception, **fields) -> None:
        message = plain_message(err)
        self.log(f"records source {src['id']}: {message}")
        self._update(src["id"], last_error=message, last_error_at=datetime.now(timezone.utc), **fields)

    def run(self, settings: dict) -> None:
        self.settings = settings
        with self.conn.cursor() as cur:
            cur.execute("select * from record_sources where pending is not null or state = 'active' order by id")
            sources = cur.fetchall()
        self.conn.commit()
        for src in sources:
            if src["pending"]:
                self.step(src)
            elif src["state"] == "active":
                every = float(settings.get("sources.poll_seconds", 30))
                if time.time() - self.last_poll.get(src["id"], 0) >= every:
                    self.last_poll[src["id"]] = time.time()
                    self.poll(src, int(settings.get("sources.batch_rows", 500)), int(settings.get("ingest.max_batch_records", 1000)))

    def step(self, src: dict) -> None:
        if src["kind"] == "fhir":
            self.fhir_step(src)
            return
        try:
            with Connection(src) as db:
                if src["pending"] == "discover":
                    tables = db.tables()
                    if not tables:
                        raise SourceError("The account signed in, but it cannot see any tables. Ask the database owner to grant it read access to the access log table.")
                    self._update(src["id"], pending=None, tables=tables, last_error=None, last_ok_at=datetime.now(timezone.utc))
                elif src["pending"] == "preview":
                    if src["table_name"] not in src["tables"]:
                        raise SourceError("Choose a table from the list.")
                    self._update(src["id"], pending=None, columns=db.columns(src["table_name"]), preview=db.preview(src["table_name"]),
                                 last_error=None, last_ok_at=datetime.now(timezone.utc))
                elif src["pending"] == "activate":
                    mapping = src["mapping"]
                    known = {c["name"] for c in src["columns"]}
                    for field in ("order", "time", "user", "patient"):
                        if not mapping.get(field):
                            raise SourceError("Match every required column before starting.")
                    if any(v and v not in known for v in mapping.values()):
                        raise SourceError("A matched column no longer exists. Read the table again and match the columns once more.")
                    start, inclusive = db.start_point(src["table_name"], mapping["order"], mapping["time"], int(src["backfill_days"]))
                    checkpoint = _checkpoint_dump(start)
                    if checkpoint and inclusive:
                        checkpoint["inclusive"] = True
                    self._update(src["id"], pending=None, state="active", checkpoint=checkpoint, preview=[],
                                 last_error=None, last_ok_at=datetime.now(timezone.utc))
                    self.log(f"records source {src['id']} active")
        except Exception as err:  # noqa: BLE001  Every failure is shown to the administrator.
            self._fail(src, err, pending=None)

    # FHIR servers

    def fhir_step(self, src: dict) -> None:
        from connectors.records_fhir import FhirClient

        try:
            client = FhirClient(src)
            if src["pending"] == "discover":
                preview = client.check()
                fields = {"pending": None, "preview": preview, "last_error": None, "last_ok_at": datetime.now(timezone.utc)}
                if client.token_url and client.token_url != src.get("token_url"):
                    fields["token_url"] = client.token_url
                self._update(src["id"], **fields)
            elif src["pending"] == "activate":
                since = datetime.now(timezone.utc) - timedelta(days=int(src["backfill_days"]))
                self._update(src["id"], pending=None, state="active", preview=[], last_error=None, last_ok_at=datetime.now(timezone.utc),
                             checkpoint={"since": since.strftime("%Y-%m-%dT%H:%M:%SZ"), "next": None, "newest": None})
                self.log(f"records source {src['id']} active")
            else:
                self._update(src["id"], pending=None)
        except Exception as err:  # noqa: BLE001  Every failure is shown to the administrator.
            self._fail(src, err, pending=None)

    def fhir_poll(self, src: dict) -> None:
        from connectors.records_fhir import FhirClient, for_platform

        settings = getattr(self, "settings", {})
        total = rejected = 0
        try:
            client = FhirClient(src)
            checkpoint = src["checkpoint"] or {}
            for item in client.read(checkpoint, int(settings.get("fhir.page_size", 100)), int(settings.get("fhir.max_pages", 20))):
                if isinstance(item, dict):
                    # The last item is where to carry on from. It is saved only after every page before it was stored.
                    self._update(src["id"], checkpoint=item)
                    continue
                if item:
                    result = self.client.send_batch(str(uuid.uuid4()), None, [{"source": "ehr", "payload": for_platform(r, src["id"])} for r in item])
                    rejected += int(result.get("rejected", 0))
                    total += len(item)
            with self.conn.cursor() as cur:
                cur.execute("""update record_sources set last_rows = %s, total_rows = total_rows + %s, rejected_rows = rejected_rows + %s,
                               last_ok_at = now(), last_error = null, updated_at = now() where id = %s""", (total, total, rejected, src["id"]))
            self.conn.commit()
        except Exception as err:  # noqa: BLE001
            self.conn.rollback()
            self._fail(src, err)

    def poll(self, src: dict, batch_rows: int, max_batch: int) -> None:
        if src["kind"] == "fhir":
            self.fhir_poll(src)
            return
        after = _checkpoint_load(src["checkpoint"])
        inclusive = bool((src["checkpoint"] or {}).get("inclusive"))
        total = rejected = 0
        try:
            with Connection(src) as db:
                with self.conn.cursor() as cur:
                    cur.execute("select id, host(ip) as ip from assets where ip is not null")
                    asset_ips = {r["id"]: r["ip"] for r in cur}
                self.conn.commit()
                for _ in range(MAX_BATCHES_PER_CYCLE):
                    rows = db.read_after(src["table_name"], src["mapping"], after, min(batch_rows, max_batch), inclusive)
                    if not rows:
                        break
                    records = []
                    last_order = None
                    for row in rows:
                        order = row.pop("_order")
                        last_order = order
                        if isinstance(order, (int, Decimal)) and not isinstance(order, bool):
                            row["record_id"] = str(order)
                        try:
                            records.append(to_audit_event(row, src["timezone"], src["day_first"], src["name"], f"db{src['id']}", asset_ips))
                        except RowError:
                            rejected += 1
                    if records:
                        result = self.client.send_batch(str(uuid.uuid4()), None, records)
                        rejected += int(result.get("rejected", 0))
                    total += len(rows)
                    # Move on only once the platform has accepted the batch. A batch sent again is ignored.
                    after, inclusive = last_order, False
                    self._update(src["id"], checkpoint=_checkpoint_dump(after))
                    if len(rows) < min(batch_rows, max_batch):
                        break
            with self.conn.cursor() as cur:
                cur.execute("""update record_sources set last_rows = %s, total_rows = total_rows + %s, rejected_rows = rejected_rows + %s,
                               last_ok_at = now(), last_error = null, updated_at = now() where id = %s""", (total, total, rejected, src["id"]))
            self.conn.commit()
        except Exception as err:  # noqa: BLE001
            self.conn.rollback()
            self._fail(src, err)
