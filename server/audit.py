# OpenDLP Central Server - tamper-evident event log - GPL-3.0-only
"""Every stored event carries `chain = HMAC(key, previous_chain || canonical(event))`.

Deleting, editing or re-ordering any row breaks every link after it, and `verify()` reports the first bad row.
The key comes from OPENDLP_AUDIT_KEY and is never stored in the database, so somebody who only has the database
file cannot rebuild a valid chain after editing it. Without a key a plain SHA-256 chain is used (still detects
accidental damage and casual edits, but not a determined attacker with database access).

Retention purges are recorded as an anchor (the chain value of the last purged row), so verification keeps working
after old events are deleted on purpose.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import sqlite3
from typing import Any, Iterable, Sequence

GENESIS = "0" * 64
EVENT_COLUMNS = ("agent_id", "ts", "level", "event_type", "message", "host", "received_at")


def canonical(row: Sequence[Any]) -> bytes:
    return json.dumps([("" if v is None else str(v)) for v in row], ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def link(key: bytes, prev: str, row: Sequence[Any]) -> str:
    data = prev.encode("ascii") + b"|" + canonical(row)
    if key:
        return hmac.new(key, data, hashlib.sha256).hexdigest()
    return hashlib.sha256(data).hexdigest()


def _meta(conn: sqlite3.Connection, key: str) -> str | None:
    r = conn.execute("SELECT value FROM meta WHERE key = ?", (key,)).fetchone()
    return None if r is None else r[0]


def _set_meta(conn: sqlite3.Connection, key: str, value: str) -> None:
    conn.execute("INSERT INTO meta(key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value", (key, value))


def ensure_schema(conn: sqlite3.Connection) -> None:
    cols = {r[1] for r in conn.execute("PRAGMA table_info(events)")}
    if "chain" not in cols:
        conn.execute("ALTER TABLE events ADD COLUMN chain TEXT")


def head(conn: sqlite3.Connection) -> str:
    return _meta(conn, "audit_head") or GENESIS


def append(conn: sqlite3.Connection, key: bytes, rows: Iterable[Sequence[Any]]) -> list[tuple[int, str]]:
    """Insert events (tuples in EVENT_COLUMNS order) and extend the chain. Caller holds the DB lock and commits."""
    prev = head(conn)
    ids: list[tuple[int, str]] = []
    for row in rows:
        prev = link(key, prev, row)
        cur = conn.execute(
            "INSERT INTO events(agent_id, ts, level, event_type, message, host, received_at, chain) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (*row, prev),
        )
        ids.append((int(cur.lastrowid), prev))
    if ids:
        _set_meta(conn, "audit_head", prev)
        _set_meta(conn, "audit_head_id", str(ids[-1][0]))
        if _meta(conn, "audit_anchor") is None:
            # First chained row: everything before it is legacy (pre-0.14) data and is not covered.
            _set_meta(conn, "audit_anchor", GENESIS)
            _set_meta(conn, "audit_anchor_id", str(ids[0][0] - 1))
    return ids


def purge_before(conn: sqlite3.Connection, cutoff_received_at: str) -> int:
    """Delete old events and move the verification anchor forward. Only removes a contiguous prefix."""
    last = conn.execute(
        "SELECT id, chain FROM events WHERE received_at < ? ORDER BY id DESC LIMIT 1", (cutoff_received_at,)
    ).fetchone()
    if last is None:
        return 0
    cur = conn.execute("DELETE FROM events WHERE id <= ?", (last[0],))
    if last[1] and int(last[0]) > int(_meta(conn, "audit_anchor_id") or -1):
        _set_meta(conn, "audit_anchor", last[1])
        _set_meta(conn, "audit_anchor_id", str(last[0]))
    return cur.rowcount


def verify(conn: sqlite3.Connection, key: bytes) -> dict[str, Any]:
    anchor_id = _meta(conn, "audit_anchor_id")
    if anchor_id is None:
        return {"ok": True, "checked": 0, "note": "no chained events yet"}
    prev = _meta(conn, "audit_anchor") or GENESIS
    expected_id = int(anchor_id)
    checked = 0
    cols = ", ".join(EVENT_COLUMNS)
    for r in conn.execute(f"SELECT id, {cols}, chain FROM events WHERE id > ? ORDER BY id", (int(anchor_id),)):
        rid, row, chain = r[0], tuple(r[1:8]), r[8]
        if rid != expected_id + 1:
            return {"ok": False, "checked": checked, "firstBadId": expected_id + 1, "reason": "event missing"}
        prev = link(key, prev, row)
        if chain is None or not hmac.compare_digest(prev, chain):
            return {"ok": False, "checked": checked, "firstBadId": rid, "reason": "event modified"}
        expected_id = rid
        checked += 1
    head_id = int(_meta(conn, "audit_head_id") or expected_id)
    if head_id != expected_id or not hmac.compare_digest(prev, head(conn)):
        return {"ok": False, "checked": checked, "firstBadId": expected_id + 1, "reason": "newest events missing"}
    return {"ok": True, "checked": checked, "head": prev, "keyed": bool(key)}
