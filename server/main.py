# OpenDLP Central Server - GPL-3.0-only
from __future__ import annotations

import hashlib
import hmac
import csv
import io
import json
import os
import secrets
import sqlite3
import threading
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, Response
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, Field

# Must be set via environment variable; if unset, the API rejects all requests (fail closed).
API_TOKEN = os.environ.get("OPENDLP_TOKEN", "").strip()
DB_PATH = Path(os.environ.get("OPENDLP_DB", Path(__file__).parent / "opendlp.db"))
MAX_EVENTS_PER_BATCH = 500
MAX_MESSAGE_LEN = 8000
MAX_BODY_BYTES = int(os.environ.get("OPENDLP_MAX_BODY_BYTES", str(2 * 1024 * 1024)))
MIN_TOKEN_BYTES = 32
VALID_LEVELS = {"DEBUG", "INFO", "WARN", "ALERT", "ERROR"}

# Admin reads (events / agent list) use a separate token so no single endpoint can read all events.
ADMIN_TOKEN = os.environ.get("OPENDLP_ADMIN_TOKEN", "").strip()
# Optional JSON file {"agent-id": "per-agent-token (>=32 bytes)"}; registered agents must use their own token.
AGENT_TOKENS_PATH = os.environ.get("OPENDLP_AGENT_TOKENS", "").strip()
# Dashboard: set a password to enable HTTP Basic; if unset the dashboard is disabled (fail closed).
DASHBOARD_USER = os.environ.get("OPENDLP_DASHBOARD_USER", "admin")
DASHBOARD_PASSWORD = os.environ.get("OPENDLP_DASHBOARD_PASSWORD", "")
DASHBOARD_INSECURE = os.environ.get("OPENDLP_DASHBOARD_INSECURE", "") == "1"
# Event retention in days; 0 = never purge.
EVENT_RETENTION_DAYS = int(os.environ.get("OPENDLP_RETENTION_DAYS", "90"))
# An agent that has not polled the server for this long is shown as "offline".
OFFLINE_AFTER_SECONDS = int(os.environ.get("OPENDLP_OFFLINE_AFTER_SECONDS", "300"))

@asynccontextmanager
async def lifespan(_app: FastAPI):
    purge_old_events()
    yield


app = FastAPI(title="OpenDLP Central Server", version="0.8.0", lifespan=lifespan)
_basic = HTTPBasic(auto_error=False)


@app.middleware("http")
async def limit_body_size(request: Request, call_next):
    cl = request.headers.get("content-length")
    if cl and cl.isdigit() and int(cl) > MAX_BODY_BYTES:
        return JSONResponse(status_code=413, content={"detail": "Request body too large"})
    return await call_next(request)
templates = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))
_db_lock = threading.Lock()


def db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    with _db_lock:
        conn = db()
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                agent_id TEXT NOT NULL,
                ts TEXT NOT NULL,
                level TEXT,
                event_type TEXT,
                message TEXT,
                host TEXT,
                received_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_events_agent_ts ON events(agent_id, ts);
            CREATE INDEX IF NOT EXISTS idx_events_type ON events(event_type);

            CREATE TABLE IF NOT EXISTS agents (
                agent_id TEXT PRIMARY KEY,
                last_seen TEXT NOT NULL,
                last_event TEXT
            );
            """
        )
        conn.commit()
        conn.close()


init_db()


class TelemetryPayload(BaseModel):
    agentId: str = Field(min_length=1, max_length=128)
    sentAt: str | None = None
    events: list[dict[str, Any]] = Field(default_factory=list, max_length=MAX_EVENTS_PER_BATCH)


def _load_agent_tokens() -> dict[str, str]:
    if not AGENT_TOKENS_PATH:
        return {}
    try:
        data = json.loads(Path(AGENT_TOKENS_PATH).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        raise HTTPException(status_code=503, detail="Agent token registry is unreadable")
    if not isinstance(data, dict):
        raise HTTPException(status_code=503, detail="Agent token registry is invalid")
    return {str(k): str(v) for k, v in data.items()}


def _bearer(authorization: str | None) -> str:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing bearer token")
    return authorization.removeprefix("Bearer ").strip()


def _token_ok(candidate: str, expected: str) -> bool:
    return secrets.compare_digest(candidate.encode(), expected.encode())


def token_for_agent(agent_id: str) -> str:
    """The secret this agent authenticates with and signs policy with."""
    per_agent = _load_agent_tokens().get(agent_id)
    if per_agent is not None:
        if len(per_agent.encode("utf-8")) < MIN_TOKEN_BYTES:
            raise HTTPException(status_code=503, detail="Per-agent token is too short")
        return per_agent
    if not API_TOKEN:
        raise HTTPException(status_code=503, detail="Server is not configured: set OPENDLP_TOKEN")
    if len(API_TOKEN.encode("utf-8")) < MIN_TOKEN_BYTES:
        raise HTTPException(status_code=503, detail="OPENDLP_TOKEN must be at least 32 bytes")
    return API_TOKEN


def auth(
    authorization: str | None = Header(default=None),
    x_agent_id: str | None = Header(default=None),
) -> str:
    """Agent authentication: returns the verified agent id."""
    if not API_TOKEN and not AGENT_TOKENS_PATH:
        raise HTTPException(status_code=503, detail="Server is not configured: set OPENDLP_TOKEN")
    token = _bearer(authorization)
    if not x_agent_id or not x_agent_id.strip() or len(x_agent_id) > 128:
        raise HTTPException(status_code=400, detail="Missing or invalid X-Agent-Id header")
    agent_id = x_agent_id.strip()
    if not _token_ok(token, token_for_agent(agent_id)):
        raise HTTPException(status_code=403, detail="Invalid token")
    return agent_id


def admin_auth(authorization: str | None = Header(default=None)) -> None:
    """Administrative read access (agent list / events). Separate secret from agents."""
    if not ADMIN_TOKEN or len(ADMIN_TOKEN.encode("utf-8")) < MIN_TOKEN_BYTES:
        raise HTTPException(status_code=503, detail="Server is not configured: set OPENDLP_ADMIN_TOKEN (>=32 bytes)")
    if not _token_ok(_bearer(authorization), ADMIN_TOKEN):
        raise HTTPException(status_code=403, detail="Invalid token")


def dashboard_auth(credentials: HTTPBasicCredentials | None = Depends(_basic)) -> None:
    if DASHBOARD_PASSWORD:
        ok = credentials is not None and _token_ok(credentials.username, DASHBOARD_USER) and _token_ok(
            credentials.password, DASHBOARD_PASSWORD
        )
        if not ok:
            raise HTTPException(status_code=401, detail="Authentication required", headers={"WWW-Authenticate": "Basic"})
        return
    if not DASHBOARD_INSECURE:
        raise HTTPException(
            status_code=404,
            detail="Dashboard disabled: set OPENDLP_DASHBOARD_PASSWORD (or OPENDLP_DASHBOARD_INSECURE=1 for local dev only)",
        )


def _clean_ts(raw: Any, fallback: str) -> str:
    try:
        parsed = datetime.fromisoformat(str(raw).replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return fallback
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc).isoformat()


def purge_old_events() -> int:
    if EVENT_RETENTION_DAYS <= 0:
        return 0
    cutoff = (datetime.now(timezone.utc) - timedelta(days=EVENT_RETENTION_DAYS)).isoformat()
    with _db_lock:
        conn = db()
        try:
            cur = conn.execute("DELETE FROM events WHERE received_at < ?", (cutoff,))
            conn.commit()
            return cur.rowcount
        finally:
            conn.close()


@app.post("/api/v1/telemetry")
def ingest(payload: TelemetryPayload, _agent: str = Depends(auth)) -> dict[str, Any]:
    if not secrets.compare_digest(payload.agentId.encode(), _agent.encode()):
        raise HTTPException(status_code=403, detail="Agent ID header does not match payload")
    now = datetime.now(timezone.utc).isoformat()
    inserted = 0

    with _db_lock:
        conn = db()
        try:
            for ev in payload.events:
                ts = _clean_ts(ev.get("ts"), now)
                level = str(ev.get("level") or "INFO").upper()[:16]
                if level not in VALID_LEVELS:
                    level = "INFO"
                event_type = str(ev.get("eventType") or "")[:64]
                message = str(ev.get("message") or "")[:MAX_MESSAGE_LEN]
                host = str(ev.get("host") or "")[:128]

                conn.execute(
                    """
                    INSERT INTO events(agent_id, ts, level, event_type, message, host, received_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (payload.agentId, ts, level, event_type, message, host, now),
                )
                inserted += 1

            conn.execute(
                """
                INSERT INTO agents(agent_id, last_seen, last_event)
                VALUES (?, ?, ?)
                ON CONFLICT(agent_id) DO UPDATE SET
                    last_seen=excluded.last_seen,
                    last_event=excluded.last_event
                """,
                (payload.agentId, now, f"batch={inserted}"),
            )
            conn.commit()
        finally:
            conn.close()

    return {"ok": True, "inserted": inserted}


POLICY_PATH = Path(os.environ.get("OPENDLP_POLICY", Path(__file__).resolve().parent.parent / "policies" / "default-policy.json"))
# Explicit value pins the version; otherwise the policy file mtime is used (monotonic), so edits propagate automatically.
_env_version = os.environ.get("OPENDLP_POLICY_VERSION", "").strip()
POLICY_VERSION: int | None = int(_env_version) if _env_version else None

_SEVERITIES = {"low", "medium", "high", "critical"}
_ACTIONS = {"log", "alert", "block"}
_RULE_TYPES = {"builtin", "keywords", "regex"}


def validate_policy(obj: Any) -> list[str]:
    """Return a list of problems; empty means the policy is acceptable to ship to agents."""
    import re

    errs: list[str] = []
    if not isinstance(obj, dict):
        return ["policy must be a JSON object"]
    rules = obj.get("rules", [])
    if not isinstance(rules, list):
        return ["'rules' must be a list"]
    seen: set[str] = set()
    for i, r in enumerate(rules):
        where = f"rules[{i}]"
        if not isinstance(r, dict):
            errs.append(f"{where} must be an object")
            continue
        rid = r.get("id")
        if not isinstance(rid, str) or not rid:
            errs.append(f"{where}.id is required")
        elif rid in seen:
            errs.append(f"{where}.id '{rid}' is duplicated")
        else:
            seen.add(rid)
        rtype = r.get("type", "builtin")
        if rtype not in _RULE_TYPES:
            errs.append(f"{where}.type must be one of {sorted(_RULE_TYPES)}")
        if r.get("severity", "medium") not in _SEVERITIES:
            errs.append(f"{where}.severity must be one of {sorted(_SEVERITIES)}")
        if r.get("action", "alert") not in _ACTIONS:
            errs.append(f"{where}.action must be one of {sorted(_ACTIONS)}")
        if not isinstance(r.get("minMatches", 1), int) or r.get("minMatches", 1) < 1:
            errs.append(f"{where}.minMatches must be an integer >= 1")
        if rtype == "builtin" and not r.get("detector"):
            errs.append(f"{where}.detector is required for builtin rules")
        if rtype == "keywords" and not (isinstance(r.get("keywords"), list) and r["keywords"]):
            errs.append(f"{where}.keywords must be a non-empty list")
        if rtype == "regex":
            try:
                re.compile(str(r.get("pattern", "")))
            except re.error as exc:
                errs.append(f"{where}.pattern is not a valid regex: {exc}")
            if not r.get("pattern"):
                errs.append(f"{where}.pattern is required for regex rules")
    usb_mode = (obj.get("usb") or {}).get("mode", "audit")
    if usb_mode not in {"audit", "block"}:
        errs.append("usb.mode must be 'audit' or 'block'")
    return errs


def policy_envelope(agent_id: str) -> dict[str, Any]:
    try:
        policy_obj = json.loads(POLICY_PATH.read_text(encoding="utf-8"))
        mtime = int(POLICY_PATH.stat().st_mtime)
    except FileNotFoundError as exc:
        raise HTTPException(status_code=500, detail="Policy file is missing") from exc
    except (json.JSONDecodeError, OSError) as exc:
        raise HTTPException(status_code=500, detail="Policy file is invalid or unreadable") from exc

    problems = validate_policy(policy_obj)
    if problems:
        raise HTTPException(status_code=500, detail="Policy failed validation: " + "; ".join(problems[:5]))

    # The agent verifies HMAC-SHA256 over this exact JSON string. The key derivation
    # mirrors AgentConfig.PolicyVerifyKey(); this is a shared-secret design, not
    # asymmetric signing. Use TLS and protect the token in any real deployment.
    policy_json = json.dumps(policy_obj, ensure_ascii=False, separators=(",", ":"))
    verify_key = hashlib.sha256(token_for_agent(agent_id).encode("utf-8")).hexdigest().encode("utf-8")
    sig = hmac.new(verify_key, policy_json.encode("utf-8"), hashlib.sha256).hexdigest()
    version = POLICY_VERSION if POLICY_VERSION is not None else mtime
    return {"version": version, "policyJson": policy_json, "sig": sig}


@app.get("/api/v1/policy", response_model=None)
def get_policy(version: int = 0, _agent: str = Depends(auth)) -> dict[str, Any] | Response:
    envelope = policy_envelope(_agent)
    if version >= envelope["version"]:
        return Response(status_code=304)
    return envelope


def agent_status(last_seen: str) -> str:
    try:
        seen = datetime.fromisoformat(last_seen)
    except ValueError:
        return "unknown"
    age = (datetime.now(timezone.utc) - seen).total_seconds()
    return "online" if age <= OFFLINE_AFTER_SECONDS else "offline"


def query_agents() -> list[dict[str, Any]]:
    with _db_lock:
        conn = db()
        try:
            rows = conn.execute(
                "SELECT agent_id, last_seen, last_event FROM agents ORDER BY last_seen DESC"
            ).fetchall()
        finally:
            conn.close()
    out = [dict(r) for r in rows]
    for r in out:
        r["status"] = agent_status(r["last_seen"])
    return out


def _like_escape(text: str) -> str:
    return text.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def query_events(
    limit: int = 100,
    agent_id: str | None = None,
    level: str | None = None,
    event_type: str | None = None,
    since: str | None = None,
    q: str | None = None,
) -> list[dict[str, Any]]:
    limit = max(1, min(limit, 5000))
    where: list[str] = []
    params: list[Any] = []
    if agent_id:
        where.append("agent_id = ?")
        params.append(agent_id)
    if level:
        where.append("level = ?")
        params.append(level.upper())
    if event_type:
        where.append("event_type = ?")
        params.append(event_type)
    if since:
        where.append("ts >= ?")
        params.append(_clean_ts(since, "1970-01-01T00:00:00+00:00"))
    if q:
        where.append("(message LIKE ? ESCAPE '\\' OR event_type LIKE ? ESCAPE '\\')")
        pat = f"%{_like_escape(q)}%"
        params += [pat, pat]
    sql = "SELECT id, agent_id, ts, level, event_type, message, host, received_at FROM events"
    if where:
        sql += " WHERE " + " AND ".join(where)
    sql += " ORDER BY id DESC LIMIT ?"
    params.append(limit)
    with _db_lock:
        conn = db()
        try:
            rows = conn.execute(sql, params).fetchall()
        finally:
            conn.close()
    return [dict(r) for r in rows]


@app.get("/api/v1/agents")
def list_agents(_admin: None = Depends(admin_auth)) -> list[dict[str, Any]]:
    return query_agents()


@app.get("/api/v1/events")
def list_events(
    limit: int = 100,
    agent_id: str | None = None,
    level: str | None = None,
    event_type: str | None = None,
    since: str | None = None,
    q: str | None = None,
    _admin: None = Depends(admin_auth),
) -> list[dict[str, Any]]:
    return query_events(min(limit, 500), agent_id, level, event_type, since, q)


def _csv_safe(value: Any) -> str:
    """Neutralise spreadsheet formula injection (cells starting with = + - @)."""
    text = "" if value is None else str(value)
    return "'" + text if text[:1] in ("=", "+", "-", "@", "\t", "\r") else text


@app.get("/api/v1/events.csv", response_class=PlainTextResponse)
def export_events_csv(
    limit: int = 1000,
    agent_id: str | None = None,
    level: str | None = None,
    event_type: str | None = None,
    since: str | None = None,
    q: str | None = None,
    _admin: None = Depends(admin_auth),
) -> Response:
    rows = query_events(limit, agent_id, level, event_type, since, q)
    buf = io.StringIO()
    cols = ["id", "agent_id", "ts", "level", "event_type", "message", "host", "received_at"]
    w = csv.writer(buf)
    w.writerow(cols)
    for r in rows:
        w.writerow([_csv_safe(r[c]) for c in cols])
    return Response(
        content=buf.getvalue(),
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": 'attachment; filename="opendlp-events.csv"'},
    )


@app.get("/api/v1/stats")
def stats(_admin: None = Depends(admin_auth)) -> dict[str, Any]:
    since = (datetime.now(timezone.utc) - timedelta(hours=24)).isoformat()
    with _db_lock:
        conn = db()
        try:
            by_level = {
                r["level"]: r["n"]
                for r in conn.execute(
                    "SELECT level, COUNT(*) AS n FROM events WHERE received_at >= ? GROUP BY level", (since,)
                )
            }
            top_types = [
                dict(r)
                for r in conn.execute(
                    "SELECT event_type, COUNT(*) AS n FROM events WHERE received_at >= ? "
                    "GROUP BY event_type ORDER BY n DESC LIMIT 10",
                    (since,),
                )
            ]
            total = conn.execute("SELECT COUNT(*) AS n FROM events").fetchone()["n"]
        finally:
            conn.close()
    agents = query_agents()
    return {
        "agents_total": len(agents),
        "agents_online": sum(1 for a in agents if a["status"] == "online"),
        "events_total": total,
        "events_24h_by_level": by_level,
        "events_24h_top_types": top_types,
    }


@app.get("/api/v1/admin/policy")
def admin_get_policy(_admin: None = Depends(admin_auth)) -> dict[str, Any]:
    try:
        obj = json.loads(POLICY_PATH.read_text(encoding="utf-8"))
        mtime = int(POLICY_PATH.stat().st_mtime)
    except (OSError, json.JSONDecodeError) as exc:
        raise HTTPException(status_code=500, detail="Policy file is missing or invalid") from exc
    return {"version": POLICY_VERSION if POLICY_VERSION is not None else mtime, "policy": obj}


@app.put("/api/v1/admin/policy")
def admin_put_policy(policy: dict[str, Any], _admin: None = Depends(admin_auth)) -> dict[str, Any]:
    """Validate and atomically replace the policy; the previous file is kept as <name>.bak."""
    problems = validate_policy(policy)
    if problems:
        raise HTTPException(status_code=422, detail=problems[:20])
    prev_mtime = int(POLICY_PATH.stat().st_mtime) if POLICY_PATH.exists() else 0
    tmp = POLICY_PATH.with_suffix(POLICY_PATH.suffix + ".tmp")
    tmp.write_text(json.dumps(policy, ensure_ascii=False, indent=2), encoding="utf-8")
    if POLICY_PATH.exists():
        POLICY_PATH.with_suffix(POLICY_PATH.suffix + ".bak").write_bytes(POLICY_PATH.read_bytes())
    os.replace(tmp, POLICY_PATH)
    # Guarantee a strictly increasing version even for two edits within the same second.
    new_mtime = max(int(datetime.now(timezone.utc).timestamp()), prev_mtime + 1)
    os.utime(POLICY_PATH, (new_mtime, new_mtime))
    return {
        "ok": True,
        "version": POLICY_VERSION if POLICY_VERSION is not None else new_mtime,
        "note": "OPENDLP_POLICY_VERSION is pinned; agents will not update until it is raised"
        if POLICY_VERSION is not None
        else "agents will pick this up on their next poll",
    }


@app.get("/", response_class=HTMLResponse)
def dashboard(
    request: Request,
    level: str = "",
    agent_id: str = "",
    q: str = "",
    _auth: None = Depends(dashboard_auth),
) -> HTMLResponse:
    agents = query_agents()
    events = query_events(100, agent_id or None, level or None, None, None, q or None)
    return templates.TemplateResponse(
        request,
        "dashboard.html",
        {
            "agents": agents,
            "events": events,
            "now": datetime.now(timezone.utc).isoformat(),
            "f_level": level,
            "f_agent": agent_id,
            "f_q": q,
            "online": sum(1 for a in agents if a["status"] == "online"),
        },
    )


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}
