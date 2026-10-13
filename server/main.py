# OpenDLP Central Server - GPL-3.0-only
from __future__ import annotations

import hashlib
import hmac
import csv
import io
import json
import os
import re
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

import audit
import cloudscan
import report
import siem
import sso

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
# Optional ECDSA P-256 private key (PEM) for asymmetric policy signatures. Generate with tools/gen_signing_key.py.
SIGNING_KEY_PATH = os.environ.get("OPENDLP_SIGNING_KEY", "").strip()
# Self-enrollment: an installer supplies this code once; the server issues that machine its own token.
ENROLL_CODE = os.environ.get("OPENDLP_ENROLL_CODE", "").strip()
# Read-only API token (dashboards, SIEM pull). Admin token can do everything a viewer can.
VIEWER_TOKEN = os.environ.get("OPENDLP_VIEWER_TOKEN", "").strip()
DASHBOARD_VIEWER_USER = os.environ.get("OPENDLP_DASHBOARD_VIEWER_USER", "viewer")
DASHBOARD_VIEWER_PASSWORD = os.environ.get("OPENDLP_DASHBOARD_VIEWER_PASSWORD", "")
# Public URL agents use to reach this server (shown on the deploy page); defaults to the URL the admin browsed to.
PUBLIC_URL = os.environ.get("OPENDLP_PUBLIC_URL", "").strip().rstrip("/")
# GitHub repository whose releases the deploy commands download from.
RELEASE_REPO = os.environ.get("OPENDLP_RELEASE_REPO", "ewjfqwe475328u0rmcjidw/OpenDLP").strip()
# Monthly PDF report: organisation name on the cover, and whether to e-mail it (SMTP settings below) on the 1st.
ORG_NAME = os.environ.get("OPENDLP_ORG_NAME", "Your organization").strip() or "Your organization"
REPORT_EMAIL = os.environ.get("OPENDLP_REPORT_EMAIL", "") == "1"
# Cloud drive scanning (report-only). Google: service-account JSON with domain-wide delegation + an admin to
# impersonate for the user list. Microsoft 365: app registration with User.Read.All + Files.Read.All (application).
GOOGLE_SA_FILE = os.environ.get("OPENDLP_GOOGLE_SA_FILE", "").strip()
GOOGLE_ADMIN = os.environ.get("OPENDLP_GOOGLE_ADMIN_EMAIL", "").strip()
GOOGLE_DOMAIN = os.environ.get("OPENDLP_GOOGLE_DOMAIN", "").strip()
M365_TENANT = os.environ.get("OPENDLP_M365_TENANT_ID", "").strip()
M365_CLIENT_ID = os.environ.get("OPENDLP_M365_CLIENT_ID", "").strip()
M365_SECRET = os.environ.get("OPENDLP_M365_CLIENT_SECRET", "").strip()
CLOUD_SCAN_HOURS = int(os.environ.get("OPENDLP_CLOUD_SCAN_HOURS", "24"))
# Notifications for high/critical alerts: generic JSON webhook (Slack/Discord/Teams/Mattermost/n8n…) and/or SMTP e-mail.
WEBHOOK_URL = os.environ.get("OPENDLP_WEBHOOK_URL", "").strip()
NOTIFY_MIN_SEVERITY = os.environ.get("OPENDLP_NOTIFY_MIN_SEVERITY", "high").lower()
NOTIFY_COOLDOWN_SECONDS = int(os.environ.get("OPENDLP_NOTIFY_COOLDOWN_SECONDS", "300"))
SMTP_HOST = os.environ.get("OPENDLP_SMTP_HOST", "").strip()
SMTP_PORT = int(os.environ.get("OPENDLP_SMTP_PORT", "587"))
SMTP_USER = os.environ.get("OPENDLP_SMTP_USER", "")
SMTP_PASSWORD = os.environ.get("OPENDLP_SMTP_PASSWORD", "")
SMTP_FROM = os.environ.get("OPENDLP_SMTP_FROM", "")
SMTP_TO = [x.strip() for x in os.environ.get("OPENDLP_SMTP_TO", "").split(",") if x.strip()]
SMTP_STARTTLS = os.environ.get("OPENDLP_SMTP_STARTTLS", "1") != "0"
# Tamper-evident event log: HMAC key for the hash chain. Keep it outside the database (env / secrets manager).
AUDIT_KEY = os.environ.get("OPENDLP_AUDIT_KEY", "").strip().encode("utf-8")
# SIEM forwarding: udp://host:514, tcp://host:514 or tls://host:6514; format cef (default) or json.
SYSLOG_URL = os.environ.get("OPENDLP_SYSLOG", "").strip()
SYSLOG_FORMAT = os.environ.get("OPENDLP_SYSLOG_FORMAT", "cef").strip().lower()
# Dashboard single sign-on (OpenID Connect). Admins / viewers: comma-separated addresses or @domain entries.
OIDC_ISSUER = os.environ.get("OPENDLP_OIDC_ISSUER", "").strip()
OIDC_CLIENT_ID = os.environ.get("OPENDLP_OIDC_CLIENT_ID", "").strip()
OIDC_CLIENT_SECRET = os.environ.get("OPENDLP_OIDC_CLIENT_SECRET", "").strip()
OIDC_ADMINS = os.environ.get("OPENDLP_OIDC_ADMINS", "")
OIDC_VIEWERS = os.environ.get("OPENDLP_OIDC_VIEWERS", "")
SESSION_HOURS = int(os.environ.get("OPENDLP_SESSION_HOURS", "8"))
# Signs dashboard session cookies. If unset a random key is used (everyone is signed out on restart).
SESSION_SECRET = (os.environ.get("OPENDLP_SESSION_SECRET", "").strip() or secrets.token_hex(32)).encode("utf-8")
VERSION = "0.13.0"

_stop_scheduler = threading.Event()


def _report_scheduler() -> None:
    """Hourly: monthly report e-mail (if enabled) and cloud drive scan when due."""
    while not _stop_scheduler.wait(3600):
        run_monthly_report_job()
        if cloud_scan_due():
            run_cloud_scan()


def run_monthly_report_job(now: datetime | None = None) -> str | None:
    if not (REPORT_EMAIL and SMTP_HOST and SMTP_TO):
        return None
    with _db_lock:
        conn = db()
        try:
            return report.maybe_send_monthly(conn, now or datetime.now(timezone.utc), ORG_NAME, deliver_report_email, AUDIT_KEY)
        except Exception:  # noqa: BLE001 - never crash the scheduler; it retries next hour
            return None
        finally:
            conn.close()


@asynccontextmanager
async def lifespan(_app: FastAPI):
    purge_old_events()
    _stop_scheduler.clear()
    threading.Thread(target=_report_scheduler, daemon=True, name="opendlp-report").start()
    yield
    _stop_scheduler.set()


app = FastAPI(title="OpenDLP Central Server", version=VERSION, lifespan=lifespan)
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
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS fingerprints (
                sha256 TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                added_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT);
            """
        )
        cols = {r["name"] for r in conn.execute("PRAGMA table_info(agents)")}
        for col, ddl in (
            ("token_hash", "TEXT"),
            ("enrolled_at", "TEXT"),
            ("revoked", "INTEGER NOT NULL DEFAULT 0"),
            ("host", "TEXT"),
            ("agent_version", "TEXT"),
            ("display_name", "TEXT"),
            ("group_name", "TEXT"),
        ):
            if col not in cols:
                conn.execute(f"ALTER TABLE agents ADD COLUMN {col} {ddl}")
        conn.execute(
            "CREATE TABLE IF NOT EXISTS group_policies (name TEXT PRIMARY KEY, overlay TEXT NOT NULL, updated_at TEXT NOT NULL)"
        )
        audit.ensure_schema(conn)
        conn.commit()
        conn.close()


init_db()

_forwarder: siem.Forwarder | None = siem.Forwarder(SYSLOG_URL, SYSLOG_FORMAT, VERSION) if SYSLOG_URL else None


def store_events(conn: sqlite3.Connection, rows: list[tuple[Any, ...]]) -> list[dict[str, Any]]:
    """The only way events are written: extends the tamper-evident chain. Caller holds _db_lock and commits,
    then passes the result to forward_events()."""
    ids = audit.append(conn, AUDIT_KEY, rows)
    out = []
    for (rid, chain), row in zip(ids, rows):
        ev = dict(zip(audit.EVENT_COLUMNS, row))
        ev["id"], ev["chain"] = rid, chain
        out.append(ev)
    return out


def forward_events(events: list[dict[str, Any]]) -> None:
    if _forwarder is None:
        return
    for ev in events:
        _forwarder.submit(ev, _severity_of(str(ev.get("message") or "")) if ev.get("level") == "ALERT" else "")


def record_admin_action(actor: str, action: str, detail: str = "") -> None:
    """Who changed what, stored in the same tamper-evident log as agent events (agent_id 'server')."""
    now = datetime.now(timezone.utc).isoformat()
    msg = f"actor={actor} action={action}" + (f" {detail}" if detail else "")
    with _db_lock:
        conn = db()
        try:
            evs = store_events(conn, [("server", now, "INFO", "ADMIN_ACTION", msg[:MAX_MESSAGE_LEN], "server", now)])
            conn.commit()
        finally:
            conn.close()
    forward_events(evs)


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


def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _enrolled_token_hash(agent_id: str) -> tuple[str | None, bool]:
    """(token_hash, revoked) for an agent that enrolled through the API, else (None, False)."""
    with _db_lock:
        conn = db()
        try:
            row = conn.execute("SELECT token_hash, revoked FROM agents WHERE agent_id = ?", (agent_id,)).fetchone()
        finally:
            conn.close()
    if row is None or not row["token_hash"]:
        return None, False
    return row["token_hash"], bool(row["revoked"])


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
    enrolled_hash, revoked = _enrolled_token_hash(agent_id)
    if enrolled_hash is not None:
        if revoked:
            raise HTTPException(status_code=403, detail="Agent has been revoked")
        if not _token_ok(_hash_token(token), enrolled_hash):
            raise HTTPException(status_code=403, detail="Invalid token")
        _remember_token(agent_id, token)
        return agent_id
    if not _token_ok(token, token_for_agent(agent_id)):
        raise HTTPException(status_code=403, detail="Invalid token")
    return agent_id


# Enrolled agents' plaintext tokens are needed to sign their policy (HMAC). Keep them in memory
# only; after a restart an agent's first request re-populates the cache.
_token_cache: dict[str, str] = {}


def _remember_token(agent_id: str, token: str) -> None:
    _token_cache[agent_id] = token


def signing_secret_for_agent(agent_id: str) -> str:
    cached = _token_cache.get(agent_id)
    if cached is not None:
        return cached
    return token_for_agent(agent_id)


def admin_auth(authorization: str | None = Header(default=None)) -> str:
    """Full administrative access. Returns the role name."""
    if not ADMIN_TOKEN or len(ADMIN_TOKEN.encode("utf-8")) < MIN_TOKEN_BYTES:
        raise HTTPException(status_code=503, detail="Server is not configured: set OPENDLP_ADMIN_TOKEN (>=32 bytes)")
    if not _token_ok(_bearer(authorization), ADMIN_TOKEN):
        raise HTTPException(status_code=403, detail="Invalid token")
    return "admin"


def viewer_auth(authorization: str | None = Header(default=None)) -> str:
    """Read-only access: admin token or viewer token. Returns the role name."""
    if not ADMIN_TOKEN or len(ADMIN_TOKEN.encode("utf-8")) < MIN_TOKEN_BYTES:
        raise HTTPException(status_code=503, detail="Server is not configured: set OPENDLP_ADMIN_TOKEN (>=32 bytes)")
    token = _bearer(authorization)
    if _token_ok(token, ADMIN_TOKEN):
        return "admin"
    if VIEWER_TOKEN and len(VIEWER_TOKEN.encode("utf-8")) >= MIN_TOKEN_BYTES and _token_ok(token, VIEWER_TOKEN):
        return "viewer"
    raise HTTPException(status_code=403, detail="Invalid token")


SESSION_COOKIE = "opendlp_session"
LOGIN_COOKIE = "opendlp_login"
_oidc: sso.Provider | None = (
    sso.Provider(OIDC_ISSUER, OIDC_CLIENT_ID, OIDC_CLIENT_SECRET, cloudscan.default_http)
    if OIDC_ISSUER and OIDC_CLIENT_ID and OIDC_CLIENT_SECRET else None
)


def _same_origin(request: Request) -> bool:
    origin = request.headers.get("origin") or request.headers.get("referer") or ""
    if not origin:
        return False
    from urllib.parse import urlparse

    return urlparse(origin).netloc == request.headers.get("host", request.url.netloc)


def dashboard_auth(request: Request, credentials: HTTPBasicCredentials | None = Depends(_basic)) -> str:
    """Returns 'admin' or 'viewer' and sets request.state.actor (who is acting, for the audit log)."""
    # Browsers attach cookies and Basic credentials automatically, so state-changing dashboard requests must come
    # from our own pages (CSRF protection). Scripts should use the /api/v1/admin endpoints with a bearer token.
    if request.method not in {"GET", "HEAD", "OPTIONS"} and not _same_origin(request):
        raise HTTPException(status_code=403, detail="Cross-site request refused")
    session = sso.unsign(request.cookies.get(SESSION_COOKIE), SESSION_SECRET)
    if session and session.get("role") in {"admin", "viewer"}:
        request.state.actor = "sso:" + str(session.get("sub", ""))
        return str(session["role"])
    if DASHBOARD_PASSWORD and credentials is not None:
        if _token_ok(credentials.username, DASHBOARD_USER) and _token_ok(credentials.password, DASHBOARD_PASSWORD):
            request.state.actor = credentials.username
            return "admin"
        if DASHBOARD_VIEWER_PASSWORD and _token_ok(credentials.username, DASHBOARD_VIEWER_USER) and _token_ok(
            credentials.password, DASHBOARD_VIEWER_PASSWORD
        ):
            request.state.actor = credentials.username
            return "viewer"
    if _oidc is not None:
        if request.method == "GET" and credentials is None:
            from urllib.parse import quote

            raise HTTPException(status_code=303, detail="Sign-in required",
                                headers={"Location": "/login?next=" + quote(request.url.path, safe="/")})
        raise HTTPException(status_code=401, detail="Sign-in required")
    if DASHBOARD_PASSWORD:
        raise HTTPException(status_code=401, detail="Authentication required", headers={"WWW-Authenticate": "Basic"})
    if not DASHBOARD_INSECURE:
        raise HTTPException(
            status_code=404,
            detail="Dashboard disabled: set OPENDLP_DASHBOARD_PASSWORD or OIDC single sign-on "
            "(or OPENDLP_DASHBOARD_INSECURE=1 for local dev only)",
        )
    request.state.actor = "insecure-dev"
    return "admin"


def actor_of(request: Request) -> str:
    return str(getattr(request.state, "actor", "unknown"))


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
            n = audit.purge_before(conn, cutoff)
            conn.commit()
            return n
        finally:
            conn.close()


@app.post("/api/v1/telemetry")
def ingest(
    payload: TelemetryPayload,
    _agent: str = Depends(auth),
    x_agent_version: str | None = Header(default=None),
) -> dict[str, Any]:
    if not secrets.compare_digest(payload.agentId.encode(), _agent.encode()):
        raise HTTPException(status_code=403, detail="Agent ID header does not match payload")
    now = datetime.now(timezone.utc).isoformat()
    inserted = 0
    notify: list[dict[str, Any]] = []
    rows: list[tuple[Any, ...]] = []
    seen_host = ""

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
                seen_host = host or seen_host
                if level == "ALERT" and _severity_rank(_severity_of(message)) >= _severity_rank(NOTIFY_MIN_SEVERITY):
                    notify.append({"agent_id": payload.agentId, "host": host, "ts": ts, "event_type": event_type, "message": message})

                rows.append((payload.agentId, ts, level, event_type, message, host, now))
                inserted += 1
            stored = store_events(conn, rows)

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
            conn.execute(
                "UPDATE agents SET host = COALESCE(NULLIF(?, ''), host), agent_version = COALESCE(?, agent_version) WHERE agent_id = ?",
                (seen_host, (x_agent_version or "")[:32] or None, payload.agentId),
            )
            conn.commit()
        finally:
            conn.close()

    forward_events(stored)
    if notify:
        send_notifications(notify)
    return {"ok": True, "inserted": inserted}


# ---------------------------------------------------------------------------
# Notifications
# ---------------------------------------------------------------------------
_SEV_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}


def _severity_rank(sev: str) -> int:
    return _SEV_RANK.get(sev, 0)


def _severity_of(message: str) -> str:
    """Agent alert messages start with 'severity=<level> ...'."""
    if message.startswith("severity="):
        return message[9:].split(" ", 1)[0].lower()
    return "medium"


_notify_last: dict[str, float] = {}


def _cooldown_ok(key: str) -> bool:
    import time

    now = time.monotonic()
    last = _notify_last.get(key)
    if last is not None and now - last < NOTIFY_COOLDOWN_SECONDS:
        return False
    _notify_last[key] = now
    return True


def deliver_webhook(url: str, body: dict[str, Any]) -> None:
    import urllib.request

    req = urllib.request.Request(
        url, data=json.dumps(body).encode("utf-8"), headers={"Content-Type": "application/json"}, method="POST"
    )
    with urllib.request.urlopen(req, timeout=10):  # noqa: S310 - operator-configured URL
        pass


def deliver_email(subject: str, text: str) -> None:
    import smtplib
    from email.message import EmailMessage

    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = SMTP_FROM or SMTP_USER
    msg["To"] = ", ".join(SMTP_TO)
    msg.set_content(text)
    with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=15) as smtp:
        if SMTP_STARTTLS:
            smtp.starttls()
        if SMTP_USER:
            smtp.login(SMTP_USER, SMTP_PASSWORD)
        smtp.send_message(msg)


def deliver_report_email(subject: str, text: str, pdf: bytes, filename: str) -> None:
    import smtplib
    from email.message import EmailMessage

    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = SMTP_FROM or SMTP_USER
    msg["To"] = ", ".join(SMTP_TO)
    msg.set_content(text)
    msg.add_attachment(pdf, maintype="application", subtype="pdf", filename=filename)
    with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=30) as smtp:
        if SMTP_STARTTLS:
            smtp.starttls()
        if SMTP_USER:
            smtp.login(SMTP_USER, SMTP_PASSWORD)
        smtp.send_message(msg)


def send_notifications(alerts: list[dict[str, Any]]) -> int:
    """Fan alerts out to the configured channels in a background thread. Returns how many alerts were dispatched."""
    if not WEBHOOK_URL and not (SMTP_HOST and SMTP_TO):
        return 0
    todo = [a for a in alerts if _cooldown_ok(f"{a['agent_id']}|{a['event_type']}")]
    if not todo:
        return 0

    def run() -> None:
        for a in todo:
            summary = f"[OpenDLP] {_severity_of(a['message']).upper()} alert on {a['agent_id']} ({a['host'] or 'unknown host'}): {a['event_type']}"
            body = {"text": summary + "\n" + a["message"][:1000], "content": summary, **a}
            if WEBHOOK_URL:
                try:
                    deliver_webhook(WEBHOOK_URL, body)
                except Exception:  # noqa: BLE001 - never let notification failures affect ingestion
                    pass
            if SMTP_HOST and SMTP_TO:
                try:
                    deliver_email(summary, f"{summary}\n\nTime: {a['ts']}\n\n{a['message']}")
                except Exception:  # noqa: BLE001
                    pass

    threading.Thread(target=run, daemon=True).start()
    return len(todo)


POLICY_PATH = Path(os.environ.get("OPENDLP_POLICY", Path(__file__).resolve().parent.parent / "policies" / "default-policy.json"))
# Explicit value pins the version; otherwise the policy file mtime is used (monotonic), so edits propagate automatically.
_env_version = os.environ.get("OPENDLP_POLICY_VERSION", "").strip()
POLICY_VERSION: int | None = int(_env_version) if _env_version else None

_SEVERITIES = {"low", "medium", "high", "critical"}
_ACTIONS = {"log", "alert", "block"}
_RULE_TYPES = {"builtin", "keywords", "regex"}
# Must match ContentScanner.RunBuiltin in agent/Scanner.cs
BUILTIN_DETECTORS = {"tw_national_id", "credit_card", "tw_mobile", "email", "tw_passport", "api_key", "private_key", "iban", "us_ssn", "passport"}


def validate_policy(obj: Any) -> list[str]:
    """Return a list of problems; empty means the policy is acceptable to ship to agents."""
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
        if rtype == "builtin" and r.get("detector") not in BUILTIN_DETECTORS:
            errs.append(f"{where}.detector must be one of {sorted(BUILTIN_DETECTORS)}")
        if rtype == "keywords" and not (isinstance(r.get("keywords"), list) and r["keywords"]):
            errs.append(f"{where}.keywords must be a non-empty list")
        if rtype == "regex":
            try:
                re.compile(str(r.get("pattern", "")))
            except re.error as exc:
                errs.append(f"{where}.pattern is not a valid regex: {exc}")
            if not r.get("pattern"):
                errs.append(f"{where}.pattern is required for regex rules")
        for x in r.get("exclude", []) or []:
            try:
                re.compile(str(x))
            except re.error as exc:
                errs.append(f"{where}.exclude pattern {x!r} is not a valid regex: {exc}")
        if not isinstance(r.get("contextWords", []), list):
            errs.append(f"{where}.contextWords must be a list")
        if not isinstance(r.get("requireContext", False), bool):
            errs.append(f"{where}.requireContext must be true or false")
    usb_mode = (obj.get("usb") or {}).get("mode", "audit")
    if usb_mode not in {"audit", "block"}:
        errs.append("usb.mode must be 'audit' or 'block'")
    browser = obj.get("browser") or {}
    if browser.get("mode", "audit") not in {"audit", "warn", "block"}:
        errs.append("browser.mode must be 'audit', 'warn' or 'block'")
    for key in ("monitoredDomains", "blockedUploadDomains"):
        if not isinstance(browser.get(key, []), list):
            errs.append(f"browser.{key} must be a list of domains")
    ai = obj.get("ai") or {}
    if ai.get("enabled") and not str(ai.get("endpoint", "")).startswith(("http://", "https://")):
        errs.append("ai.endpoint must be an http(s) URL when ai.enabled is true")
    if "fingerprints" in obj:
        errs.append("'fingerprints' is managed by the server registry (/api/v1/admin/fingerprints); remove it from the policy file")
    return errs


def _load_signing_key():
    if not SIGNING_KEY_PATH:
        return None
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ec

        key = serialization.load_pem_private_key(Path(SIGNING_KEY_PATH).read_bytes(), password=None)
        if not isinstance(key, ec.EllipticCurvePrivateKey) or key.curve.name != "secp256r1":
            raise HTTPException(status_code=500, detail="OPENDLP_SIGNING_KEY must be an ECDSA P-256 key")
        return key
    except HTTPException:
        raise
    except Exception as exc:  # unreadable / malformed key: fail closed rather than ship unsigned policy
        raise HTTPException(status_code=500, detail="Policy signing key is unreadable") from exc


def asymmetric_sign(data: bytes) -> str | None:
    key = _load_signing_key()
    if key is None:
        return None
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    import base64

    return base64.b64encode(key.sign(data, ec.ECDSA(hashes.SHA256()))).decode("ascii")


def fingerprint_registry() -> tuple[list[dict[str, str]], int]:
    """Registered confidential-file fingerprints and the version (epoch seconds) of the last change."""
    with _db_lock:
        conn = db()
        try:
            rows = conn.execute("SELECT sha256, name FROM fingerprints ORDER BY added_at").fetchall()
            v = conn.execute("SELECT value FROM meta WHERE key = 'fingerprints_version'").fetchone()
        finally:
            conn.close()
    return [{"sha256": r["sha256"], "name": r["name"]} for r in rows], int(v["value"]) if v else 0


def _bump_fingerprint_version(conn: sqlite3.Connection) -> int:
    """Strictly increasing so agents always see a newer policy version after a registry change."""
    prev = conn.execute("SELECT value FROM meta WHERE key = 'fingerprints_version'").fetchone()
    policy_mtime = int(POLICY_PATH.stat().st_mtime) if POLICY_PATH.exists() else 0
    new = max(int(datetime.now(timezone.utc).timestamp()), (int(prev["value"]) if prev else 0) + 1, policy_mtime + 1)
    conn.execute("INSERT INTO meta(key, value) VALUES ('fingerprints_version', ?) "
                 "ON CONFLICT(key) DO UPDATE SET value = excluded.value", (str(new),))
    return new


_GROUP_RX = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 _.-]{0,63}$")


def merge_policy(base: dict[str, Any], overlay: dict[str, Any]) -> dict[str, Any]:
    """Group overlay on top of the company policy.
    - rules: a rule with an existing id replaces it, a new id is appended
    - disableRules: list of rule ids to drop
    - objects (usb, browser, ai, ...): keys are merged one level deep
    - anything else: replaced"""
    out = json.loads(json.dumps(base))
    for key, val in overlay.items():
        if key == "rules" and isinstance(val, list):
            by_id = {r.get("id"): i for i, r in enumerate(out.get("rules", [])) if isinstance(r, dict)}
            for r in val:
                if isinstance(r, dict) and r.get("id") in by_id:
                    out["rules"][by_id[r["id"]]] = r
                else:
                    out.setdefault("rules", []).append(r)
        elif key == "disableRules" and isinstance(val, list):
            out["rules"] = [r for r in out.get("rules", []) if not (isinstance(r, dict) and r.get("id") in val)]
        elif isinstance(val, dict) and isinstance(out.get(key), dict):
            out[key] = {**out[key], **val}
        else:
            out[key] = val
    return out


def _read_base_policy() -> tuple[dict[str, Any], int]:
    try:
        return json.loads(POLICY_PATH.read_text(encoding="utf-8")), int(POLICY_PATH.stat().st_mtime)
    except FileNotFoundError as exc:
        raise HTTPException(status_code=500, detail="Policy file is missing") from exc
    except (json.JSONDecodeError, OSError) as exc:
        raise HTTPException(status_code=500, detail="Policy file is invalid or unreadable") from exc


def group_of(agent_id: str) -> str | None:
    with _db_lock:
        conn = db()
        try:
            row = conn.execute("SELECT group_name FROM agents WHERE agent_id = ?", (agent_id,)).fetchone()
        finally:
            conn.close()
    return row["group_name"] if row and row["group_name"] else None


def group_overlay(name: str) -> dict[str, Any] | None:
    with _db_lock:
        conn = db()
        try:
            row = conn.execute("SELECT overlay FROM group_policies WHERE name = ?", (name,)).fetchone()
        finally:
            conn.close()
    return json.loads(row["overlay"]) if row else None


def effective_policy(agent_id: str | None) -> dict[str, Any]:
    policy_obj, _ = _read_base_policy()
    group = group_of(agent_id) if agent_id else None
    overlay = group_overlay(group) if group else None
    if overlay:
        policy_obj = merge_policy(policy_obj, overlay)
    return policy_obj


def policy_envelope(agent_id: str) -> dict[str, Any]:
    _, mtime = _read_base_policy()
    policy_obj = effective_policy(agent_id)

    problems = validate_policy(policy_obj)
    if problems:
        raise HTTPException(status_code=500, detail="Policy failed validation: " + "; ".join(problems[:5]))

    # The agent verifies HMAC-SHA256 over this exact JSON string. The key derivation
    # mirrors AgentConfig.PolicyVerifyKey(); this is a shared-secret design, not
    # asymmetric signing. Use TLS and protect the token in any real deployment.
    fps, fp_version = fingerprint_registry()
    policy_obj["fingerprints"] = fps
    mtime = max(mtime, fp_version)
    policy_json = json.dumps(policy_obj, ensure_ascii=False, separators=(",", ":"))
    verify_key = hashlib.sha256(signing_secret_for_agent(agent_id).encode("utf-8")).hexdigest().encode("utf-8")
    sig = hmac.new(verify_key, policy_json.encode("utf-8"), hashlib.sha256).hexdigest()
    version = POLICY_VERSION if POLICY_VERSION is not None else mtime
    envelope: dict[str, Any] = {"version": version, "policyJson": policy_json, "sig": sig}
    pub_sig = asymmetric_sign(policy_json.encode("utf-8"))
    if pub_sig is not None:
        envelope["pubSig"] = pub_sig
    return envelope


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
                "SELECT agent_id, last_seen, last_event, enrolled_at, revoked, host, agent_version, display_name, group_name, "
                "CASE WHEN token_hash IS NULL THEN 0 ELSE 1 END AS enrolled FROM agents ORDER BY last_seen DESC"
            ).fetchall()
        finally:
            conn.close()
    out = [dict(r) for r in rows]
    for r in out:
        r["revoked"] = bool(r["revoked"])
        r["enrolled"] = bool(r["enrolled"])
        r["status"] = "revoked" if r["revoked"] else agent_status(r["last_seen"])
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
def list_agents(_role: str = Depends(viewer_auth)) -> list[dict[str, Any]]:
    return query_agents()


@app.get("/api/v1/events")
def list_events(
    limit: int = 100,
    agent_id: str | None = None,
    level: str | None = None,
    event_type: str | None = None,
    since: str | None = None,
    q: str | None = None,
    _role: str = Depends(viewer_auth),
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
    _role: str = Depends(viewer_auth),
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


def event_timeseries(hours: int = 24, level: str | None = None, bucket: str = "hour") -> list[dict[str, Any]]:
    """Event counts per hour (or day) over the window, zero-filled, oldest first. Uses server receive time."""
    now = datetime.now(timezone.utc)
    if bucket == "day":
        start = (now - timedelta(days=max(1, hours // 24) - 1)).replace(hour=0, minute=0, second=0, microsecond=0)
        width, step, fmt = 10, timedelta(days=1), "%Y-%m-%d"
    else:
        start = (now - timedelta(hours=hours - 1)).replace(minute=0, second=0, microsecond=0)
        width, step, fmt = 13, timedelta(hours=1), "%Y-%m-%dT%H"
    sql = f"SELECT substr(received_at, 1, {width}) AS b, COUNT(*) AS n FROM events WHERE received_at >= ?"
    params: list[Any] = [start.isoformat()]
    if level:
        sql += " AND level = ?"
        params.append(level.upper())
    sql += " GROUP BY b"
    with _db_lock:
        conn = db()
        try:
            counts = {r["b"]: r["n"] for r in conn.execute(sql, params)}
        finally:
            conn.close()
    out = []
    t = start
    while t <= now:
        key = t.strftime(fmt)
        out.append({"bucket": key, "count": counts.get(key, 0)})
        t += step
    return out


@app.get("/api/v1/stats/timeseries")
def stats_timeseries(
    hours: int = 24, level: str | None = None, bucket: str = "hour", _role: str = Depends(viewer_auth)
) -> list[dict[str, Any]]:
    hours = max(1, min(hours, 24 * 90))
    return event_timeseries(hours, level, "day" if bucket == "day" else "hour")


def _bar_chart(series: list[dict[str, Any]], label_every: int, label_fmt) -> dict[str, Any]:
    """Pre-compute bar geometry for the dashboard's server-rendered SVG chart."""
    width, height, left, bottom, top = 720, 160, 32, 22, 8
    n = max(1, len(series))
    peak = max([p["count"] for p in series] + [1])
    plot_w, plot_h = width - left - 8, height - bottom - top
    slot = plot_w / n
    bar_w = max(2.0, slot - 2)  # 2px gap between bars
    bars = []
    for i, p in enumerate(series):
        h = 0 if p["count"] == 0 else max(2.0, plot_h * p["count"] / peak)
        x = left + i * slot + 1
        bars.append({
            "x": round(x, 1), "y": round(top + plot_h - h, 1), "w": round(bar_w, 1), "h": round(h, 1),
            "slot_x": round(left + i * slot, 1), "slot_w": round(slot, 1),
            "count": p["count"], "label": label_fmt(p["bucket"]),
            "tick": i % label_every == 0 or i == n - 1,
        })
    return {"width": width, "height": height, "left": left, "top": top, "base": top + plot_h,
            "mid": top + plot_h / 2, "peak": peak, "half": peak / 2, "bars": bars,
            "total": sum(p["count"] for p in series)}


@app.get("/api/v1/stats")
def stats(_role: str = Depends(viewer_auth)) -> dict[str, Any]:
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
def admin_get_policy(_role: str = Depends(viewer_auth)) -> dict[str, Any]:
    try:
        obj = json.loads(POLICY_PATH.read_text(encoding="utf-8"))
        mtime = int(POLICY_PATH.stat().st_mtime)
    except (OSError, json.JSONDecodeError) as exc:
        raise HTTPException(status_code=500, detail="Policy file is missing or invalid") from exc
    _, fp_version = fingerprint_registry()
    return {"version": POLICY_VERSION if POLICY_VERSION is not None else max(mtime, fp_version), "policy": obj}


@app.put("/api/v1/admin/policy")
def admin_put_policy(policy: dict[str, Any], _admin: str = Depends(admin_auth)) -> dict[str, Any]:
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
    record_admin_action("api-admin-token", "policy_update", f"rules={len(policy.get('rules', []))}")
    return {
        "ok": True,
        "version": POLICY_VERSION if POLICY_VERSION is not None else new_mtime,
        "note": "OPENDLP_POLICY_VERSION is pinned; agents will not update until it is raised"
        if POLICY_VERSION is not None
        else "agents will pick this up on their next poll",
    }



# ---------------------------------------------------------------------------
# Self-enrollment and agent administration
# ---------------------------------------------------------------------------
class EnrollRequest(BaseModel):
    agentId: str = Field(min_length=1, max_length=128)
    enrollmentCode: str = Field(min_length=1, max_length=256)
    host: str | None = Field(default=None, max_length=128)
    displayName: str | None = Field(default=None, max_length=128)


@app.post("/api/v1/enroll")
def enroll(req: EnrollRequest) -> dict[str, Any]:
    """Exchange the one-time enrollment code for a per-machine token. Re-enrolling an existing,
    non-revoked agent rotates its token (so a reinstalled machine keeps working)."""
    if not ENROLL_CODE or len(ENROLL_CODE.encode("utf-8")) < 16:
        raise HTTPException(status_code=503, detail="Enrollment disabled: set OPENDLP_ENROLL_CODE (>=16 bytes)")
    if not _token_ok(req.enrollmentCode, ENROLL_CODE):
        raise HTTPException(status_code=403, detail="Invalid enrollment code")
    agent_id = req.agentId.strip()
    if not agent_id:
        raise HTTPException(status_code=422, detail="agentId required")
    _, revoked = _enrolled_token_hash(agent_id)
    if revoked:
        raise HTTPException(status_code=403, detail="Agent has been revoked; an administrator must un-revoke it first")
    token = secrets.token_urlsafe(48)
    now = datetime.now(timezone.utc).isoformat()
    with _db_lock:
        conn = db()
        try:
            conn.execute(
                """
                INSERT INTO agents(agent_id, last_seen, last_event, token_hash, enrolled_at, host, display_name)
                VALUES (?, ?, 'enrolled', ?, ?, ?, ?)
                ON CONFLICT(agent_id) DO UPDATE SET
                    token_hash=excluded.token_hash, enrolled_at=excluded.enrolled_at,
                    host=COALESCE(excluded.host, agents.host), display_name=COALESCE(excluded.display_name, agents.display_name)
                """,
                (agent_id, now, _hash_token(token), now, req.host, req.displayName),
            )
            conn.commit()
        finally:
            conn.close()
    _remember_token(agent_id, token)
    return {"agentId": agent_id, "token": token, "policyPollSeconds": 60}


@app.post("/api/v1/admin/agents/{agent_id}/revoke")
def revoke_agent(agent_id: str, _admin: str = Depends(admin_auth)) -> dict[str, Any]:
    with _db_lock:
        conn = db()
        try:
            cur = conn.execute("UPDATE agents SET revoked = 1 WHERE agent_id = ?", (agent_id,))
            conn.commit()
        finally:
            conn.close()
    _token_cache.pop(agent_id, None)
    if cur.rowcount == 0:
        raise HTTPException(status_code=404, detail="Unknown agent")
    record_admin_action("api-admin-token", "agent_revoke", f"agent={agent_id}")
    return {"ok": True, "agent_id": agent_id, "revoked": True}


@app.post("/api/v1/admin/agents/{agent_id}/unrevoke")
def unrevoke_agent(agent_id: str, _admin: str = Depends(admin_auth)) -> dict[str, Any]:
    with _db_lock:
        conn = db()
        try:
            cur = conn.execute("UPDATE agents SET revoked = 0 WHERE agent_id = ?", (agent_id,))
            conn.commit()
        finally:
            conn.close()
    if cur.rowcount == 0:
        raise HTTPException(status_code=404, detail="Unknown agent")
    record_admin_action("api-admin-token", "agent_unrevoke", f"agent={agent_id}")
    return {"ok": True, "agent_id": agent_id, "revoked": False}


@app.delete("/api/v1/admin/agents/{agent_id}")
def delete_agent(agent_id: str, _admin: str = Depends(admin_auth)) -> dict[str, Any]:
    """Remove an agent record (its events are kept for audit)."""
    with _db_lock:
        conn = db()
        try:
            cur = conn.execute("DELETE FROM agents WHERE agent_id = ?", (agent_id,))
            conn.commit()
        finally:
            conn.close()
    _token_cache.pop(agent_id, None)
    if cur.rowcount == 0:
        raise HTTPException(status_code=404, detail="Unknown agent")
    record_admin_action("api-admin-token", "agent_delete", f"agent={agent_id}")
    return {"ok": True}


@app.post("/api/v1/admin/notify/test")
def notify_test(_admin: str = Depends(admin_auth)) -> dict[str, Any]:
    n = send_notifications([{
        "agent_id": "test", "host": "test-host", "ts": datetime.now(timezone.utc).isoformat(),
        "event_type": "NOTIFY_TEST", "message": "severity=critical This is a test notification from OpenDLP",
    }])
    return {"dispatched": n, "webhook": bool(WEBHOOK_URL), "email": bool(SMTP_HOST and SMTP_TO)}


@app.get("/", response_class=HTMLResponse)
def dashboard(
    request: Request,
    level: str = "",
    agent_id: str = "",
    q: str = "",
    role: str = Depends(dashboard_auth),
) -> HTMLResponse:
    agents = query_agents()
    events = query_events(100, agent_id or None, level or None, None, None, q or None)
    alerts_24h = _bar_chart(event_timeseries(24, "ALERT"), 6, lambda b: b[-2:] + ":00")
    events_7d = _bar_chart(event_timeseries(24 * 7, None, "day"), 1, lambda b: b[5:])
    since = (datetime.now(timezone.utc) - timedelta(hours=24)).isoformat()
    sev = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for e in query_events(5000, None, "ALERT", None, since, None):
        sev[_severity_of(e["message"])] = sev.get(_severity_of(e["message"]), 0) + 1
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
            "role": role,
            "actor": actor_of(request),
            "sso": _oidc is not None,
            "groups": [g["name"] for g in list_groups()],
            "audit": verify_audit_chain(),
            "sev": sev,
            "charts": [
                {"id": "alerts24", "title": "Alerts per hour", "sub": "last 24 hours, UTC", "c": alerts_24h},
                {"id": "events7", "title": "Events per day", "sub": "last 7 days, UTC", "c": events_7d},
            ],
        },
    )


# --------------------------------------------------------------------------- cloud drive scanning
_cloud_lock = threading.Lock()
_cloud_status: dict[str, Any] = {"running": False, "last_started": None, "last_finished": None, "results": []}


def cloud_sources() -> list[str]:
    out = []
    if GOOGLE_SA_FILE and GOOGLE_ADMIN and GOOGLE_DOMAIN:
        out.append("google")
    if M365_TENANT and M365_CLIENT_ID and M365_SECRET:
        out.append("m365")
    return out


def cloud_scan_due(now: datetime | None = None) -> bool:
    if CLOUD_SCAN_HOURS <= 0 or not cloud_sources() or _cloud_status["running"]:
        return False
    last = _cloud_status["last_finished"]
    now = now or datetime.now(timezone.utc)
    return last is None or (now - datetime.fromisoformat(last)).total_seconds() >= CLOUD_SCAN_HOURS * 3600


def _policy_rules_and_fingerprints() -> tuple[list[dict[str, Any]], dict[str, str]]:
    try:
        rules = json.loads(POLICY_PATH.read_text(encoding="utf-8")).get("rules", [])
    except (OSError, json.JSONDecodeError):
        rules = []
    return rules, {f["sha256"]: f["name"] for f in fingerprint_registry()[0]}


def record_cloud_result(res: "cloudscan.ScanResult") -> None:
    agent_id = f"cloud-{res.source}"
    now = datetime.now(timezone.utc).isoformat()
    events = [(agent_id, now, "ALERT", "CLOUD_PUBLIC_SHARE", f.message()[:MAX_MESSAGE_LEN], res.source, now) for f in res.findings]
    events.append((agent_id, now, "WARN" if res.errors else "INFO", "CLOUD_SCAN_SUMMARY",
                   f"users={res.users} public_files={res.public_files} inspected={res.inspected} "
                   f"findings={len(res.findings)} errors={len(res.errors)}"
                   + (" first_error=" + res.errors[0][:300] if res.errors else ""), res.source, now))
    with _db_lock:
        conn = db()
        try:
            stored = store_events(conn, events)
            conn.execute(
                "INSERT INTO agents(agent_id, last_seen, last_event, host, display_name) VALUES (?, ?, ?, ?, ?) "
                "ON CONFLICT(agent_id) DO UPDATE SET last_seen = excluded.last_seen, last_event = excluded.last_event",
                (agent_id, now, f"cloud scan: {len(res.findings)} findings", res.source,
                 "Google Drive scan" if res.source == "google" else "Microsoft 365 scan"),
            )
            conn.commit()
        finally:
            conn.close()
    forward_events(stored)
    alerts = [{"agent_id": agent_id, "host": res.source, "ts": now, "event_type": "CLOUD_PUBLIC_SHARE", "message": f.message()}
              for f in res.findings]
    if alerts:
        send_notifications(alerts)


def run_cloud_scan(http: "cloudscan.Http | None" = None) -> list[dict[str, Any]]:
    """Scan every configured source once. Returns a summary per source."""
    if not _cloud_lock.acquire(blocking=False):
        return [{"source": "all", "error": "a scan is already running"}]
    _cloud_status.update(running=True, last_started=datetime.now(timezone.utc).isoformat())
    summaries: list[dict[str, Any]] = []
    try:
        rules, fps = _policy_rules_and_fingerprints()
        h = http or cloudscan.default_http
        for src in cloud_sources():
            try:
                if src == "google":
                    sa = json.loads(Path(GOOGLE_SA_FILE).read_text(encoding="utf-8"))
                    res = cloudscan.scan_google(sa, GOOGLE_ADMIN, GOOGLE_DOMAIN, rules, fps, h)
                else:
                    res = cloudscan.scan_m365(M365_TENANT, M365_CLIENT_ID, M365_SECRET, rules, fps, h)
                record_cloud_result(res)
                summaries.append({"source": src, "users": res.users, "public_files": res.public_files,
                                  "inspected": res.inspected, "findings": len(res.findings), "errors": res.errors[:5]})
            except Exception as exc:  # noqa: BLE001 - report and continue with the next source
                summaries.append({"source": src, "error": str(exc)[:300]})
    finally:
        _cloud_status.update(running=False, last_finished=datetime.now(timezone.utc).isoformat(), results=summaries)
        _cloud_lock.release()
    return summaries


@app.get("/api/v1/admin/cloudscan")
def cloudscan_status(_role: str = Depends(viewer_auth)) -> dict[str, Any]:
    return {"sources": cloud_sources(), "interval_hours": CLOUD_SCAN_HOURS, **_cloud_status}


@app.post("/api/v1/admin/cloudscan/run")
def cloudscan_run(_admin: str = Depends(admin_auth)) -> dict[str, Any]:
    if not cloud_sources():
        raise HTTPException(status_code=409, detail="No cloud source configured (see docs/CLOUD-SCAN.md)")
    if _cloud_status["running"]:
        raise HTTPException(status_code=409, detail="A scan is already running")
    threading.Thread(target=run_cloud_scan, daemon=True, name="opendlp-cloudscan").start()
    record_admin_action("api-admin-token", "cloudscan_run", "sources=" + ",".join(cloud_sources()))
    return {"started": True, "sources": cloud_sources()}


_SHA256_RX = re.compile(r"^[0-9a-fA-F]{64}$")


class FingerprintIn(BaseModel):
    sha256: str = Field(min_length=64, max_length=64)
    name: str = Field(min_length=1, max_length=200)


def add_fingerprint(fp: FingerprintIn, actor: str) -> dict[str, Any]:
    if not _SHA256_RX.match(fp.sha256):
        raise HTTPException(status_code=422, detail="sha256 must be 64 hex characters")
    with _db_lock:
        conn = db()
        try:
            conn.execute(
                "INSERT INTO fingerprints(sha256, name, added_at) VALUES (?, ?, ?) "
                "ON CONFLICT(sha256) DO UPDATE SET name = excluded.name",
                (fp.sha256.lower(), fp.name.strip(), datetime.now(timezone.utc).isoformat()),
            )
            version = _bump_fingerprint_version(conn)
            conn.commit()
        finally:
            conn.close()
    record_admin_action(actor, "fingerprint_add", f"sha256={fp.sha256.lower()} name=\"{fp.name.strip()[:100]}\"")
    return {"ok": True, "sha256": fp.sha256.lower(), "name": fp.name.strip(), "policyVersion": version}


def remove_fingerprint(sha256: str, actor: str) -> dict[str, Any]:
    with _db_lock:
        conn = db()
        try:
            cur = conn.execute("DELETE FROM fingerprints WHERE sha256 = ?", (sha256.lower(),))
            if cur.rowcount:
                _bump_fingerprint_version(conn)
            conn.commit()
        finally:
            conn.close()
    if cur.rowcount == 0:
        raise HTTPException(status_code=404, detail="Unknown fingerprint")
    record_admin_action(actor, "fingerprint_remove", f"sha256={sha256.lower()}")
    return {"ok": True}


@app.get("/api/v1/admin/fingerprints")
def list_fingerprints(_role: str = Depends(viewer_auth)) -> list[dict[str, str]]:
    return fingerprint_registry()[0]


@app.post("/api/v1/admin/fingerprints")
def api_add_fingerprint(fp: FingerprintIn, _admin: str = Depends(admin_auth)) -> dict[str, Any]:
    return add_fingerprint(fp, "api-admin-token")


@app.delete("/api/v1/admin/fingerprints/{sha256}")
def api_remove_fingerprint(sha256: str, _admin: str = Depends(admin_auth)) -> dict[str, Any]:
    return remove_fingerprint(sha256, "api-admin-token")


@app.get("/fingerprints", response_class=HTMLResponse)
def fingerprints_page(request: Request, role: str = Depends(dashboard_auth)) -> HTMLResponse:
    return templates.TemplateResponse(request, "fingerprints.html", {"items": fingerprint_registry()[0], "role": role})


@app.post("/fingerprints")
def dashboard_add_fingerprint(fp: FingerprintIn, request: Request, role: str = Depends(dashboard_auth)) -> dict[str, Any]:
    if role != "admin":
        raise HTTPException(status_code=403, detail="Admin only")
    return add_fingerprint(fp, actor_of(request))


@app.delete("/fingerprints/{sha256}")
def dashboard_remove_fingerprint(sha256: str, request: Request, role: str = Depends(dashboard_auth)) -> dict[str, Any]:
    if role != "admin":
        raise HTTPException(status_code=403, detail="Admin only")
    return remove_fingerprint(sha256, actor_of(request))


def _report_response(month: str | None) -> Response:
    try:
        with _db_lock:
            conn = db()
            try:
                label, pdf = report.build_monthly_report(conn, month, ORG_NAME, AUDIT_KEY)
            finally:
                conn.close()
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return Response(
        content=pdf,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="opendlp-report-{label}.pdf"'},
    )


@app.get("/api/v1/reports/monthly.pdf")
def monthly_report_api(month: str | None = None, _role: str = Depends(viewer_auth)) -> Response:
    """PDF report for a month ('YYYY-MM', default: current month to date)."""
    return _report_response(month)


@app.get("/reports/monthly.pdf")
def monthly_report_dashboard(month: str | None = None, _role: str = Depends(dashboard_auth)) -> Response:
    return _report_response(month)


@app.get("/deploy", response_class=HTMLResponse)
def deploy_page(request: Request, role: str = Depends(dashboard_auth)) -> HTMLResponse:
    """Ready-to-copy rollout commands. Admin only: it shows the enrollment code."""
    if role != "admin":
        raise HTTPException(status_code=403, detail="Admin only")
    server_url = PUBLIC_URL or str(request.base_url).rstrip("/")
    version = "v" + app.version
    base = f"https://github.com/{RELEASE_REPO}/releases/download/{version}"
    return templates.TemplateResponse(
        request,
        "deploy.html",
        {
            "server_url": server_url,
            "enroll_code": ENROLL_CODE,
            "enroll_ok": len(ENROLL_CODE.encode("utf-8")) >= 16,
            "version": version,
            "release_base": base,
            "release_page": f"https://github.com/{RELEASE_REPO}/releases/tag/{version}",
            "plain_http": server_url.startswith("http://") and not any(h in server_url for h in ("127.0.0.1", "localhost")),
        },
    )


# --------------------------------------------------------------------------- department / group policies
class GroupAssign(BaseModel):
    group: str | None = Field(default=None, max_length=64)


def list_groups() -> list[dict[str, Any]]:
    with _db_lock:
        conn = db()
        try:
            rows = conn.execute(
                "SELECT g.name, g.overlay, g.updated_at, (SELECT COUNT(*) FROM agents a WHERE a.group_name = g.name) AS agents "
                "FROM group_policies g ORDER BY g.name"
            ).fetchall()
        finally:
            conn.close()
    return [{"name": r["name"], "overlay": json.loads(r["overlay"]), "updatedAt": r["updated_at"], "agents": r["agents"]} for r in rows]


def put_group(name: str, overlay: dict[str, Any], actor: str) -> dict[str, Any]:
    if not _GROUP_RX.match(name):
        raise HTTPException(status_code=422, detail="Group name: 1-64 letters, digits, space, '_', '-' or '.'")
    if "fingerprints" in overlay:
        raise HTTPException(status_code=422, detail="'fingerprints' is managed by the server registry")
    if "disableRules" in overlay and not (isinstance(overlay["disableRules"], list)
                                         and all(isinstance(x, str) for x in overlay["disableRules"])):
        raise HTTPException(status_code=422, detail="disableRules must be a list of rule ids")
    base, _ = _read_base_policy()
    problems = validate_policy(merge_policy(base, overlay))
    if problems:
        raise HTTPException(status_code=422, detail=problems[:20])
    with _db_lock:
        conn = db()
        try:
            conn.execute(
                "INSERT INTO group_policies(name, overlay, updated_at) VALUES (?, ?, ?) "
                "ON CONFLICT(name) DO UPDATE SET overlay = excluded.overlay, updated_at = excluded.updated_at",
                (name, json.dumps(overlay, ensure_ascii=False), datetime.now(timezone.utc).isoformat()),
            )
            version = _bump_fingerprint_version(conn)
            conn.commit()
        finally:
            conn.close()
    record_admin_action(actor, "group_policy_update", f"group=\"{name}\"")
    return {"ok": True, "group": name, "policyVersion": version}


def delete_group(name: str, actor: str) -> dict[str, Any]:
    with _db_lock:
        conn = db()
        try:
            cur = conn.execute("DELETE FROM group_policies WHERE name = ?", (name,))
            conn.execute("UPDATE agents SET group_name = NULL WHERE group_name = ?", (name,))
            if cur.rowcount:
                _bump_fingerprint_version(conn)
            conn.commit()
        finally:
            conn.close()
    if cur.rowcount == 0:
        raise HTTPException(status_code=404, detail="Unknown group")
    record_admin_action(actor, "group_delete", f"group=\"{name}\"")
    return {"ok": True}


def assign_group(agent_id: str, group: str | None, actor: str) -> dict[str, Any]:
    group = (group or "").strip() or None
    with _db_lock:
        conn = db()
        try:
            if group and conn.execute("SELECT 1 FROM group_policies WHERE name = ?", (group,)).fetchone() is None:
                raise HTTPException(status_code=404, detail="Unknown group; create it first")
            cur = conn.execute("UPDATE agents SET group_name = ? WHERE agent_id = ?", (group, agent_id))
            if cur.rowcount == 0:
                raise HTTPException(status_code=404, detail="Unknown agent")
            version = _bump_fingerprint_version(conn)
            conn.commit()
        finally:
            conn.close()
    record_admin_action(actor, "agent_group_assign", f"agent={agent_id} group=\"{group or ''}\"")
    return {"ok": True, "agent_id": agent_id, "group": group, "policyVersion": version}


@app.get("/api/v1/admin/groups")
def api_list_groups(_role: str = Depends(viewer_auth)) -> list[dict[str, Any]]:
    return list_groups()


@app.put("/api/v1/admin/groups/{name}")
def api_put_group(name: str, overlay: dict[str, Any], _admin: str = Depends(admin_auth)) -> dict[str, Any]:
    return put_group(name, overlay, "api-admin-token")


@app.delete("/api/v1/admin/groups/{name}")
def api_delete_group(name: str, _admin: str = Depends(admin_auth)) -> dict[str, Any]:
    return delete_group(name, "api-admin-token")


@app.post("/api/v1/admin/agents/{agent_id}/group")
def api_assign_group(agent_id: str, body: GroupAssign, _admin: str = Depends(admin_auth)) -> dict[str, Any]:
    return assign_group(agent_id, body.group, "api-admin-token")


@app.get("/api/v1/admin/agents/{agent_id}/effective-policy")
def api_effective_policy(agent_id: str, _role: str = Depends(viewer_auth)) -> dict[str, Any]:
    return {"agent_id": agent_id, "group": group_of(agent_id), "policy": effective_policy(agent_id)}


@app.post("/agents/{agent_id}/group")
def dashboard_assign_group(agent_id: str, body: GroupAssign, request: Request,
                           role: str = Depends(dashboard_auth)) -> dict[str, Any]:
    if role != "admin":
        raise HTTPException(status_code=403, detail="Admin only")
    return assign_group(agent_id, body.group, actor_of(request))


# --------------------------------------------------------------------------- audit log integrity and SIEM
def verify_audit_chain() -> dict[str, Any]:
    with _db_lock:
        conn = db()
        try:
            return audit.verify(conn, AUDIT_KEY)
        finally:
            conn.close()


@app.get("/api/v1/admin/audit/verify")
def api_audit_verify(_role: str = Depends(viewer_auth)) -> dict[str, Any]:
    return verify_audit_chain()


@app.get("/api/v1/admin/siem")
def api_siem_status(_role: str = Depends(viewer_auth)) -> dict[str, Any]:
    return {"enabled": _forwarder is not None, "format": SYSLOG_FORMAT, **(_forwarder.status() if _forwarder else {})}


# --------------------------------------------------------------------------- single sign-on
def _redirect_uri(request: Request) -> str:
    base = PUBLIC_URL or str(request.base_url).rstrip("/")
    return base + "/auth/callback"


def _secure_cookie(request: Request) -> bool:
    return request.url.scheme == "https" or PUBLIC_URL.startswith("https://")


def _safe_next(raw: str | None) -> str:
    return raw if raw and raw.startswith("/") and not raw.startswith("//") and "\\" not in raw else "/"


@app.get("/login", response_model=None)
def sso_login(request: Request, next: str = "/") -> Response:
    if _oidc is None:
        raise HTTPException(status_code=404, detail="Single sign-on is not configured")
    st = sso.new_login()
    try:
        url = _oidc.authorize_url(_redirect_uri(request), st["state"], st["nonce"], st["verifier"])
    except Exception as exc:  # noqa: BLE001 - provider unreachable / misconfigured
        raise HTTPException(status_code=502, detail=f"Identity provider error: {exc}") from exc
    resp = Response(status_code=303, headers={"Location": url})
    resp.set_cookie(LOGIN_COOKIE, sso.sign({**st, "next": _safe_next(next), "exp": datetime.now(timezone.utc).timestamp() + 600},
                                            SESSION_SECRET),
                    max_age=600, httponly=True, secure=_secure_cookie(request), samesite="lax", path="/auth")
    return resp


@app.get("/auth/callback", response_model=None)
def sso_callback(request: Request, code: str = "", state: str = "", error: str = "") -> Response:
    if _oidc is None:
        raise HTTPException(status_code=404, detail="Single sign-on is not configured")
    login = sso.unsign(request.cookies.get(LOGIN_COOKIE), SESSION_SECRET)
    if error:
        raise HTTPException(status_code=401, detail=f"Sign-in was cancelled or refused: {error[:100]}")
    if not login or not code or not secrets.compare_digest(str(login.get("state", "")), state):
        raise HTTPException(status_code=400, detail="Sign-in session expired; start again at /login")
    try:
        claims = _oidc.verify(_oidc.exchange(code, _redirect_uri(request), str(login["verifier"])), str(login["nonce"]))
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=401, detail=f"Sign-in failed: {exc}") from exc
    email = sso.email_of(claims)
    role = sso.role_for(email, OIDC_ADMINS, OIDC_VIEWERS)
    if role is None:
        record_admin_action(f"sso:{email or 'unknown'}", "login_denied")
        raise HTTPException(status_code=403, detail=f"{email or 'This account'} is not allowed to use this dashboard")
    record_admin_action(f"sso:{email}", "login", f"role={role}")
    resp = Response(status_code=303, headers={"Location": _safe_next(str(login.get("next")))})
    exp = datetime.now(timezone.utc).timestamp() + SESSION_HOURS * 3600
    resp.set_cookie(SESSION_COOKIE, sso.sign({"sub": email, "role": role, "exp": exp}, SESSION_SECRET),
                    max_age=SESSION_HOURS * 3600, httponly=True, secure=_secure_cookie(request), samesite="lax", path="/")
    resp.delete_cookie(LOGIN_COOKIE, path="/auth")
    return resp


@app.get("/logout", response_class=HTMLResponse)
def sso_logout() -> HTMLResponse:
    resp = HTMLResponse("<!doctype html><title>Signed out</title><p>You are signed out of OpenDLP. "
                        "<a href=\"/login\">Sign in again</a></p>")
    resp.delete_cookie(SESSION_COOKIE, path="/")
    return resp


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}
