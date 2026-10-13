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

import report

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

_stop_scheduler = threading.Event()


def _report_scheduler() -> None:
    """Hourly: on/after the 1st, e-mail last month's PDF report once (if enabled)."""
    while not _stop_scheduler.wait(3600):
        run_monthly_report_job()


def run_monthly_report_job(now: datetime | None = None) -> str | None:
    if not (REPORT_EMAIL and SMTP_HOST and SMTP_TO):
        return None
    with _db_lock:
        conn = db()
        try:
            return report.maybe_send_monthly(conn, now or datetime.now(timezone.utc), ORG_NAME, deliver_report_email)
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


app = FastAPI(title="OpenDLP Central Server", version="0.12.0", lifespan=lifespan)
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
        cols = {r["name"] for r in conn.execute("PRAGMA table_info(agents)")}
        for col, ddl in (
            ("token_hash", "TEXT"),
            ("enrolled_at", "TEXT"),
            ("revoked", "INTEGER NOT NULL DEFAULT 0"),
            ("host", "TEXT"),
            ("agent_version", "TEXT"),
            ("display_name", "TEXT"),
        ):
            if col not in cols:
                conn.execute(f"ALTER TABLE agents ADD COLUMN {col} {ddl}")
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


def dashboard_auth(credentials: HTTPBasicCredentials | None = Depends(_basic)) -> str:
    """Returns 'admin' or 'viewer'."""
    if DASHBOARD_PASSWORD:
        if credentials is not None:
            if _token_ok(credentials.username, DASHBOARD_USER) and _token_ok(credentials.password, DASHBOARD_PASSWORD):
                return "admin"
            if DASHBOARD_VIEWER_PASSWORD and _token_ok(credentials.username, DASHBOARD_VIEWER_USER) and _token_ok(
                credentials.password, DASHBOARD_VIEWER_PASSWORD
            ):
                return "viewer"
        raise HTTPException(status_code=401, detail="Authentication required", headers={"WWW-Authenticate": "Basic"})
    if not DASHBOARD_INSECURE:
        raise HTTPException(
            status_code=404,
            detail="Dashboard disabled: set OPENDLP_DASHBOARD_PASSWORD (or OPENDLP_DASHBOARD_INSECURE=1 for local dev only)",
        )
    return "admin"


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
            conn.execute(
                "UPDATE agents SET host = COALESCE(NULLIF(?, ''), host), agent_version = COALESCE(?, agent_version) WHERE agent_id = ?",
                (seen_host, (x_agent_version or "")[:32] or None, payload.agentId),
            )
            conn.commit()
        finally:
            conn.close()

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
    usb_mode = (obj.get("usb") or {}).get("mode", "audit")
    if usb_mode not in {"audit", "block"}:
        errs.append("usb.mode must be 'audit' or 'block'")
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
                "SELECT agent_id, last_seen, last_event, enrolled_at, revoked, host, agent_version, display_name, "
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
    return {"version": POLICY_VERSION if POLICY_VERSION is not None else mtime, "policy": obj}


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
            "sev": sev,
            "charts": [
                {"id": "alerts24", "title": "Alerts per hour", "sub": "last 24 hours, UTC", "c": alerts_24h},
                {"id": "events7", "title": "Events per day", "sub": "last 7 days, UTC", "c": events_7d},
            ],
        },
    )


def _report_response(month: str | None) -> Response:
    try:
        with _db_lock:
            conn = db()
            try:
                label, pdf = report.build_monthly_report(conn, month, ORG_NAME)
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


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}
