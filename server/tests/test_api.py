import hashlib
import hmac
import json

import pytest
from fastapi.testclient import TestClient

import main


ADMIN = "admin-token-that-is-long-and-random-enough"
VIEWER = "viewer-token-that-is-long-and-random-enough"
ENROLL = "enroll-code-1234567890"


def viewer():
    return {"Authorization": f"Bearer {VIEWER}"}


def admin():
    return {"Authorization": f"Bearer {ADMIN}"}


@pytest.fixture()
def client(tmp_path, monkeypatch):
    token = "test-token-that-is-long-and-random-enough"
    monkeypatch.setattr(main, "API_TOKEN", token)
    monkeypatch.setattr(main, "DB_PATH", tmp_path / "test.db")
    monkeypatch.setattr(main, "POLICY_PATH", tmp_path / "policy.json")
    monkeypatch.setattr(main, "POLICY_VERSION", 1)
    monkeypatch.setattr(main, "ADMIN_TOKEN", ADMIN)
    monkeypatch.setattr(main, "AGENT_TOKENS_PATH", "")
    monkeypatch.setattr(main, "DASHBOARD_PASSWORD", "dash-pass")
    monkeypatch.setattr(main, "DASHBOARD_INSECURE", False)
    monkeypatch.setattr(main, "ENROLL_CODE", ENROLL)
    monkeypatch.setattr(main, "VIEWER_TOKEN", VIEWER)
    monkeypatch.setattr(main, "DASHBOARD_VIEWER_PASSWORD", "view-pass")
    monkeypatch.setattr(main, "WEBHOOK_URL", "")
    monkeypatch.setattr(main, "SMTP_HOST", "")
    main._token_cache.clear()
    main._notify_last.clear()
    main.POLICY_PATH.write_text(json.dumps({"rules": [], "usb": {"mode": "audit"}}, ensure_ascii=False), encoding="utf-8")
    main.init_db()
    return TestClient(main.app), token


def headers(token, agent_id="agent-test"):
    return {"Authorization": f"Bearer {token}", "X-Agent-Id": agent_id}


def test_api_requires_token(client):
    c, _ = client
    response = c.get("/api/v1/agents")
    assert response.status_code == 401
    assert c.post("/api/v1/telemetry", json={"agentId": "a", "events": []}).status_code == 401


def test_telemetry_rejects_agent_id_mismatch(client):
    c, token = client
    response = c.post("/api/v1/telemetry", headers=headers(token, "agent-a"), json={"agentId": "agent-b", "events": []})
    assert response.status_code == 403


def test_telemetry_accepts_matching_agent_id(client):
    c, token = client
    response = c.post("/api/v1/telemetry", headers=headers(token), json={"agentId": "agent-test", "events": [{"level": "INFO", "eventType": "TEST", "message": "hello"}]})
    assert response.status_code == 200
    assert response.json()["inserted"] == 1

def test_policy_signature_matches_agent_scheme(client):
    c, token = client
    response = c.get("/api/v1/policy?version=0", headers=headers(token))
    assert response.status_code == 200
    envelope = response.json()
    key = hashlib.sha256(token.encode()).hexdigest().encode()
    expected = hmac.new(key, envelope["policyJson"].encode(), hashlib.sha256).hexdigest()
    assert hmac.compare_digest(envelope["sig"], expected)

def test_policy_returns_not_modified_for_current_version(client):
    c, token = client
    response = c.get("/api/v1/policy?version=1", headers=headers(token))
    assert response.status_code == 304


def test_api_fails_closed_when_server_token_is_unset(client, monkeypatch):
    c, _ = client
    monkeypatch.setattr(main, "API_TOKEN", "")
    response = c.get("/api/v1/policy", headers={"X-Agent-Id": "agent-test"})
    assert response.status_code == 503


def test_api_rejects_wrong_token(client):
    c, _ = client
    response = c.get("/api/v1/policy", headers=headers("wrong-token"))
    assert response.status_code == 403


def test_api_requires_agent_id_header(client):
    c, token = client
    response = c.get("/api/v1/policy", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 400


def test_telemetry_rejects_oversized_batch(client):
    c, token = client
    events = [{"eventType": "TEST", "message": "x"} for _ in range(main.MAX_EVENTS_PER_BATCH + 1)]
    response = c.post("/api/v1/telemetry", headers=headers(token), json={"agentId": "agent-test", "events": events})
    assert response.status_code == 422


def test_policy_missing_file_returns_server_error(client):
    c, token = client
    main.POLICY_PATH.unlink()
    response = c.get("/api/v1/policy?version=0", headers=headers(token))
    assert response.status_code == 500


def test_api_fails_closed_for_weak_server_token(client, monkeypatch):
    c, _ = client
    monkeypatch.setattr(main, "API_TOKEN", "weak-token")
    response = c.get("/api/v1/policy", headers=headers("weak-token"))
    assert response.status_code == 503


def test_dashboard_requires_password(client):
    c, _ = client
    assert c.get("/").status_code == 401
    assert c.get("/", auth=("admin", "wrong")).status_code == 401


def test_dashboard_renders_with_password(client):
    c, _ = client
    response = c.get("/", auth=("admin", "dash-pass"))
    assert response.status_code == 200
    assert "OpenDLP" in response.text


def test_dashboard_disabled_by_default(client, monkeypatch):
    c, _ = client
    monkeypatch.setattr(main, "DASHBOARD_PASSWORD", "")
    assert c.get("/").status_code == 404


def test_dashboard_escapes_event_content(client):
    c, token = client
    c.post("/api/v1/telemetry", headers=headers(token), json={"agentId": "agent-test", "events": [
        {"level": "ALERT", "eventType": "XSS", "message": "<script>alert(1)</script>"}]})
    html = c.get("/", auth=("admin", "dash-pass")).text
    assert "<script>alert(1)</script>" not in html


def test_agent_token_cannot_read_events(client):
    c, token = client
    assert c.get("/api/v1/events", headers=headers(token)).status_code == 403
    assert c.get("/api/v1/agents", headers=headers(token)).status_code == 403


def test_admin_can_read_events_and_agents(client):
    c, token = client
    c.post("/api/v1/telemetry", headers=headers(token), json={"agentId": "agent-test", "events": [
        {"level": "alert", "eventType": "T", "message": "m"}]})
    events = c.get("/api/v1/events", headers=admin()).json()
    assert events[0]["level"] == "ALERT"
    assert c.get("/api/v1/agents", headers=admin()).json()[0]["agent_id"] == "agent-test"


def test_admin_endpoints_fail_closed_without_admin_token(client, monkeypatch):
    c, _ = client
    monkeypatch.setattr(main, "ADMIN_TOKEN", "")
    assert c.get("/api/v1/events", headers=admin()).status_code == 503


def test_telemetry_sanitises_bad_fields(client):
    c, token = client
    c.post("/api/v1/telemetry", headers=headers(token), json={"agentId": "agent-test", "events": [
        {"ts": "not-a-date", "level": "weird", "eventType": "E" * 500, "message": "x" * 20000, "host": "h" * 500}]})
    ev = c.get("/api/v1/events", headers=admin()).json()[0]
    assert ev["level"] == "INFO"
    assert len(ev["event_type"]) == 64
    assert len(ev["message"]) == main.MAX_MESSAGE_LEN
    assert len(ev["host"]) == 128
    assert ev["ts"] != "not-a-date"


def test_oversized_body_rejected(client, monkeypatch):
    c, token = client
    monkeypatch.setattr(main, "MAX_BODY_BYTES", 100)
    r = c.post("/api/v1/telemetry", headers=headers(token), json={"agentId": "agent-test", "events": [{"message": "x" * 500}]})
    assert r.status_code == 413


def test_per_agent_tokens(client, monkeypatch, tmp_path):
    c, shared = client
    reg = tmp_path / "tokens.json"
    own = "agent-a-own-token-long-and-random-1234567"
    reg.write_text(json.dumps({"agent-a": own}))
    monkeypatch.setattr(main, "AGENT_TOKENS_PATH", str(reg))
    # registered agent: shared token no longer works, own token does
    assert c.get("/api/v1/policy", headers=headers(shared, "agent-a")).status_code == 403
    r = c.get("/api/v1/policy", headers=headers(own, "agent-a"))
    assert r.status_code == 200
    key = hashlib.sha256(own.encode()).hexdigest().encode()
    assert hmac.compare_digest(r.json()["sig"], hmac.new(key, r.json()["policyJson"].encode(), hashlib.sha256).hexdigest())
    # an agent's own token cannot be used to impersonate another agent
    assert c.get("/api/v1/policy", headers=headers(own, "agent-b")).status_code == 403


def test_policy_validation_rejects_bad_policy(client):
    c, token = client
    main.POLICY_PATH.write_text(json.dumps({"rules": [{"id": "x", "type": "regex", "pattern": "(", "action": "nuke"}]}))
    r = c.get("/api/v1/policy?version=0", headers=headers(token))
    assert r.status_code == 500
    assert "validation" in r.json()["detail"]


def test_default_policy_is_valid():
    from pathlib import Path
    real = Path(__file__).resolve().parents[2] / "policies" / "default-policy.json"
    assert main.validate_policy(json.loads(real.read_text(encoding="utf-8"))) == []


def test_policy_version_defaults_to_mtime(client, monkeypatch):
    c, token = client
    monkeypatch.setattr(main, "POLICY_VERSION", None)
    v = c.get("/api/v1/policy?version=0", headers=headers(token)).json()["version"]
    assert v == int(main.POLICY_PATH.stat().st_mtime)
    assert c.get(f"/api/v1/policy?version={v}", headers=headers(token)).status_code == 304


def test_retention_purges_old_events(client, monkeypatch):
    c, token = client
    c.post("/api/v1/telemetry", headers=headers(token), json={"agentId": "agent-test", "events": [{"message": "old"}]})
    conn = main.db()
    conn.execute("UPDATE events SET received_at='2000-01-01T00:00:00+00:00'")
    conn.commit(); conn.close()
    monkeypatch.setattr(main, "EVENT_RETENTION_DAYS", 30)
    assert main.purge_old_events() == 1


def _seed(c, token):
    c.post("/api/v1/telemetry", headers=headers(token), json={"agentId": "agent-test", "events": [
        {"level": "ALERT", "eventType": "TW_ID", "message": "found 100%_match in report.docx"},
        {"level": "INFO", "eventType": "START", "message": "agent started"},
        {"level": "WARN", "eventType": "USB", "message": "=cmd|' /C calc'!A0"}]})


def test_event_filters(client):
    c, token = client
    _seed(c, token)
    ev = lambda **p: c.get("/api/v1/events", headers=admin(), params=p).json()
    assert len(ev()) == 3
    assert [e["event_type"] for e in ev(level="alert")] == ["TW_ID"]
    assert [e["event_type"] for e in ev(event_type="USB")] == ["USB"]
    assert [e["event_type"] for e in ev(q="report")] == ["TW_ID"]
    assert [e["event_type"] for e in ev(q="100%_")] == ["TW_ID"]   # LIKE wildcards are escaped
    assert ev(q="%") == [e for e in ev(q="%")] and len(ev(q="%")) == 1
    assert ev(agent_id="nobody") == []
    assert len(ev(since="2999-01-01T00:00:00Z")) == 0


def test_csv_export_neutralises_formulas(client):
    c, token = client
    _seed(c, token)
    r = c.get("/api/v1/events.csv", headers=admin())
    assert r.status_code == 200 and r.headers["content-type"].startswith("text/csv")
    assert "'=cmd" in r.text and ",=cmd" not in r.text
    assert c.get("/api/v1/events.csv", headers=headers(token)).status_code == 403


def test_agent_status_and_stats(client, monkeypatch):
    c, token = client
    _seed(c, token)
    a = c.get("/api/v1/agents", headers=admin()).json()[0]
    assert a["status"] == "online"
    monkeypatch.setattr(main, "OFFLINE_AFTER_SECONDS", -1)
    assert c.get("/api/v1/agents", headers=admin()).json()[0]["status"] == "offline"
    st = c.get("/api/v1/stats", headers=admin()).json()
    assert st["events_total"] == 3 and st["events_24h_by_level"]["ALERT"] == 1 and st["agents_total"] == 1


def test_admin_policy_roundtrip_and_validation(client, monkeypatch):
    c, token = client
    monkeypatch.setattr(main, "POLICY_VERSION", None)
    v1 = c.get("/api/v1/admin/policy", headers=admin()).json()["version"]
    new = {"rules": [{"id": "R1", "type": "keywords", "keywords": ["secret"], "severity": "high", "action": "alert"}]}
    r = c.put("/api/v1/admin/policy", headers=admin(), json=new)
    assert r.status_code == 200 and r.json()["version"] > v1
    assert main.POLICY_PATH.with_suffix(".json.bak").exists()
    # agents now receive the new policy, still correctly signed
    env = c.get(f"/api/v1/policy?version={v1}", headers=headers(token)).json()
    assert json.loads(env["policyJson"])["rules"][0]["id"] == "R1"
    # a second edit in the same second still bumps the version
    r2 = c.put("/api/v1/admin/policy", headers=admin(), json=new)
    assert r2.json()["version"] > r.json()["version"]
    # invalid policy rejected and file untouched
    bad = c.put("/api/v1/admin/policy", headers=admin(), json={"rules": [{"id": "X", "type": "regex", "pattern": "("}]})
    assert bad.status_code == 422
    assert json.loads(main.POLICY_PATH.read_text())["rules"][0]["id"] == "R1"
    # agents cannot edit policy
    assert c.put("/api/v1/admin/policy", headers=headers(token), json=new).status_code == 403


def test_dashboard_filters(client):
    c, token = client
    _seed(c, token)
    html = c.get("/", auth=("admin", "dash-pass"), params={"level": "ALERT"}).text
    assert "TW_ID" in html and "agent started" not in html


def test_policy_asymmetric_signature(client, monkeypatch, tmp_path):
    import base64
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec

    c, token = client
    key = ec.generate_private_key(ec.SECP256R1())
    pem = tmp_path / "sign.pem"
    pem.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    monkeypatch.setattr(main, "SIGNING_KEY_PATH", str(pem))
    env = c.get("/api/v1/policy?version=0", headers=headers(token)).json()
    assert "pubSig" in env
    key.public_key().verify(base64.b64decode(env["pubSig"]), env["policyJson"].encode(), ec.ECDSA(hashes.SHA256()))
    # HMAC still present for older agents
    assert env["sig"]


def test_policy_without_signing_key_has_no_pubsig(client):
    c, token = client
    env = c.get("/api/v1/policy?version=0", headers=headers(token)).json()
    assert "pubSig" not in env


def test_policy_fails_closed_on_bad_signing_key(client, monkeypatch, tmp_path):
    c, token = client
    bad = tmp_path / "bad.pem"
    bad.write_text("not a key")
    monkeypatch.setattr(main, "SIGNING_KEY_PATH", str(bad))
    assert c.get("/api/v1/policy?version=0", headers=headers(token)).status_code == 500


# ---------------------------------------------------------------- enrollment

def test_enroll_issues_per_agent_token_and_signs_policy(client):
    c, shared = client
    r = c.post("/api/v1/enroll", json={"agentId": "pc-01", "enrollmentCode": ENROLL, "host": "PC-01"})
    assert r.status_code == 200
    tok = r.json()["token"]
    # issued token works; shared token does not work for an enrolled agent
    env = c.get("/api/v1/policy?version=0", headers=headers(tok, "pc-01"))
    assert env.status_code == 200
    key = hashlib.sha256(tok.encode()).hexdigest().encode()
    assert hmac.compare_digest(env.json()["sig"], hmac.new(key, env.json()["policyJson"].encode(), hashlib.sha256).hexdigest())
    assert c.get("/api/v1/policy", headers=headers(shared, "pc-01")).status_code == 403
    # token hash, not token, is stored
    assert c.get("/api/v1/agents", headers=admin()).json()[0]["enrolled"] is True
    assert "token" not in c.get("/api/v1/agents", headers=admin()).json()[0]


def test_enroll_rejects_bad_code_and_disabled(client, monkeypatch):
    c, _ = client
    assert c.post("/api/v1/enroll", json={"agentId": "x", "enrollmentCode": "wrong"}).status_code == 403
    monkeypatch.setattr(main, "ENROLL_CODE", "")
    assert c.post("/api/v1/enroll", json={"agentId": "x", "enrollmentCode": ENROLL}).status_code == 503


def test_reenroll_rotates_token(client):
    c, _ = client
    t1 = c.post("/api/v1/enroll", json={"agentId": "pc-02", "enrollmentCode": ENROLL}).json()["token"]
    t2 = c.post("/api/v1/enroll", json={"agentId": "pc-02", "enrollmentCode": ENROLL}).json()["token"]
    assert t1 != t2
    assert c.get("/api/v1/policy", headers=headers(t1, "pc-02")).status_code == 403
    assert c.get("/api/v1/policy?version=0", headers=headers(t2, "pc-02")).status_code == 200


def test_revoke_and_unrevoke(client):
    c, _ = client
    tok = c.post("/api/v1/enroll", json={"agentId": "pc-03", "enrollmentCode": ENROLL}).json()["token"]
    assert c.post("/api/v1/admin/agents/pc-03/revoke", headers=admin()).status_code == 200
    assert c.get("/api/v1/policy?version=0", headers=headers(tok, "pc-03")).status_code == 403
    assert c.post("/api/v1/enroll", json={"agentId": "pc-03", "enrollmentCode": ENROLL}).status_code == 403
    assert c.get("/api/v1/agents", headers=admin()).json()[0]["status"] == "revoked"
    assert c.post("/api/v1/admin/agents/pc-03/unrevoke", headers=admin()).status_code == 200
    assert c.get("/api/v1/policy?version=0", headers=headers(tok, "pc-03")).status_code == 200
    assert c.post("/api/v1/admin/agents/nope/revoke", headers=admin()).status_code == 404
    assert c.post("/api/v1/admin/agents/pc-03/revoke", headers=viewer()).status_code == 403


def test_enrolled_token_survives_restart_cache_loss(client):
    c, _ = client
    tok = c.post("/api/v1/enroll", json={"agentId": "pc-04", "enrollmentCode": ENROLL}).json()["token"]
    main._token_cache.clear()  # simulate server restart
    r = c.get("/api/v1/policy?version=0", headers=headers(tok, "pc-04"))
    assert r.status_code == 200
    key = hashlib.sha256(tok.encode()).hexdigest().encode()
    assert hmac.compare_digest(r.json()["sig"], hmac.new(key, r.json()["policyJson"].encode(), hashlib.sha256).hexdigest())


def test_telemetry_records_host_and_version(client):
    c, token = client
    h = {**headers(token), "X-Agent-Version": "0.10.0"}
    c.post("/api/v1/telemetry", headers=h, json={"agentId": "agent-test", "events": [{"host": "DESKTOP-1", "message": "m"}]})
    a = c.get("/api/v1/agents", headers=admin()).json()[0]
    assert a["host"] == "DESKTOP-1" and a["agent_version"] == "0.10.0"


# ---------------------------------------------------------------- roles

def test_viewer_can_read_but_not_write(client):
    c, token = client
    _seed(c, token)
    assert c.get("/api/v1/events", headers=viewer()).status_code == 200
    assert c.get("/api/v1/stats", headers=viewer()).status_code == 200
    assert c.get("/api/v1/admin/policy", headers=viewer()).status_code == 200
    assert c.put("/api/v1/admin/policy", headers=viewer(), json={"rules": []}).status_code == 403
    assert c.delete("/api/v1/admin/agents/agent-test", headers=viewer()).status_code == 403
    assert c.delete("/api/v1/admin/agents/agent-test", headers=admin()).status_code == 200


def test_dashboard_viewer_login(client):
    c, _ = client
    html = c.get("/", auth=("viewer", "view-pass")).text
    assert "viewer" in html and "Critical alerts" in html
    assert c.get("/", auth=("viewer", "wrong")).status_code == 401


# ---------------------------------------------------------------- notifications

def test_notifications_dispatch_high_alerts_only(client, monkeypatch):
    c, token = client
    sent = []
    monkeypatch.setattr(main, "WEBHOOK_URL", "https://example.invalid/hook")
    monkeypatch.setattr(main, "deliver_webhook", lambda url, body: sent.append(body))
    orig = main.send_notifications

    def sync(alerts):  # run inline instead of a thread so the test can assert
        n = orig(alerts)
        import time
        for _ in range(50):
            if len(sent) >= n:
                break
            time.sleep(0.02)
        return n
    monkeypatch.setattr(main, "send_notifications", sync)

    c.post("/api/v1/telemetry", headers=headers(token), json={"agentId": "agent-test", "events": [
        {"level": "ALERT", "eventType": "CONTENT", "message": "severity=critical rules=API-KEYx1"},
        {"level": "ALERT", "eventType": "USB", "message": "severity=low removable drive"},
        {"level": "INFO", "eventType": "START", "message": "severity=critical not an alert"},
        {"level": "ALERT", "eventType": "CONTENT", "message": "severity=high duplicate within cooldown"}]})
    assert len(sent) == 1
    assert sent[0]["event_type"] == "CONTENT" and "CRITICAL" in sent[0]["text"]
    r = c.post("/api/v1/admin/notify/test", headers=admin())
    assert r.json()["webhook"] is True


def test_notification_failure_does_not_break_ingestion(client, monkeypatch):
    c, token = client
    monkeypatch.setattr(main, "WEBHOOK_URL", "https://example.invalid/hook")
    def boom(url, body): raise RuntimeError("down")
    monkeypatch.setattr(main, "deliver_webhook", boom)
    r = c.post("/api/v1/telemetry", headers=headers(token), json={"agentId": "agent-test", "events": [
        {"level": "ALERT", "eventType": "X", "message": "severity=critical boom"}]})
    assert r.status_code == 200 and r.json()["inserted"] == 1
