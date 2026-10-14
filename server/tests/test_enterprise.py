"""Tamper-evident audit log, SIEM forwarding, group policies and OIDC single sign-on."""
import base64
import json
import socket
import socketserver
import threading
import time
from urllib.parse import parse_qs, urlparse

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

import audit
import main
import siem
import sso
from test_api import admin, client, headers, viewer  # noqa: F401 - pytest fixture

SAME = {"Origin": "http://testserver"}


def _send(c, token, agent="agent-test", events=None):
    events = events or [{"level": "ALERT", "eventType": "FILE_SENSITIVE", "message": "severity=high rules=EMAIL x1"}]
    r = c.post("/api/v1/telemetry", headers=headers(token, agent), json={"agentId": agent, "events": events})
    assert r.status_code == 200, r.text


# --------------------------------------------------------------------------- audit chain
def test_audit_chain_detects_edit_delete_and_truncation(client):
    c, token = client
    for i in range(5):
        _send(c, token, events=[{"message": f"event {i}"}])
    v = c.get("/api/v1/admin/audit/verify", headers=viewer()).json()
    assert v["ok"] and v["checked"] == 5 and v["keyed"]

    conn = main.db()
    ids = [r[0] for r in conn.execute("SELECT id FROM events ORDER BY id")]
    conn.execute("UPDATE events SET message = 'nothing to see' WHERE id = ?", (ids[2],))
    conn.commit()
    v = c.get("/api/v1/admin/audit/verify", headers=admin()).json()
    assert not v["ok"] and v["firstBadId"] == ids[2] and v["reason"] == "event modified"

    conn.execute("UPDATE events SET message = 'event 2' WHERE id = ?", (ids[2],))
    conn.commit()
    assert main.verify_audit_chain()["ok"]

    conn.execute("DELETE FROM events WHERE id = ?", (ids[1],))
    conn.commit()
    v = main.verify_audit_chain()
    assert not v["ok"] and v["firstBadId"] == ids[1]
    conn.close()


def test_audit_chain_detects_deleted_newest_rows_and_survives_retention(client, monkeypatch):
    c, token = client
    for i in range(4):
        _send(c, token, events=[{"message": f"event {i}"}])
    conn = main.db()
    last = conn.execute("SELECT MAX(id) FROM events").fetchone()[0]
    conn.execute("UPDATE events SET received_at = '2000-01-01T00:00:00+00:00' WHERE id < ?", (last - 1,))
    conn.commit()
    monkeypatch.setattr(main, "EVENT_RETENTION_DAYS", 30)
    assert main.purge_old_events() == 2
    assert main.verify_audit_chain() == {**main.verify_audit_chain(), "ok": True, "checked": 2}

    conn.execute("DELETE FROM events WHERE id = ?", (last,))
    conn.commit()
    conn.close()
    v = main.verify_audit_chain()
    assert not v["ok"] and v["reason"] == "newest events missing"


def test_audit_chain_cannot_be_rebuilt_without_the_key(client):
    c, token = client
    _send(c, token, events=[{"message": "real"}])
    conn = main.db()
    row = conn.execute("SELECT id, agent_id, ts, level, event_type, message, host, received_at FROM events").fetchone()
    forged = (row[1], row[2], row[3], row[4], "forged", row[6], row[7])
    conn.execute("UPDATE events SET message = 'forged', chain = ? WHERE id = ?", (audit.link(b"", audit.GENESIS, forged), row[0]))
    conn.execute("UPDATE meta SET value = ? WHERE key = 'audit_head'", (audit.link(b"", audit.GENESIS, forged),))
    conn.commit()
    conn.close()
    assert not main.verify_audit_chain()["ok"]


def test_admin_actions_are_logged_with_actor(client):
    c, _ = client
    fp = "ab" * 32
    assert c.post("/fingerprints", auth=("admin", "dash-pass"), headers=SAME, json={"sha256": fp, "name": "deck.pptx"}).status_code == 200
    c.post("/api/v1/admin/agents/nobody/revoke", headers=admin())  # 404, not logged
    ev = c.get("/api/v1/events?event_type=ADMIN_ACTION", headers=admin()).json()
    assert len(ev) == 1 and ev[0]["agent_id"] == "server"
    assert "actor=admin action=fingerprint_add" in ev[0]["message"] and fp in ev[0]["message"]
    assert main.verify_audit_chain()["ok"]
    page = c.get("/", auth=("admin", "dash-pass")).text
    assert "Intact" in page and "signed in as admin" in page


# --------------------------------------------------------------------------- SIEM
class _Udp:
    def __init__(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.settimeout(5)
        self.port = self.sock.getsockname()[1]

    def recv(self) -> str:
        return self.sock.recvfrom(70000)[0].decode()


def test_cef_format_escapes_and_maps_severity():
    ev = {"id": 7, "agent_id": "pc|1", "ts": "2026-01-01T00:00:00+00:00", "level": "ALERT", "event_type": "USB_BLOCK",
          "message": "a=b\nc\\d", "host": "HOST", "chain": "ff"}
    cef = siem.format_cef(ev, "critical", "0.14.0")
    assert cef.startswith("CEF:0|Leakwarden|Leakwarden|0.14.0|USB_BLOCK|USB_BLOCK|10|")
    assert "msg=a\\=b\\nc\\\\d" in cef and "deviceExternalId=pc|1" in cef and "cs3=ff" in cef
    line = siem.syslog_line(ev, cef).decode()
    assert line.startswith("<81>1 ") and " leakwarden - USB_BLOCK - CEF:0|" in line
    assert json.loads(siem.format_json(ev, "critical", ""))["severity"] == "critical"
    with pytest.raises(ValueError):
        siem.Forwarder("http://siem:514")


def test_events_are_forwarded_over_udp(client, monkeypatch):
    c, token = client
    srv = _Udp()
    fwd = siem.Forwarder(f"udp://127.0.0.1:{srv.port}", "cef", "0.14.0")
    monkeypatch.setattr(main, "_forwarder", fwd)
    _send(c, token, events=[{"level": "ALERT", "eventType": "CLIPBOARD_BLOCK", "message": "severity=critical rules=CREDIT_CARDx1"}])
    got = srv.recv()
    assert "|CLIPBOARD_BLOCK|CLIPBOARD_BLOCK|10|" in got and "deviceExternalId=agent-test" in got and "cs3Label=auditChain" in got
    st = c.get("/api/v1/admin/siem", headers=viewer()).json()
    assert st["enabled"] and st["sent"] == 1 and st["dropped"] == 0
    fwd.close()


def test_tcp_forwarding_uses_octet_counting_and_reconnects():
    received: list[bytes] = []

    class H(socketserver.BaseRequestHandler):
        def handle(self):
            buf = b""
            while True:
                data = self.request.recv(4096)
                if not data:
                    break
                buf += data
            received.append(buf)

    srv = socketserver.ThreadingTCPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    fwd = siem.Forwarder(f"tcp://127.0.0.1:{srv.server_address[1]}", "json")
    for i in range(3):
        fwd.submit({"id": i, "level": "INFO", "event_type": "T", "message": f"m{i}"}, "")
    fwd.flush()
    fwd._sock.close()  # end the stream so the handler returns
    deadline = time.time() + 5
    while not received and time.time() < deadline:
        time.sleep(0.05)
    srv.shutdown()
    data = received[0]
    frames = []
    while data:
        n, rest = data.split(b" ", 1)
        frames.append(rest[: int(n)])
        data = rest[int(n):]
    assert [json.loads(f.split(b" - ", 2)[2])["message"] for f in frames] == ["m0", "m1", "m2"]
    fwd.close()


def test_unreachable_siem_never_blocks_ingest(client, monkeypatch):
    c, token = client
    fwd = siem.Forwarder("tcp://127.0.0.1:1", "cef", max_queue=2)
    monkeypatch.setattr(main, "_forwarder", fwd)
    t = time.time()
    for _ in range(5):
        _send(c, token)
    assert time.time() - t < 3
    assert fwd.dropped >= 2
    fwd.close()


# --------------------------------------------------------------------------- group policies
def _policy(c, token, agent):
    r = c.get("/api/v1/policy", headers=headers(token, agent))
    assert r.status_code == 200
    return r.json()["version"], json.loads(r.json()["policyJson"])


def test_group_policy_overlay_and_assignment(client, monkeypatch):
    c, token = client
    monkeypatch.setattr(main, "POLICY_VERSION", None)
    main.POLICY_PATH.write_text(json.dumps({
        "rules": [{"id": "EMAIL", "type": "builtin", "detector": "email", "severity": "low"},
                  {"id": "CARD", "type": "builtin", "detector": "credit_card", "severity": "high"}],
        "usb": {"mode": "audit", "allowedSerials": ["S1"]},
    }), encoding="utf-8")
    for a in ("fin-01", "dev-01"):
        _send(c, token, agent=a, events=[{"message": "hello"}])
    v0, base = _policy(c, token, "fin-01")

    overlay = {"usb": {"mode": "block"}, "disableRules": ["EMAIL"],
               "rules": [{"id": "CARD", "type": "builtin", "detector": "credit_card", "severity": "critical", "action": "block"}]}
    assert c.put("/api/v1/admin/groups/Finance", headers=viewer(), json=overlay).status_code == 403
    assert c.put("/api/v1/admin/groups/Finance", headers=admin(), json={"usb": {"mode": "explode"}}).status_code == 422
    assert c.put("/api/v1/admin/groups/bad%2Fname", headers=admin(), json={}).status_code in (404, 422)
    assert c.put("/api/v1/admin/groups/Finance", headers=admin(), json=overlay).status_code == 200
    assert c.post("/api/v1/admin/agents/fin-01/group", headers=admin(), json={"group": "Nope"}).status_code == 404
    assert c.post("/api/v1/admin/agents/fin-01/group", headers=admin(), json={"group": "Finance"}).status_code == 200

    v1, fin = _policy(c, token, "fin-01")
    _, dev = _policy(c, token, "dev-01")
    assert v1 > v0
    assert fin["usb"] == {"mode": "block", "allowedSerials": ["S1"]}
    assert [r["id"] for r in fin["rules"]] == ["CARD"] and fin["rules"][0]["action"] == "block"
    assert dev["usb"]["mode"] == "audit" and len(dev["rules"]) == 2
    groups = c.get("/api/v1/admin/groups", headers=viewer()).json()
    assert groups[0]["name"] == "Finance" and groups[0]["agents"] == 1
    eff = c.get("/api/v1/admin/agents/fin-01/effective-policy", headers=viewer()).json()
    assert eff["group"] == "Finance" and eff["policy"]["usb"]["mode"] == "block"

    page = c.get("/", auth=("admin", "dash-pass")).text
    assert 'class="grp"' in page and "<option selected>Finance</option>" in page
    assert c.post("/agents/dev-01/group", auth=("viewer", "view-pass"), headers=SAME, json={"group": "Finance"}).status_code == 403
    assert c.post("/agents/dev-01/group", auth=("admin", "dash-pass"), headers=SAME, json={"group": "Finance"}).status_code == 200

    assert c.delete("/api/v1/admin/groups/Finance", headers=admin()).status_code == 200
    v2, fin = _policy(c, token, "fin-01")
    assert v2 > v1 and fin["usb"]["mode"] == "audit"
    assert c.get("/api/v1/admin/groups", headers=admin()).json() == []
    actions = [e["message"] for e in c.get("/api/v1/events?event_type=ADMIN_ACTION", headers=admin()).json()]
    assert any("group_policy_update" in m for m in actions) and any("agent_group_assign" in m for m in actions)


def test_merge_policy_rules():
    base = {"rules": [{"id": "A", "x": 1}, {"id": "B"}], "browser": {"mode": "warn", "monitoredDomains": ["a"]}, "k": 1}
    out = main.merge_policy(base, {"rules": [{"id": "A", "x": 2}, {"id": "C"}], "browser": {"mode": "block"}, "k": 2})
    assert out == {"rules": [{"id": "A", "x": 2}, {"id": "B"}, {"id": "C"}],
                   "browser": {"mode": "block", "monitoredDomains": ["a"]}, "k": 2}
    assert base["rules"][0]["x"] == 1  # base untouched


# --------------------------------------------------------------------------- OIDC single sign-on
ISS = "https://idp.example.com/tenant"
CID = "leakwarden-client"


class FakeIdp:
    def __init__(self, alg="RS256"):
        self.alg = alg
        if alg == "RS256":
            self.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            n = self.key.public_key().public_numbers()
            self.jwk = {"kty": "RSA", "kid": "k1", "n": sso.b64u(n.n.to_bytes(256, "big")), "e": sso.b64u(n.e.to_bytes(3, "big"))}
        else:
            self.key = ec.generate_private_key(ec.SECP256R1())
            n = self.key.public_key().public_numbers()
            self.jwk = {"kty": "EC", "crv": "P-256", "kid": "k1", "x": sso.b64u(n.x.to_bytes(32, "big")), "y": sso.b64u(n.y.to_bytes(32, "big"))}
        self.claims = {}
        self.nonce = ""
        self.token_calls = []

    def id_token(self, **over):
        claims = {"iss": ISS, "aud": CID, "exp": time.time() + 300, "nonce": self.nonce, "email": "alice@acme.test", **self.claims, **over}
        h = sso.b64u(json.dumps({"alg": self.alg, "kid": "k1"}).encode())
        c = sso.b64u(json.dumps(claims).encode())
        data = f"{h}.{c}".encode()
        if self.alg == "RS256":
            sig = self.key.sign(data, padding.PKCS1v15(), hashes.SHA256())
        else:
            r, s = decode_dss_signature(self.key.sign(data, ec.ECDSA(hashes.SHA256())))
            sig = r.to_bytes(32, "big") + s.to_bytes(32, "big")
        return f"{h}.{c}.{sso.b64u(sig)}"

    def http(self, method, url, hdrs, body):
        if url == ISS + "/.well-known/openid-configuration":
            return 200, json.dumps({"issuer": ISS, "authorization_endpoint": ISS + "/authorize",
                                    "token_endpoint": ISS + "/token", "jwks_uri": ISS + "/keys"}).encode()
        if url == ISS + "/keys":
            return 200, json.dumps({"keys": [self.jwk]}).encode()
        if url == ISS + "/token" and method == "POST":
            form = parse_qs(body.decode())
            self.token_calls.append(form)
            if form.get("code") != ["good-code"] or not form.get("code_verifier"):
                return 400, b"{}"
            return 200, json.dumps({"id_token": self.id_token()}).encode()
        return 404, b""


@pytest.fixture()
def sso_client(client, monkeypatch):
    c, token = client
    idp = FakeIdp()
    monkeypatch.setattr(main, "_oidc", sso.Provider(ISS, CID, "secret", idp.http))
    monkeypatch.setattr(main, "OIDC_ADMINS", "alice@acme.test")
    monkeypatch.setattr(main, "OIDC_VIEWERS", "@acme.test")
    return c, idp


def _login(c, idp, next_path="/"):
    r = c.get(f"/login?next={next_path}", follow_redirects=False)
    assert r.status_code == 303
    q = parse_qs(urlparse(r.headers["location"]).query)
    assert r.headers["location"].startswith(ISS + "/authorize?")
    assert q["code_challenge_method"] == ["S256"] and q["client_id"] == [CID]
    assert q["redirect_uri"] == ["http://testserver/auth/callback"]
    idp.nonce = q["nonce"][0]
    return q["state"][0]


def test_sso_full_flow_admin(sso_client):
    c, idp = sso_client
    r = c.get("/fingerprints", follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/login?next=/fingerprints"
    state = _login(c, idp, "/fingerprints")
    r = c.get(f"/auth/callback?code=good-code&state={state}", follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/fingerprints"
    assert "httponly" in r.headers["set-cookie"].lower()
    page = c.get("/").text
    assert "signed in as sso:alice@acme.test" in page and "Sign out" in page
    # cookie session can change things only from our own pages
    fp = "cd" * 32
    assert c.post("/fingerprints", json={"sha256": fp, "name": "x"}).status_code == 403
    assert c.post("/fingerprints", headers=SAME, json={"sha256": fp, "name": "x"}).status_code == 200
    msgs = [e["message"] for e in c.get("/api/v1/events?event_type=ADMIN_ACTION", headers=admin()).json()]
    assert any("actor=sso:alice@acme.test action=login role=admin" in m for m in msgs)
    assert any("actor=sso:alice@acme.test action=fingerprint_add" in m for m in msgs)
    c.get("/logout")
    assert c.get("/", follow_redirects=False).status_code == 303
    # Basic auth still works as a break-glass account
    assert c.get("/", auth=("admin", "dash-pass")).status_code == 200


def test_sso_viewer_and_refused_users(sso_client):
    c, idp = sso_client
    idp.claims = {"email": "bob@acme.test"}
    state = _login(c, idp)
    c.get(f"/auth/callback?code=good-code&state={state}", follow_redirects=False)
    assert "viewer" in c.get("/").text
    assert c.post("/fingerprints", headers=SAME, json={"sha256": "ef" * 32, "name": "x"}).status_code == 403
    c.cookies.clear()

    idp.claims = {"email": "eve@evil.test"}
    state = _login(c, idp)
    r = c.get(f"/auth/callback?code=good-code&state={state}", follow_redirects=False)
    assert r.status_code == 403
    msgs = [e["message"] for e in c.get("/api/v1/events?event_type=ADMIN_ACTION", headers=admin()).json()]
    assert any("sso:eve@evil.test action=login_denied" in m for m in msgs)

    idp.claims = {"email": "alice@acme.test", "email_verified": False, "preferred_username": "mallory@evil.test"}
    state = _login(c, idp)
    assert c.get(f"/auth/callback?code=good-code&state={state}", follow_redirects=False).status_code == 403


@pytest.mark.parametrize("bad", [
    {"aud": "someone-else"}, {"iss": "https://other.example"}, {"exp": time.time() - 3600}, {"nonce": "replayed"},
])
def test_sso_rejects_bad_tokens(sso_client, bad):
    c, idp = sso_client
    idp.claims = bad
    state = _login(c, idp)
    assert c.get(f"/auth/callback?code=good-code&state={state}", follow_redirects=False).status_code == 401
    assert c.get("/", follow_redirects=False).status_code == 303


def test_sso_rejects_wrong_state_and_forged_signature(sso_client, monkeypatch):
    c, idp = sso_client
    _login(c, idp)
    assert c.get("/auth/callback?code=good-code&state=attacker", follow_redirects=False).status_code == 400
    state = _login(c, idp)
    other = FakeIdp()
    other.nonce = idp.nonce
    monkeypatch.setattr(idp, "id_token", other.id_token)  # signed by a key the IdP never published
    assert c.get(f"/auth/callback?code=good-code&state={state}", follow_redirects=False).status_code == 401
    # open redirect protection
    assert main._safe_next("//evil.example") == "/" and main._safe_next("https://evil.example") == "/"


def test_es256_tokens_and_cookie_tampering():
    idp = FakeIdp("ES256")
    p = sso.Provider(ISS, CID, "s", idp.http)
    idp.nonce = "n1"
    assert p.verify(idp.id_token(), "n1")["email"] == "alice@acme.test"
    secret = b"k" * 32
    cookie = sso.sign({"sub": "a", "role": "viewer", "exp": time.time() + 60}, secret)
    assert sso.unsign(cookie, secret)["role"] == "viewer"
    body, mac = cookie.split(".")
    forged = base64.urlsafe_b64encode(json.dumps({"sub": "a", "role": "admin", "exp": time.time() + 60}).encode()).rstrip(b"=").decode()
    assert sso.unsign(f"{forged}.{mac}", secret) is None
    assert sso.unsign(sso.sign({"exp": time.time() - 1}, secret), secret) is None
    assert sso.role_for("Alice@Acme.test", "alice@acme.test", "") == "admin"
    assert sso.role_for("x@acme.test.evil", "", "@acme.test") is None


def test_monthly_report_states_audit_integrity(client):
    import io
    from pypdf import PdfReader

    c, token = client
    _send(c, token)

    def text():
        data = c.get("/api/v1/reports/monthly.pdf", headers=viewer()).content
        return " ".join(p.extract_text() for p in PdfReader(io.BytesIO(data)).pages)

    assert "Audit log integrity" in text() and "Verified." in text()
    conn = main.db()
    conn.execute("UPDATE events SET message = 'x'")
    conn.commit()
    conn.close()
    assert "Integrity check FAILED" in text()
