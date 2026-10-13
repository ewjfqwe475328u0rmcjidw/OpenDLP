"""Outbound e-mail scanning against fake Microsoft Graph / Gmail APIs (no network)."""
import base64
import json
import urllib.parse
from datetime import datetime, timedelta, timezone

import emailscan
from test_cloudscan import FPS, RULES, SECRET, _unb64, sa  # noqa: F401 - pytest fixture

SINCE = datetime(2026, 10, 1, tzinfo=timezone.utc)
CARD_BODY = "<p>Hi, the card is 4111 1111 1111 1111 &amp; expires 12/29</p>"


def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def m365_fake(calls):
    def http(method, url, headers, body):
        calls.append(url)
        if "login.microsoftonline.com" in url:
            return 200, json.dumps({"access_token": "graph"}).encode()
        u = urllib.parse.urlparse(url)
        if u.path == "/v1.0/users":
            return 200, json.dumps({"value": [
                {"id": "u1", "userPrincipalName": "Alice@acme.test", "mail": "alice@acme.test"},
                {"id": "u2", "userPrincipalName": "nomail@acme.test"},
                {"id": "u3", "userPrincipalName": "off@acme.test", "accountEnabled": False},
            ]}).encode()
        if u.path == "/v1.0/users/u2/mailFolders/SentItems/messages":
            return 404, b""
        if u.path == "/v1.0/users/u1/mailFolders/SentItems/messages":
            q = urllib.parse.parse_qs(u.query)
            assert q["$filter"] == ["sentDateTime ge 2026-10-01T00:00:00Z"] and "%20" in u.query
            if "$skiptoken" in q:
                return 200, json.dumps({"value": [
                    {"id": "m3", "subject": "Board deck", "sentDateTime": "2026-10-02T10:00:00Z", "hasAttachments": True,
                     "toRecipients": [{"emailAddress": {"address": "rival@competitor.test"}}], "body": {"contentType": "text", "content": "fyi"}},
                ]}).encode()
            return 200, json.dumps({"value": [
                {"id": "m1", "subject": "Payment", "sentDateTime": "2026-10-02T09:00:00Z", "hasAttachments": False,
                 "toRecipients": [{"emailAddress": {"address": "Friend@Gmail.test"}}],
                 "ccRecipients": [{"emailAddress": {"address": "bob@acme.test"}}],
                 "body": {"contentType": "html", "content": CARD_BODY}},
                {"id": "m2", "subject": "Internal only", "sentDateTime": "2026-10-02T09:30:00Z", "hasAttachments": False,
                 "toRecipients": [{"emailAddress": {"address": "bob@acme.test"}}], "body": {"contentType": "text", "content": "4111 1111 1111 1111"}},
            ], "@odata.nextLink": "https://graph.microsoft.com/v1.0/users/u1/mailFolders/SentItems/messages?$filter=sentDateTime%20ge%202026-10-01T00:00:00Z&$skiptoken=x"}).encode()
        if u.path == "/v1.0/users/u1/messages/m3/attachments":
            return 200, json.dumps({"value": [
                {"@odata.type": "#microsoft.graph.fileAttachment", "name": "notes.txt", "size": len(SECRET),
                 "contentBytes": base64.b64encode(SECRET).decode()},
                {"@odata.type": "#microsoft.graph.itemAttachment", "name": "forwarded mail"},
            ]}).encode()
        raise AssertionError(f"unexpected call {url}")
    return http


def test_m365_reports_only_external_mail_with_sensitive_content():
    calls = []
    res = emailscan.scan_m365("t", "c", "s", SINCE, set(), RULES, FPS, m365_fake(calls))
    assert (res.users, res.messages, res.external_messages, res.errors) == (2, 3, 2, [])
    assert len(res.findings) == 2
    card, deck = res.findings
    msg = card.message()
    assert "CREDIT-CARD" in msg and "to=friend@gmail.test" in msg and "bob@acme.test" not in msg
    assert 'subject="Payment"' in msg and "4111 1111 1111 1111" not in msg
    assert deck.fingerprint == "Board plan" and 'attachments="notes.txt"' in deck.message()
    assert "severity=critical" in deck.message()
    assert not any("/messages/m1/attachments" in c for c in calls)  # no attachments fetched when there are none
    assert all(c.startswith(("https://graph.microsoft.com", "https://login.microsoftonline.com")) for c in calls)
    assert not any(m in c for c in calls for m in ("/send", "/move", "/delete"))  # read-only


def test_internal_domains_setting_treats_partner_domains_as_internal():
    res = emailscan.scan_m365("t", "c", "s", SINCE, {"acme.test", "gmail.test", "competitor.test"}, RULES, FPS, m365_fake([]))
    assert res.external_messages == 0 and res.findings == []


def gmail_fake(pub):
    from test_cloudscan import google_fake

    base = google_fake(pub, [])
    plain = "SSN 123-45-6789 for payroll"

    def http(method, url, headers, body):
        u = urllib.parse.urlparse(url)
        auth = headers.get("Authorization", "")
        if u.netloc != "gmail.googleapis.com":
            if u.path == "/drive/v3/files":
                raise AssertionError("drive must not be called")
            return base(method, url, headers, body)
        assert auth.endswith("gmail.readonly")
        if "bob@acme.test" in auth:
            return 500, b"boom"
        if u.path == "/gmail/v1/users/me/messages":
            q = urllib.parse.parse_qs(u.query)
            assert q["q"] == [f"in:sent after:{int(SINCE.timestamp())}"]
            return 200, json.dumps({"messages": [{"id": "g1"}, {"id": "g2"}]}).encode()
        if u.path == "/gmail/v1/users/me/messages/g1":
            return 200, json.dumps({"internalDate": "1790000000000", "payload": {
                "headers": [{"name": "To", "value": "HR Partner <hr@outsourcer.test>"}, {"name": "Subject", "value": "Payroll"}],
                "mimeType": "multipart/mixed", "parts": [
                    {"mimeType": "multipart/alternative", "parts": [
                        {"mimeType": "text/plain", "body": {"data": b64u(plain.encode())}},
                        {"mimeType": "text/html", "body": {"data": b64u(f"<b>{plain}</b>".encode())}},
                    ]},
                    {"mimeType": "text/plain", "filename": "plan.txt", "body": {"attachmentId": "a1", "size": len(SECRET)}},
                ]}}).encode()
        if u.path == "/gmail/v1/users/me/messages/g1/attachments/a1":
            return 200, json.dumps({"data": b64u(SECRET)}).encode()
        if u.path == "/gmail/v1/users/me/messages/g2":
            return 200, json.dumps({"payload": {"headers": [{"name": "To", "value": "carol@acme.test"}],
                                                "mimeType": "text/plain", "body": {"data": b64u(plain.encode())}}}).encode()
        raise AssertionError(f"unexpected call {url}")
    return http


def test_gmail_scan(sa):
    sa_json, pub = sa
    res = emailscan.scan_google(sa_json, "admin@acme.test", "acme.test", SINCE, set(), RULES, FPS, gmail_fake(pub))
    assert res.users == 2 and res.messages == 2 and res.external_messages == 1
    assert len(res.errors) == 1 and res.errors[0].startswith("bob@acme.test")
    (f,) = res.findings
    assert f.recipients == ["hr@outsourcer.test"] and f.fingerprint == "Board plan"
    assert "US-SSNx1" in f.message()  # plain + html alternative counted once
    assert f.sent_at.startswith("2026-09-21T") and f.sent_at.endswith("+00:00")


def test_server_records_email_findings_and_advances_window(monkeypatch, tmp_path):
    import main
    monkeypatch.setattr(main, "DB_PATH", tmp_path / "e.db")
    monkeypatch.setattr(main, "M365_TENANT", "t")
    monkeypatch.setattr(main, "M365_CLIENT_ID", "c")
    monkeypatch.setattr(main, "M365_SECRET", "s")
    monkeypatch.setattr(main, "GOOGLE_SA_FILE", "")
    monkeypatch.setattr(main, "WEBHOOK_URL", "")
    monkeypatch.setattr(main, "SMTP_HOST", "")
    monkeypatch.setattr(main, "EMAIL_SCAN", True)
    monkeypatch.setattr(main, "_forwarder", None)
    main.init_db()
    now = SINCE + timedelta(hours=24)
    out = main.run_email_scan(http=m365_fake([]), now=now)
    assert out[0]["findings"] == 1 and out[0]["external"] == 2 and out[0]["since"] == SINCE.isoformat()
    assert main._meta_get("email_since_m365") == now.isoformat()
    conn = main.db()
    rows = [dict(r) for r in conn.execute("SELECT agent_id, ts, level, event_type, message FROM events ORDER BY id")]
    conn.close()
    assert [r["event_type"] for r in rows] == ["EMAIL_EXTERNAL_SENSITIVE", "EMAIL_SCAN_SUMMARY"]
    assert rows[0]["agent_id"] == "email-m365" and rows[0]["ts"].startswith("2026-10-02T09:00")
    assert main.verify_audit_chain()["ok"]
