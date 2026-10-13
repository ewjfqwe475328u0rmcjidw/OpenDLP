"""Cloud drive scanning against fake Google / Microsoft APIs (no network)."""
import base64
import hashlib
import json
import urllib.parse

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

import cloudscan

RULES = [
    {"id": "CREDIT-CARD", "type": "builtin", "detector": "credit_card", "severity": "high"},
    {"id": "US-SSN", "type": "builtin", "detector": "us_ssn", "requireContext": True, "severity": "high"},
]
SECRET = b"Project Falcon - acquisition target list"
FPS = {hashlib.sha256(SECRET).hexdigest(): "Board plan"}


def _unb64(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


@pytest.fixture()
def sa():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()).decode()
    return {"client_email": "scanner@proj.iam.gserviceaccount.com", "private_key": pem,
            "token_uri": "https://oauth2.googleapis.com/token"}, key.public_key()


def google_fake(pub, calls):
    def http(method, url, headers, body):
        calls.append(url)
        u = urllib.parse.urlparse(url)
        q = urllib.parse.parse_qs(u.query)
        if url == "https://oauth2.googleapis.com/token":
            form = urllib.parse.parse_qs(body.decode())
            h, c, s = form["assertion"][0].split(".")
            pub.verify(_unb64(s), f"{h}.{c}".encode(), padding.PKCS1v15(), hashes.SHA256())  # real signature check
            claims = json.loads(_unb64(c))
            assert claims["iss"] == "scanner@proj.iam.gserviceaccount.com"
            return 200, json.dumps({"access_token": "tok:" + claims["sub"] + ":" + claims["scope"].rsplit("/", 1)[-1]}).encode()
        auth = headers.get("Authorization", "")
        if u.path == "/admin/directory/v1/users":
            assert auth.endswith("admin.directory.user.readonly") and "admin@acme.test" in auth
            if "pageToken" not in q:
                return 200, json.dumps({"users": [{"primaryEmail": "alice@acme.test"}, {"primaryEmail": "gone@acme.test", "suspended": True}],
                                        "nextPageToken": "p2"}).encode()
            return 200, json.dumps({"users": [{"primaryEmail": "bob@acme.test"}]}).encode()
        if u.path == "/drive/v3/files":
            assert "visibility = 'anyoneWithLink'" in q["q"][0]
            if "alice@acme.test" in auth:
                return 200, json.dumps({"files": [
                    {"id": "d1", "name": "Customer cards", "mimeType": "application/vnd.google-apps.spreadsheet", "webViewLink": "https://docs.google.com/d1"},
                    {"id": "f2", "name": "holiday.txt", "mimeType": "text/plain", "size": str(len(SECRET)), "webViewLink": "https://drive.google.com/f2"},
                    {"id": "f3", "name": "menu.txt", "mimeType": "text/plain", "size": "20", "webViewLink": "https://drive.google.com/f3"},
                ]}).encode()
            return 500, b"boom"   # bob: per-user error must not stop the scan
        if u.path == "/drive/v3/files/d1/export":
            assert q["mimeType"] == ["text/csv"]
            return 200, b"name,card\nAlice,4111 1111 1111 1111\n"
        if u.path == "/drive/v3/files/f2":
            return 200, SECRET
        if u.path == "/drive/v3/files/f3":
            return 200, b"pizza and salad"
        raise AssertionError("unexpected call " + url)
    return http


def test_google_scan_finds_public_sensitive_files(sa):
    info, pub = sa
    calls = []
    res = cloudscan.scan_google(info, "admin@acme.test", "acme.test", RULES, FPS, google_fake(pub, calls))
    assert res.users == 2                      # suspended user skipped, pagination followed
    assert res.public_files == 3 and res.inspected == 3
    by_name = {f.name: f for f in res.findings}
    assert set(by_name) == {"Customer cards.csv", "holiday.txt"}
    assert [h.rule_id for h in by_name["Customer cards.csv"].hits] == ["CREDIT-CARD"]
    assert by_name["holiday.txt"].fingerprint == "Board plan"
    msg = by_name["Customer cards.csv"].message()
    assert "4111 1111 1111 1111" not in msg and "owner=alice@acme.test" in msg and "url=https://docs.google.com/d1" in msg
    assert len(res.errors) == 1 and res.errors[0].startswith("bob@acme.test")
    assert not any("permissions" in c for c in calls)   # report-only: never touches sharing


def m365_fake(calls):
    def http(method, url, headers, body):
        calls.append((method, url))
        if "login.microsoftonline.com" in url:
            assert b"client_credentials" in body
            return 200, b'{"access_token": "graph-token"}'
        assert headers["Authorization"] == "Bearer graph-token"
        if url.startswith(cloudscan.GRAPH + "/users?"):
            return 200, json.dumps({"value": [{"id": "u1", "userPrincipalName": "carol@acme.test"},
                                              {"id": "u2", "userPrincipalName": "dave@acme.test"},
                                              {"id": "u3", "userPrincipalName": "old@acme.test", "accountEnabled": False}]}).encode()
        if "/users/u1/drive/root/delta" in url:
            if "page2" not in url:
                return 200, json.dumps({"value": [
                    {"id": "i1", "name": "payroll.xlsx.csv", "file": {}, "size": 50, "webUrl": "https://1drv/i1", "shared": {"scope": "anonymous"}},
                    {"id": "i2", "name": "internal.csv", "file": {}, "size": 50, "webUrl": "https://1drv/i2", "shared": {"scope": "organization"}},
                    {"id": "dir", "name": "Docs", "folder": {}, "shared": {"scope": "anonymous"}},
                ], "@odata.nextLink": cloudscan.GRAPH + "/users/u1/drive/root/delta?token=page2"}).encode()
            return 200, json.dumps({"value": [
                {"id": "i3", "name": "notes.txt", "file": {}, "size": 10, "webUrl": "https://1drv/i3", "shared": {"scope": "anonymous"}}]}).encode()
        if "/users/u2/drive/root/delta" in url:
            return 404, b"no drive"
        if url.endswith("/drive/items/i1/content"):
            return 200, b"employee,SSN\nBob,123-45-6789\n"
        if url.endswith("/drive/items/i3/content"):
            return 200, b"buy milk"
        raise AssertionError("unexpected call " + url)
    return http


def test_m365_scan_only_anonymous_links():
    calls = []
    res = cloudscan.scan_m365("tenant-id", "client", "secret", RULES, FPS, m365_fake(calls))
    assert res.users == 2 and res.public_files == 2 and res.inspected == 2 and res.errors == []
    assert [(f.name, [h.rule_id for h in f.hits]) for f in res.findings] == [("payroll.xlsx.csv", ["US-SSN"])]
    assert not any(c[1].endswith("/i2/content") for c in calls)   # organisation-only share is not downloaded
    assert all(m == "GET" for m, u in calls if "graph.microsoft.com" in u)  # read-only


def test_text_of_office_and_zip():
    import io
    import zipfile
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("word/document.xml", "<w:t>IBAN GB82 WEST 1234 5698 7654 32</w:t>")
    docx = buf.getvalue()
    assert "GB82 WEST" in cloudscan.text_of("a.docx", docx)
    outer = io.BytesIO()
    with zipfile.ZipFile(outer, "w") as z:
        z.writestr("x/a.docx", docx)
        z.writestr("b.csv", "card,4111 1111 1111 1111")
    t = cloudscan.text_of("bundle.zip", outer.getvalue())
    assert "GB82 WEST" in t and "4111" in t
    assert cloudscan.text_of("photo.jpg", b"\xff\xd8") == ""


def test_server_records_findings_and_status(monkeypatch, tmp_path):
    import main
    monkeypatch.setattr(main, "DB_PATH", tmp_path / "c.db")
    monkeypatch.setattr(main, "M365_TENANT", "t")
    monkeypatch.setattr(main, "M365_CLIENT_ID", "c")
    monkeypatch.setattr(main, "M365_SECRET", "s")
    monkeypatch.setattr(main, "GOOGLE_SA_FILE", "")
    monkeypatch.setattr(main, "WEBHOOK_URL", "")
    monkeypatch.setattr(main, "SMTP_HOST", "")
    main.init_db()
    out = main.run_cloud_scan(http=m365_fake([]))
    assert out == [{"source": "m365", "users": 2, "public_files": 2, "inspected": 2, "findings": 1, "errors": []}]
    conn = main.db()
    rows = [dict(r) for r in conn.execute("SELECT agent_id, level, event_type, message FROM events ORDER BY id")]
    agents = [dict(r) for r in conn.execute("SELECT agent_id, display_name FROM agents")]
    conn.close()
    assert rows[0]["agent_id"] == "cloud-m365" and rows[0]["event_type"] == "CLOUD_PUBLIC_SHARE" and rows[0]["level"] == "ALERT"
    assert "123-45-6789" not in rows[0]["message"]
    assert rows[1]["event_type"] == "CLOUD_SCAN_SUMMARY" and "findings=1" in rows[1]["message"]
    assert agents == [{"agent_id": "cloud-m365", "display_name": "Microsoft 365 scan"}]
    assert main.cloud_scan_due() is False   # just ran
