# Leakwarden Central Server - cloud drive scanning (report-only) - GPL-3.0-only
"""Finds files in Google Workspace (Drive) and Microsoft 365 (OneDrive) that are shared with *anyone with the link*
and contain sensitive data (same rules as the agents) or match a registered fingerprint.

Report-only by design: it never changes sharing settings. Each organisation connects its *own* tenant
(Google: service account with domain-wide delegation; Microsoft: app registration with application permissions),
so no third-party app verification is involved and no data leaves the organisation's server.

All HTTP goes through an injectable `Http` callable so the whole flow is unit-tested with fake APIs.
"""
from __future__ import annotations

import base64
import hashlib
import io
import json
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from dataclasses import dataclass, field
from typing import Any, Callable

import detectors

Http = Callable[[str, str, dict[str, str], bytes | None], tuple[int, bytes]]

MAX_DOWNLOAD = 10 * 1024 * 1024
MAX_FILES_PER_USER = 500
TEXT_EXT = (".txt", ".csv", ".tsv", ".log", ".json", ".xml", ".md", ".html", ".htm", ".ini", ".yml", ".yaml", ".sql", ".eml")
OOXML_PARTS = {
    ".docx": lambda n: n == "word/document.xml",
    ".xlsx": lambda n: n == "xl/sharedStrings.xml" or (n.startswith("xl/worksheets/") and n.endswith(".xml")),
    ".pptx": lambda n: n.startswith("ppt/slides/slide") and n.endswith(".xml"),
}


def default_http(method: str, url: str, headers: dict[str, str], body: bytes | None) -> tuple[int, bytes]:
    req = urllib.request.Request(url, data=body, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=60) as r:  # noqa: S310 - fixed Google / Microsoft endpoints
            return r.status, r.read(MAX_DOWNLOAD + 1)
    except urllib.error.HTTPError as e:
        return e.code, e.read()


def _strip_xml(xml: bytes) -> str:
    import re

    return re.sub(r"<[^>]+>", " ", xml.decode("utf-8", "replace"))


def text_of(name: str, data: bytes) -> str:
    low = name.lower()
    if low.endswith(TEXT_EXT):
        return data.decode("utf-8", "replace")
    ext = "." + low.rsplit(".", 1)[-1] if "." in low else ""
    if ext in OOXML_PARTS or ext == ".zip":
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as z:
                parts = []
                for info in z.infolist()[:300]:
                    if info.flag_bits & 0x1 or info.file_size > MAX_DOWNLOAD:
                        continue
                    if ext in OOXML_PARTS and OOXML_PARTS[ext](info.filename):
                        parts.append(_strip_xml(z.read(info)))
                    elif ext == ".zip" and not info.is_dir():
                        parts.append(text_of(info.filename, z.read(info)))
                return "\n".join(parts)
        except zipfile.BadZipFile:
            return ""
    return ""


@dataclass
class Finding:
    source: str          # "google" | "m365"
    owner: str
    name: str
    url: str
    hits: list[detectors.Hit]
    fingerprint: str = ""

    def message(self) -> str:
        hits = list(self.hits)
        if self.fingerprint:
            hits.insert(0, detectors.Hit("FINGERPRINT", self.fingerprint, "critical", "alert", 1, self.fingerprint[:40]))
        safe_name = self.name.replace('"', "'")[:200]
        return (f"{detectors.summarize(hits)} sharing=anyone-with-link owner={self.owner} "
                f"file=\"{safe_name}\" url={self.url}")


@dataclass
class ScanResult:
    source: str
    users: int = 0
    public_files: int = 0
    inspected: int = 0
    findings: list[Finding] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


def _inspect(source: str, owner: str, name: str, url: str, data: bytes | None,
             rules: list[dict[str, Any]], fingerprints: dict[str, str], result: ScanResult) -> None:
    if data is None:
        return
    result.inspected += 1
    fp = fingerprints.get(hashlib.sha256(data).hexdigest(), "")
    hits = detectors.scan(rules, text_of(name, data))
    if fp or hits:
        result.findings.append(Finding(source, owner, name, url, hits, fp))


# --------------------------------------------------------------------------- Google Workspace

def _b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def google_token(sa: dict[str, Any], subject: str, scope: str, http: Http, now: float | None = None) -> str:
    """OAuth 2.0 JWT-bearer grant for a service account with domain-wide delegation."""
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding

    now = int(now or time.time())
    header = _b64url(json.dumps({"alg": "RS256", "typ": "JWT"}).encode())
    claims = _b64url(json.dumps({
        "iss": sa["client_email"], "sub": subject, "scope": scope,
        "aud": sa.get("token_uri", "https://oauth2.googleapis.com/token"), "iat": now, "exp": now + 3600,
    }).encode())
    key = serialization.load_pem_private_key(sa["private_key"].encode(), password=None)
    sig = key.sign(f"{header}.{claims}".encode(), padding.PKCS1v15(), hashes.SHA256())
    assertion = f"{header}.{claims}.{_b64url(sig)}"
    body = urllib.parse.urlencode({"grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer", "assertion": assertion}).encode()
    status, data = http("POST", sa.get("token_uri", "https://oauth2.googleapis.com/token"),
                        {"Content-Type": "application/x-www-form-urlencoded"}, body)
    if status != 200:
        raise RuntimeError(f"Google token for {subject}: HTTP {status}")
    return json.loads(data)["access_token"]


GOOGLE_EXPORT = {
    "application/vnd.google-apps.document": ("text/plain", ".txt"),
    "application/vnd.google-apps.spreadsheet": ("text/csv", ".csv"),
    "application/vnd.google-apps.presentation": ("text/plain", ".txt"),
}


def scan_google(sa: dict[str, Any], admin_email: str, domain: str, rules: list[dict[str, Any]],
                fingerprints: dict[str, str], http: Http = default_http) -> ScanResult:
    res = ScanResult("google")
    admin_tok = google_token(sa, admin_email, "https://www.googleapis.com/auth/admin.directory.user.readonly", http)
    users, page = [], ""
    while True:
        q = urllib.parse.urlencode({"domain": domain, "maxResults": 500, **({"pageToken": page} if page else {})})
        st, data = http("GET", f"https://admin.googleapis.com/admin/directory/v1/users?{q}", {"Authorization": f"Bearer {admin_tok}"}, None)
        if st != 200:
            raise RuntimeError(f"Google user list: HTTP {st}")
        d = json.loads(data)
        users += [u["primaryEmail"] for u in d.get("users", []) if not u.get("suspended")]
        page = d.get("nextPageToken", "")
        if not page:
            break
    res.users = len(users)

    for user in users:
        try:
            tok = google_token(sa, user, "https://www.googleapis.com/auth/drive.readonly", http)
            auth = {"Authorization": f"Bearer {tok}"}
            page, seen = "", 0
            while seen < MAX_FILES_PER_USER:
                params = {
                    "q": "(visibility = 'anyoneWithLink' or visibility = 'anyoneCanFind') and trashed = false and 'me' in owners",
                    "fields": "nextPageToken, files(id, name, mimeType, size, webViewLink)", "pageSize": 100,
                    **({"pageToken": page} if page else {}),
                }
                st, data = http("GET", "https://www.googleapis.com/drive/v3/files?" + urllib.parse.urlencode(params), auth, None)
                if st != 200:
                    raise RuntimeError(f"Drive list: HTTP {st}")
                d = json.loads(data)
                for f in d.get("files", []):
                    seen += 1
                    res.public_files += 1
                    name, mime = f["name"], f.get("mimeType", "")
                    content: bytes | None = None
                    if mime in GOOGLE_EXPORT:
                        export_mime, ext = GOOGLE_EXPORT[mime]
                        st2, content = http("GET", f"https://www.googleapis.com/drive/v3/files/{f['id']}/export?"
                                            + urllib.parse.urlencode({"mimeType": export_mime}), auth, None)
                        name += ext
                    elif int(f.get("size", 0) or 0) <= MAX_DOWNLOAD and not mime.startswith("application/vnd.google-apps"):
                        st2, content = http("GET", f"https://www.googleapis.com/drive/v3/files/{f['id']}?alt=media", auth, None)
                    else:
                        st2 = 0
                    _inspect("google", user, name, f.get("webViewLink", ""), content if st2 == 200 else None, rules, fingerprints, res)
                page = d.get("nextPageToken", "")
                if not page:
                    break
        except Exception as exc:  # noqa: BLE001 - one user's failure must not stop the scan
            res.errors.append(f"{user}: {exc}")
    return res


# --------------------------------------------------------------------------- Microsoft 365

def m365_token(tenant: str, client_id: str, secret: str, http: Http) -> str:
    body = urllib.parse.urlencode({
        "client_id": client_id, "client_secret": secret, "grant_type": "client_credentials",
        "scope": "https://graph.microsoft.com/.default",
    }).encode()
    st, data = http("POST", f"https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token",
                    {"Content-Type": "application/x-www-form-urlencoded"}, body)
    if st != 200:
        raise RuntimeError(f"Microsoft token: HTTP {st}")
    return json.loads(data)["access_token"]


GRAPH = "https://graph.microsoft.com/v1.0"


def scan_m365(tenant: str, client_id: str, secret: str, rules: list[dict[str, Any]],
              fingerprints: dict[str, str], http: Http = default_http) -> ScanResult:
    res = ScanResult("m365")
    auth = {"Authorization": f"Bearer {m365_token(tenant, client_id, secret, http)}"}
    users, url = [], f"{GRAPH}/users?$select=id,userPrincipalName,accountEnabled&$top=999"
    while url:
        st, data = http("GET", url, auth, None)
        if st != 200:
            raise RuntimeError(f"Graph users: HTTP {st}")
        d = json.loads(data)
        users += [u for u in d.get("value", []) if u.get("accountEnabled", True)]
        url = d.get("@odata.nextLink", "")
    res.users = len(users)

    for u in users:
        upn = u.get("userPrincipalName", u["id"])
        try:
            url, seen = f"{GRAPH}/users/{u['id']}/drive/root/delta?$select=id,name,size,file,webUrl,shared,deleted", 0
            while url and seen < MAX_FILES_PER_USER * 20:
                st, data = http("GET", url, auth, None)
                if st == 404:
                    break  # user without OneDrive
                if st != 200:
                    raise RuntimeError(f"OneDrive delta: HTTP {st}")
                d = json.loads(data)
                for item in d.get("value", []):
                    seen += 1
                    if "file" not in item or item.get("deleted") or (item.get("shared") or {}).get("scope") != "anonymous":
                        continue
                    res.public_files += 1
                    content = None
                    if int(item.get("size", 0) or 0) <= MAX_DOWNLOAD:
                        st2, body = http("GET", f"{GRAPH}/users/{u['id']}/drive/items/{item['id']}/content", auth, None)
                        content = body if st2 == 200 else None
                    _inspect("m365", upn, item.get("name", ""), item.get("webUrl", ""), content, rules, fingerprints, res)
                url = d.get("@odata.nextLink", "")
        except Exception as exc:  # noqa: BLE001
            res.errors.append(f"{upn}: {exc}")
    return res
