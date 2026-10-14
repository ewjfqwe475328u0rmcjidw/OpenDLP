# Leakwarden Central Server - outbound e-mail scanning (report-only) - GPL-3.0-only
"""Finds e-mails sent to people *outside* the organisation whose body or attachments contain sensitive data
(same rules as the agents) or an exact copy of a fingerprinted file.

Report-only: it reads the Sent folder after the fact and never blocks, deletes, moves or changes mail.
Uses the same credentials as cloud drive scanning plus one extra read permission:
Google Workspace - gmail.readonly (domain-wide delegation); Microsoft 365 - Mail.Read (application).
"""
from __future__ import annotations

import base64
import hashlib
import html
import json
import re
import urllib.parse
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

import cloudscan
import detectors

MAX_MESSAGES_PER_USER = 300
MAX_ATTACHMENT = cloudscan.MAX_DOWNLOAD
GRAPH = cloudscan.GRAPH


def strip_html(text: str) -> str:
    text = re.sub(r"(?is)<(script|style)\b.*?</\1>", " ", text)
    return html.unescape(re.sub(r"<[^>]+>", " ", text))


def domain_of(addr: str) -> str:
    addr = addr.strip().strip("<>").lower()
    return addr.rsplit("@", 1)[1] if "@" in addr else ""


def external(recipients: list[str], internal_domains: set[str]) -> list[str]:
    return sorted({r.strip().lower() for r in recipients if r and domain_of(r) and domain_of(r) not in internal_domains})


@dataclass
class EmailFinding:
    source: str
    sender: str
    recipients: list[str]
    subject: str
    sent_at: str
    hits: list[detectors.Hit]
    attachments: list[str] = field(default_factory=list)
    fingerprint: str = ""

    def message(self) -> str:
        hits = list(self.hits)
        if self.fingerprint:
            hits.insert(0, detectors.Hit("FINGERPRINT", self.fingerprint, "critical", "alert", 1, self.fingerprint[:40]))
        subj = self.subject.replace('"', "'")[:150]
        att = ",".join(a.replace('"', "'")[:80] for a in self.attachments[:10])
        to = ",".join(self.recipients[:10]) + (f",+{len(self.recipients) - 10}" if len(self.recipients) > 10 else "")
        return (f"{detectors.summarize(hits)} channel=email from={self.sender} to={to} subject=\"{subj}\""
                + (f" attachments=\"{att}\"" if att else "") + f" sent={self.sent_at}")


@dataclass
class EmailScanResult:
    source: str
    users: int = 0
    messages: int = 0
    external_messages: int = 0
    findings: list[EmailFinding] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


def _inspect(res: EmailScanResult, sender: str, recipients: list[str], subject: str, sent_at: str,
             body: str, attachments: list[tuple[str, bytes]], rules: list[dict[str, Any]], fingerprints: dict[str, str]) -> None:
    res.external_messages += 1
    texts = [subject, body]
    fp = ""
    flagged: list[str] = []
    for name, data in attachments:
        texts.append(cloudscan.text_of(name, data))
        hit_fp = fingerprints.get(hashlib.sha256(data).hexdigest(), "")
        fp = fp or hit_fp
        if hit_fp:
            flagged.append(name)
    hits = detectors.scan(rules, "\n".join(t for t in texts if t))
    if hits or fp:
        res.findings.append(EmailFinding(res.source, sender, recipients, subject, sent_at, hits,
                                         [n for n, _ in attachments], fp))


# --------------------------------------------------------------------------- Microsoft 365
def _addresses(items: list[dict[str, Any]] | None) -> list[str]:
    return [((x or {}).get("emailAddress") or {}).get("address", "") for x in (items or [])]


def scan_m365(tenant: str, client_id: str, secret: str, since: datetime, internal_domains: set[str],
              rules: list[dict[str, Any]], fingerprints: dict[str, str], http: cloudscan.Http = cloudscan.default_http) -> EmailScanResult:
    res = EmailScanResult("m365")
    auth = {"Authorization": f"Bearer {cloudscan.m365_token(tenant, client_id, secret, http)}"}
    users, url = [], f"{GRAPH}/users?$select=id,userPrincipalName,mail,accountEnabled&$top=999"
    while url:
        st, data = http("GET", url, auth, None)
        if st != 200:
            raise RuntimeError(f"Graph users: HTTP {st}")
        d = json.loads(data)
        users += [u for u in d.get("value", []) if u.get("accountEnabled", True)]
        url = d.get("@odata.nextLink", "")
    res.users = len(users)
    since_s = since.strftime("%Y-%m-%dT%H:%M:%SZ")

    for u in users:
        sender = (u.get("mail") or u.get("userPrincipalName") or u["id"]).lower()
        own = internal_domains or {domain_of(sender)}
        try:
            q = urllib.parse.urlencode({
                "$filter": f"sentDateTime ge {since_s}",
                "$select": "id,subject,sentDateTime,toRecipients,ccRecipients,bccRecipients,body,hasAttachments",
                "$top": "50",
            }, safe="$,", quote_via=urllib.parse.quote)
            url, seen = f"{GRAPH}/users/{u['id']}/mailFolders/SentItems/messages?{q}", 0
            while url and seen < MAX_MESSAGES_PER_USER:
                st, data = http("GET", url, auth, None)
                if st == 404:
                    break  # no mailbox
                if st != 200:
                    raise RuntimeError(f"Sent items: HTTP {st}")
                d = json.loads(data)
                for m in d.get("value", []):
                    seen += 1
                    res.messages += 1
                    rcpt = _addresses(m.get("toRecipients")) + _addresses(m.get("ccRecipients")) + _addresses(m.get("bccRecipients"))
                    ext = external(rcpt, own)
                    if not ext:
                        continue
                    body = (m.get("body") or {}).get("content", "")
                    if (m.get("body") or {}).get("contentType", "").lower() == "html":
                        body = strip_html(body)
                    atts: list[tuple[str, bytes]] = []
                    if m.get("hasAttachments"):
                        st2, raw = http("GET", f"{GRAPH}/users/{u['id']}/messages/{m['id']}/attachments", auth, None)
                        if st2 == 200:
                            for a in json.loads(raw).get("value", []):
                                if a.get("@odata.type") == "#microsoft.graph.fileAttachment" and a.get("contentBytes") \
                                        and int(a.get("size", 0) or 0) <= MAX_ATTACHMENT:
                                    atts.append((a.get("name", "attachment"), base64.b64decode(a["contentBytes"])))
                    _inspect(res, sender, ext, m.get("subject") or "", m.get("sentDateTime", ""), body, atts, rules, fingerprints)
                url = d.get("@odata.nextLink", "")
        except Exception as exc:  # noqa: BLE001 - one mailbox must not stop the scan
            res.errors.append(f"{sender}: {exc}")
    return res


# --------------------------------------------------------------------------- Google Workspace (Gmail)
def _b64url_dec(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _walk(part: dict[str, Any]):
    yield part
    for p in part.get("parts", []) or []:
        yield from _walk(p)


def scan_google(sa: dict[str, Any], admin_email: str, domain: str, since: datetime, internal_domains: set[str],
                rules: list[dict[str, Any]], fingerprints: dict[str, str], http: cloudscan.Http = cloudscan.default_http) -> EmailScanResult:
    res = EmailScanResult("google")
    own = internal_domains or {domain.lower()}
    admin_tok = cloudscan.google_token(sa, admin_email, "https://www.googleapis.com/auth/admin.directory.user.readonly", http)
    users, page = [], ""
    while True:
        q = urllib.parse.urlencode({"domain": domain, "maxResults": 500, **({"pageToken": page} if page else {})})
        st, data = http("GET", f"https://admin.googleapis.com/admin/directory/v1/users?{q}", {"Authorization": f"Bearer {admin_tok}"}, None)
        if st != 200:
            raise RuntimeError(f"Google user list: HTTP {st}")
        d = json.loads(data)
        users += [x["primaryEmail"] for x in d.get("users", []) if not x.get("suspended")]
        page = d.get("nextPageToken", "")
        if not page:
            break
    res.users = len(users)
    gm = "https://gmail.googleapis.com/gmail/v1/users/me"

    for user in users:
        try:
            auth = {"Authorization": f"Bearer {cloudscan.google_token(sa, user, 'https://www.googleapis.com/auth/gmail.readonly', http)}"}
            page, seen = "", 0
            while seen < MAX_MESSAGES_PER_USER:
                params = {"q": f"in:sent after:{int(since.timestamp())}", "maxResults": 100, **({"pageToken": page} if page else {})}
                st, data = http("GET", f"{gm}/messages?" + urllib.parse.urlencode(params), auth, None)
                if st != 200:
                    raise RuntimeError(f"Gmail list: HTTP {st}")
                d = json.loads(data)
                for ref in d.get("messages", []) or []:
                    seen += 1
                    res.messages += 1
                    st2, raw = http("GET", f"{gm}/messages/{ref['id']}?format=full", auth, None)
                    if st2 != 200:
                        continue
                    msg = json.loads(raw)
                    hdr = {h["name"].lower(): h["value"] for h in msg.get("payload", {}).get("headers", [])}
                    rcpt = re.findall(r"[\w.+'-]+@[\w-]+(?:\.[\w-]+)+", " ".join(hdr.get(k, "") for k in ("to", "cc", "bcc")))
                    ext = external(rcpt, own)
                    if not ext:
                        continue
                    plain, htmls, atts = [], [], []
                    for p in _walk(msg.get("payload", {})):
                        b = p.get("body", {}) or {}
                        if p.get("filename") and b.get("attachmentId") and int(b.get("size", 0) or 0) <= MAX_ATTACHMENT:
                            st3, araw = http("GET", f"{gm}/messages/{ref['id']}/attachments/{b['attachmentId']}", auth, None)
                            if st3 == 200:
                                atts.append((p["filename"], _b64url_dec(json.loads(araw).get("data", ""))))
                        elif p.get("mimeType") in ("text/plain", "text/html") and b.get("data"):
                            t = _b64url_dec(b["data"]).decode("utf-8", "replace")
                            (htmls if p["mimeType"] == "text/html" else plain).append(t)
                    # multipart/alternative carries the same text twice: prefer the plain part so counts are not doubled
                    body = "\n".join(plain) if plain else strip_html("\n".join(htmls))
                    sent = (datetime.fromtimestamp(int(msg["internalDate"]) / 1000, tz=timezone.utc).isoformat()
                            if msg.get("internalDate") else "")
                    _inspect(res, user.lower(), ext, hdr.get("subject", ""), sent, body, atts, rules, fingerprints)
                page = d.get("nextPageToken", "")
                if not page:
                    break
        except Exception as exc:  # noqa: BLE001
            res.errors.append(f"{user}: {exc}")
    return res
