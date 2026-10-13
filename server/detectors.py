# OpenDLP Central Server - content detectors - GPL-3.0-only
"""Python port of the agent's ContentScanner (agent/Scanner.cs), used for server-side scans (cloud drives).

Behaviour must match the C# agent and the browser extension: all three are tested against
tests/vectors/detectors.json.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Callable, Iterable

_NID = re.compile(r"(?<![A-Za-z0-9])[A-Z][12]\d{8}(?!\d)")
_CARD = re.compile(r"(?<!\d)(?:\d[ -]?){12,18}\d(?!\d)")
_MOBILE = re.compile(r"(?<!\d)09\d{2}[- ]?\d{3}[- ]?\d{3}(?!\d)")
_EMAIL = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
_TW_PASSPORT = re.compile(r"(?i)(?:passport|護照)[^\d]{0,20}(?<![\d])([1-3]\d{8})(?!\d)")
_API_KEY = re.compile(
    r"(?:AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{22,}|xox[baprs]-[A-Za-z0-9-]{10,}"
    r"|AIza[0-9A-Za-z_\-]{35}|sk_(?:live|test)_[0-9A-Za-z]{16,}|sk-[A-Za-z0-9]{20,}"
    r"|(?i:api[_-]?key|secret[_-]?key|access[_-]?token)\s*[:=]\s*[\"']?[A-Za-z0-9_\-]{16,})"
)
_PRIVATE_KEY = re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----")
_IBAN = re.compile(r"(?<![A-Z0-9])[A-Z]{2}\d{2}(?:[ ]?[A-Z0-9]{4}){2,7}[ ]?[A-Z0-9]{1,4}(?![A-Z0-9])")
_SSN = re.compile(r"(?<![\d-])(?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0000)\d{4}(?![\d-])")
_PASSPORT = re.compile(
    r"(?i)(?:passport|passeport|reisepass|pasaporte|passaporto|паспорт|护照|護照|パスポート|여권)"
    r"[\s\S]{0,20}?(?<![A-Za-z0-9])(?=[A-Z]*\d)([A-Z0-9]{6,9})(?![A-Za-z0-9])"
)

DEFAULT_CONTEXT = {
    "credit_card": ["card", "credit", "visa", "mastercard", "amex", "payment", "cvv", "expiry", "信用卡", "卡號"],
    "us_ssn": ["ssn", "social security", "taxpayer"],
    "iban": ["iban", "bank", "account", "swift", "bic"],
    "tw_national_id": ["身分證", "身份證", "national id", "id no", "統一編號"],
    "tw_mobile": ["手機", "電話", "mobile", "phone", "tel"],
    "email": ["email", "e-mail", "mail", "信箱"],
}


def is_valid_tw_id(s: str) -> bool:
    letters = "ABCDEFGHJKLMNPQRSTUVXYWZIO"
    if len(s) != 10 or s[0] not in letters or not s[1:].isdigit():
        return False
    code = letters.index(s[0]) + 10
    w = [1, 9, 8, 7, 6, 5, 4, 3, 2, 1, 1]
    total = (code // 10) * w[0] + (code % 10) * w[1] + sum(int(s[i]) * w[i + 1] for i in range(1, 10))
    return total % 10 == 0


def is_valid_card(raw: str) -> bool:
    d = [int(c) for c in raw if c.isdigit()]
    if not 13 <= len(d) <= 19 or not 3 <= d[0] <= 6:
        return False
    total, dbl = 0, False
    for x in reversed(d):
        if dbl:
            x *= 2
            if x > 9:
                x -= 9
        total += x
        dbl = not dbl
    return total % 10 == 0


def is_valid_iban(raw: str) -> bool:
    s = raw.replace(" ", "").upper()
    if not 15 <= len(s) <= 34:
        return False
    r = s[4:] + s[:4]
    if not r.isalnum():
        return False
    return int("".join(str(int(c, 36)) for c in r)) % 97 == 1


_any: Callable[[str], bool] = lambda _s: True
BUILTIN: dict[str, tuple[re.Pattern[str], Callable[[str], bool]]] = {
    "tw_national_id": (_NID, is_valid_tw_id),
    "credit_card": (_CARD, is_valid_card),
    "tw_mobile": (_MOBILE, _any),
    "email": (_EMAIL, _any),
    "tw_passport": (_TW_PASSPORT, _any),
    "api_key": (_API_KEY, _any),
    "private_key": (_PRIVATE_KEY, _any),
    "iban": (_IBAN, is_valid_iban),
    "us_ssn": (_SSN, _any),
    "passport": (_PASSPORT, _any),
}


def mask(s: str) -> str:
    return "*" * len(s) if len(s) <= 4 else s[:2] + "*" * (len(s) - 4) + s[-2:]


def has_context(text: str, index: int, length: int, words: Iterable[str]) -> bool:
    around = text[max(0, index - 60): index + length + 60].lower()
    return any(w and w.lower() in around for w in words)


def _compile(p: str) -> re.Pattern[str] | None:
    try:
        return re.compile(p)
    except re.error:
        return None


@dataclass
class Hit:
    rule_id: str
    name: str
    severity: str
    action: str
    count: int
    sample: str


def _run(rule: dict[str, Any], text: str) -> tuple[int, str]:
    rtype = rule.get("type", "builtin")
    if rtype == "keywords":
        total, sample = 0, ""
        low = text.lower()
        for kw in rule.get("keywords", []):
            if not kw:
                continue
            n = low.count(kw.lower())
            if n and not sample:
                sample = kw
            total += n
        return total, sample
    if rtype == "regex":
        rx = _compile(rule.get("pattern", ""))
        if not rx:
            return 0, ""
        ms = [m.group(0) for m in rx.finditer(text)]
        return len(ms), mask(ms[0]) if ms else ""
    det = BUILTIN.get(str(rule.get("detector", "")).lower())
    if not det:
        return 0, ""
    rx, valid = det
    excludes = [x for x in (_compile(p) for p in rule.get("exclude", []) or []) if x]
    context = rule.get("contextWords") or DEFAULT_CONTEXT.get(str(rule.get("detector", "")).lower(), [])
    n, sample = 0, ""
    for m in rx.finditer(text):
        v = m.group(0)
        if not valid(v) or any(x.search(v) for x in excludes):
            continue
        if rule.get("requireContext") and context and not has_context(text, m.start(), len(v), context):
            continue
        n += 1
        if not sample:
            sample = mask(v)
    return n, sample


def scan(rules: list[dict[str, Any]], text: str) -> list[Hit]:
    hits: list[Hit] = []
    if not text:
        return hits
    for r in rules:
        try:
            count, sample = _run(r, text)
        except Exception:  # noqa: BLE001 - a bad rule must not stop the scan
            continue
        if count >= max(1, int(r.get("minMatches", 1) or 1)):
            hits.append(Hit(r.get("id", ""), r.get("name", ""), r.get("severity", "medium"), str(r.get("action", "alert")).lower(), count, sample))
    return hits


def worst_severity(hits: list[Hit]) -> str:
    rank = {"critical": 4, "high": 3, "medium": 2, "low": 1}
    return max((h.severity for h in hits), key=lambda s: rank.get(s, 0), default="low")


def summarize(hits: list[Hit]) -> str:
    rules = ",".join(f"{h.rule_id}x{h.count}" for h in hits)
    samples = ",".join(f"{h.rule_id}:{h.sample}" for h in hits)
    return f"severity={worst_severity(hits)} rules={rules} samples={samples}"
