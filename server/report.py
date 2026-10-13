# OpenDLP Central Server - monthly PDF report - GPL-3.0-only
"""Monthly audit report: what was detected, where, and how healthy the agent fleet is.

Only facts recorded by the server go into the report. It deliberately contains no invented
"compliance score": it is evidence for an audit, not a certification.
"""
from __future__ import annotations

import io
import re
import sqlite3
from collections import Counter
from datetime import datetime, timedelta, timezone
from typing import Any, Callable

from reportlab.graphics.charts.barcharts import VerticalBarChart
from reportlab.graphics.shapes import Drawing, String
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import KeepTogether, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

INK = colors.HexColor("#0b1220")
MUTED = colors.HexColor("#5b6b85")
LINE = colors.HexColor("#d9e0ea")
BLUE = colors.HexColor("#2a78d6")
SEV_COLORS = {"critical": "#c62828", "high": "#d9601c", "medium": "#a87400", "low": "#5b6b85"}

_RULES_RX = re.compile(r"rules=(\S+)")
_RULE_ITEM_RX = re.compile(r"^(.+)x(\d+)$")


def month_bounds(month: str | None, now: datetime | None = None) -> tuple[datetime, datetime, str]:
    """[start, end) of a 'YYYY-MM' month in UTC; defaults to the current month."""
    now = now or datetime.now(timezone.utc)
    if month:
        try:
            start = datetime.strptime(month, "%Y-%m").replace(tzinfo=timezone.utc)
        except ValueError as exc:
            raise ValueError("month must look like 2026-10") from exc
    else:
        start = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    end = (start + timedelta(days=32)).replace(day=1)
    return start, end, start.strftime("%Y-%m")


def previous_month(now: datetime) -> str:
    first = now.replace(day=1)
    return (first - timedelta(days=1)).strftime("%Y-%m")


def _severity(message: str) -> str:
    if message.startswith("severity="):
        return message[9:].split(" ", 1)[0].lower()
    return "medium"


def collect(conn: sqlite3.Connection, month: str | None, offline_after: timedelta = timedelta(days=7)) -> dict[str, Any]:
    start, end, label = month_bounds(month)
    rows = conn.execute(
        "SELECT agent_id, level, event_type, message, received_at FROM events WHERE received_at >= ? AND received_at < ?",
        (start.isoformat(), end.isoformat()),
    ).fetchall()

    by_level: Counter[str] = Counter()
    by_sev: Counter[str] = Counter()
    by_type: Counter[str] = Counter()
    rules: Counter[str] = Counter()
    agent_alerts: Counter[str] = Counter()
    reporting: set[str] = set()
    days = (end - start).days
    daily = [0] * days

    for r in rows:
        level, etype, msg = r["level"] or "", r["event_type"] or "", r["message"] or ""
        reporting.add(r["agent_id"])
        by_level[level] += 1
        by_type[etype] += 1
        if level == "ALERT":
            by_sev[_severity(msg)] += 1
            agent_alerts[r["agent_id"]] += 1
            try:
                day = datetime.fromisoformat(r["received_at"]).day - 1
                if 0 <= day < days:
                    daily[day] += 1
            except ValueError:
                pass
        m = _RULES_RX.search(msg)
        if m:
            for item in m.group(1).split(","):
                im = _RULE_ITEM_RX.match(item)
                if im:
                    rules[im.group(1)] += int(im.group(2))

    agents = [dict(a) for a in conn.execute(
        "SELECT agent_id, last_seen, host, agent_version, display_name, revoked FROM agents ORDER BY agent_id"
    ).fetchall()]
    stale_before = min(end, datetime.now(timezone.utc)) - offline_after
    stale, revoked = [], []
    for a in agents:
        if a.get("revoked"):
            revoked.append(a)
            continue
        try:
            if datetime.fromisoformat(a["last_seen"]) < stale_before:
                stale.append(a)
        except (TypeError, ValueError):
            stale.append(a)

    def cat(*prefixes: str) -> int:
        return sum(n for t, n in by_type.items() if any(t.startswith(p) for p in prefixes))

    return {
        "month": label,
        "start": start,
        "end": end,
        "total_events": len(rows),
        "alerts": by_level.get("ALERT", 0),
        "by_severity": {s: by_sev.get(s, 0) for s in ("critical", "high", "medium", "low")},
        "categories": [
            ("Sensitive content found in files", cat("CONTENT_MATCH")),
            ("Removable drives (inserted / files written)", cat("USB_INSERT", "USB_FILE")),
            ("Print jobs", cat("PRINT_JOB")),
            ("Clipboard detections", cat("CLIPBOARD")),
            ("Disguised files (extension mismatch)", cat("EVASION_ALERT")),
            ("High-entropy files (possible encryption)", cat("HIGH_ENTROPY")),
            ("Pasted / uploaded in the browser", cat("BROWSER_PASTE", "BROWSER_DROP", "BROWSER_UPLOAD")),
            ("Copies of registered confidential files", cat("FINGERPRINT_MATCH", "USB_FINGERPRINT_MATCH")),
            ("Publicly shared cloud files with sensitive data", cat("CLOUD_PUBLIC_SHARE")),
            ("AI-classified confidential documents", cat("AI_CLASSIFIED", "USB_AI_CLASSIFIED")),
            ("Rejected policy signatures", cat("POLICY_SIG_INVALID")),
        ],
        "top_rules": rules.most_common(10),
        "top_agents": agent_alerts.most_common(10),
        "daily_alerts": daily,
        "agents_total": len(agents),
        "agents_reporting": len(reporting),
        "stale_agents": stale,
        "revoked_agents": revoked,
    }


def _styles() -> dict[str, ParagraphStyle]:
    base = getSampleStyleSheet()
    return {
        "title": ParagraphStyle("t", parent=base["Title"], fontSize=22, leading=26, textColor=INK, alignment=0, spaceAfter=2),
        "sub": ParagraphStyle("s", parent=base["Normal"], fontSize=10, textColor=MUTED, leading=14),
        "h2": ParagraphStyle("h2", parent=base["Heading2"], fontSize=13, textColor=INK, spaceBefore=14, spaceAfter=6),
        "body": ParagraphStyle("b", parent=base["Normal"], fontSize=9.5, leading=13, textColor=INK),
        "small": ParagraphStyle("sm", parent=base["Normal"], fontSize=8, leading=11, textColor=MUTED),
    }


def _table(data: list[list[Any]], widths: list[float], numeric_cols: tuple[int, ...] = ()) -> Table:
    t = Table(data, colWidths=widths, hAlign="LEFT")
    style = [
        ("FONT", (0, 0), (-1, 0), "Helvetica-Bold", 9),
        ("FONT", (0, 1), (-1, -1), "Helvetica", 9),
        ("TEXTCOLOR", (0, 0), (-1, 0), MUTED),
        ("LINEBELOW", (0, 0), (-1, 0), 0.8, LINE),
        ("LINEBELOW", (0, 1), (-1, -1), 0.4, LINE),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]
    for c in numeric_cols:
        style.append(("ALIGN", (c, 0), (c, -1), "RIGHT"))
    t.setStyle(TableStyle(style))
    return t


def _kpis(d: dict[str, Any]) -> Table:
    cells = [
        (str(d["agents_reporting"]), f"of {d['agents_total']} endpoints reported"),
        (str(d["alerts"]), "alerts"),
        (str(d["by_severity"]["critical"] + d["by_severity"]["high"]), "critical + high alerts"),
        (str(d["total_events"]), "events recorded"),
    ]
    data = [[Paragraph(f'<font size="20"><b>{v}</b></font><br/><font size="8" color="#5b6b85">{l}</font>', ParagraphStyle("k", leading=22)) for v, l in cells]]
    t = Table(data, colWidths=[42 * mm] * 4, hAlign="LEFT")
    t.setStyle(TableStyle([
        ("BOX", (0, 0), (-1, -1), 0.6, LINE),
        ("INNERGRID", (0, 0), (-1, -1), 0.6, LINE),
        ("TOPPADDING", (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
    ]))
    return t


def _daily_chart(daily: list[int]) -> Drawing:
    width, height = 170 * mm, 52 * mm
    dr = Drawing(width, height)
    bc = VerticalBarChart()
    bc.x, bc.y, bc.width, bc.height = 26, 16, width - 36, height - 26
    bc.data = [daily or [0]]
    bc.strokeColor = None
    bc.bars[0].fillColor = BLUE
    bc.bars[0].strokeColor = None
    bc.barSpacing = 1.5
    bc.groupSpacing = 2
    bc.valueAxis.valueMin = 0
    peak = max(daily + [1])
    step = max(1, -(-peak // 4))
    bc.valueAxis.valueStep = step
    bc.valueAxis.valueMax = step * 4
    bc.valueAxis.labels.fontName, bc.valueAxis.labels.fontSize = "Helvetica", 7
    bc.valueAxis.labels.fillColor = MUTED
    bc.valueAxis.strokeColor = LINE
    bc.valueAxis.gridStrokeColor = LINE
    bc.valueAxis.visibleGrid = True
    bc.categoryAxis.categoryNames = [str(i + 1) if (i % 5 == 0 or i == len(daily) - 1) else "" for i in range(len(daily))]
    bc.categoryAxis.labels.fontName, bc.categoryAxis.labels.fontSize = "Helvetica", 7
    bc.categoryAxis.labels.fillColor = MUTED
    bc.categoryAxis.strokeColor = LINE
    dr.add(bc)
    dr.add(String(width - 4, height - 7, "alerts per day, day of month (UTC)", fontName="Helvetica", fontSize=7, fillColor=MUTED, textAnchor="end"))
    return dr


def _esc(s: Any) -> str:
    return str(s if s is not None else "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def render_pdf(d: dict[str, Any], org_name: str, generated_at: datetime | None = None) -> bytes:
    generated_at = generated_at or datetime.now(timezone.utc)
    st = _styles()
    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf, pagesize=A4, leftMargin=18 * mm, rightMargin=18 * mm, topMargin=16 * mm, bottomMargin=16 * mm,
        title=f"OpenDLP monthly report {d['month']}", author="OpenDLP", subject=org_name,
    )
    period = f"{d['start']:%Y-%m-%d} to {(d['end'] - timedelta(days=1)):%Y-%m-%d} (UTC)"
    story: list[Any] = [
        Paragraph(f"Data protection report &mdash; {d['start']:%B %Y}", st["title"]),
        Paragraph(f"{_esc(org_name)} &middot; {period} &middot; generated {generated_at:%Y-%m-%d %H:%M} UTC by OpenDLP", st["sub"]),
        Spacer(1, 10),
        _kpis(d),
    ]

    sev = d["by_severity"]
    sev_rows = [["Severity", "Alerts"]] + [
        [Paragraph(f'<font color="{SEV_COLORS[k]}"><b>{k.capitalize()}</b></font>', st["body"]), sev[k]] for k in ("critical", "high", "medium", "low")
    ]
    story += [Paragraph("Alerts by severity", st["h2"]), _table(sev_rows, [60 * mm, 25 * mm], (1,))]

    story += [KeepTogether([Paragraph("Alerts per day", st["h2"]), _daily_chart(d["daily_alerts"])])]

    story += [Paragraph("What was detected", st["h2"]),
              _table([["Activity", "Events"]] + [[k, v] for k, v in d["categories"]], [120 * mm, 25 * mm], (1,))]

    if d["top_rules"]:
        story += [Paragraph("Most triggered detection rules", st["h2"]),
                  _table([["Rule", "Matches"]] + [[_esc(r), n] for r, n in d["top_rules"]], [120 * mm, 25 * mm], (1,))]

    if d["top_agents"]:
        story += [Paragraph("Endpoints with the most alerts", st["h2"]),
                  _table([["Endpoint", "Alerts"]] + [[_esc(a), n] for a, n in d["top_agents"]], [120 * mm, 25 * mm], (1,))]

    health = [["Endpoint", "Host", "Version", "Last seen (UTC)", "Status"]]
    for a in d["stale_agents"]:
        health.append([_esc(a.get("display_name") or a["agent_id"]), _esc(a.get("host")), _esc(a.get("agent_version")),
                       _esc((a.get("last_seen") or "")[:16].replace("T", " ")), "not reporting"])
    for a in d["revoked_agents"]:
        health.append([_esc(a.get("display_name") or a["agent_id"]), _esc(a.get("host")), _esc(a.get("agent_version")),
                       _esc((a.get("last_seen") or "")[:16].replace("T", " ")), "revoked"])
    story.append(Paragraph("Endpoint health", st["h2"]))
    if len(health) > 1:
        story += [Paragraph("Endpoints that were revoked or have not reported for 7+ days. Unprotected endpoints are a gap in coverage.", st["body"]),
                  Spacer(1, 4), _table(health, [42 * mm, 36 * mm, 18 * mm, 32 * mm, 26 * mm])]
    else:
        story.append(Paragraph("All registered endpoints reported within the last 7 days.", st["body"]))

    if d.get("audit") is not None:
        a = d["audit"]
        story.append(Paragraph("Audit log integrity", st["h2"]))
        if a.get("ok"):
            how = "keyed HMAC-SHA256 chain" if a.get("keyed") else "SHA-256 chain (no OPENDLP_AUDIT_KEY set)"
            story.append(Paragraph(
                f'<font color="#1f9d55"><b>Verified.</b></font> All {a.get("checked", 0)} stored events and administrator '
                f"actions form an unbroken {how}; no record has been edited or deleted outside the retention policy. "
                f"Chain head: <font face=\"Courier\" size=\"7\">{_esc(str(a.get('head', '')))}</font>", st["body"]))
        else:
            story.append(Paragraph(
                f'<font color="#d64545"><b>Integrity check FAILED</b></font> at event #{a.get("firstBadId")} '
                f"({_esc(str(a.get('reason')))}). Records may have been altered; investigate before relying on this report.",
                st["body"]))

    story += [
        Spacer(1, 14),
        Paragraph(
            "About this report: figures come from events received by the OpenDLP server in the period. "
            "OpenDLP is an open-source audit and detection tool; detections are alerts, not proof of a data breach, "
            "and this report is not a certification of compliance with any law or standard. Matched values are masked "
            "on the endpoint and never stored on the server.", st["small"]),
    ]

    def footer(canvas, doc_):  # noqa: ANN001 - reportlab callback signature
        canvas.saveState()
        canvas.setFont("Helvetica", 7.5)
        canvas.setFillColor(MUTED)
        canvas.drawString(18 * mm, 10 * mm, f"OpenDLP data protection report {d['month']} - {org_name}")
        canvas.drawRightString(A4[0] - 18 * mm, 10 * mm, f"page {doc_.page}")
        canvas.restoreState()

    doc.build(story, onFirstPage=footer, onLaterPages=footer)
    return buf.getvalue()


def build_monthly_report(conn: sqlite3.Connection, month: str | None, org_name: str,
                         audit_key: bytes | None = None) -> tuple[str, bytes]:
    d = collect(conn, month)
    if audit_key is not None:
        import audit

        d["audit"] = audit.verify(conn, audit_key)
    return d["month"], render_pdf(d, org_name)


def maybe_send_monthly(
    conn: sqlite3.Connection,
    now: datetime,
    org_name: str,
    send: Callable[[str, str, bytes, str], None],
    audit_key: bytes | None = None,
) -> str | None:
    """On or after the 1st of a month, e-mail last month's report once. Returns the month sent, if any."""
    conn.execute("CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT)")
    target = previous_month(now)
    row = conn.execute("SELECT value FROM meta WHERE key = 'last_report_month'").fetchone()
    if row is not None and row[0] >= target:
        return None
    month, pdf = build_monthly_report(conn, target, org_name, audit_key)
    send(f"OpenDLP data protection report {month}",
         f"Attached: the OpenDLP data protection report for {month} ({org_name}).",
         pdf, f"opendlp-report-{month}.pdf")
    conn.execute("INSERT INTO meta(key, value) VALUES ('last_report_month', ?) "
                 "ON CONFLICT(key) DO UPDATE SET value = excluded.value", (target,))
    conn.commit()
    return target
