# OpenDLP Central Server - SIEM forwarding (syslog, CEF or JSON) - GPL-3.0-only
"""Streams every stored event to a SIEM (Splunk, Microsoft Sentinel, QRadar, Wazuh, Graylog, Elastic...).

OPENDLP_SYSLOG = udp://host:514 | tcp://host:514 | tls://host:6514
OPENDLP_SYSLOG_FORMAT = cef (default) | json

Messages are RFC 5424 syslog lines. TCP/TLS use octet-counting framing (RFC 6587). Sending happens on a background
thread with a bounded queue, so a slow or unreachable SIEM never slows down agents; dropped messages are counted.
"""
from __future__ import annotations

import json
import queue
import socket
import ssl
import threading
import time
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse

_SEV_CEF = {"low": 3, "medium": 5, "high": 8, "critical": 10}
_LEVEL_CEF = {"DEBUG": 1, "INFO": 2, "WARN": 4, "ERROR": 6, "ALERT": 7}
_LEVEL_SYSLOG = {"DEBUG": 7, "INFO": 6, "WARN": 4, "ERROR": 3, "ALERT": 1}
FACILITY = 10  # authpriv / security


def _cef_header(v: str) -> str:
    return v.replace("\\", "\\\\").replace("|", "\\|").replace("\r", " ").replace("\n", " ")


def _cef_ext(v: Any) -> str:
    return (str(v).replace("\\", "\\\\").replace("=", "\\=").replace("\r", "\\r").replace("\n", "\\n"))


def format_cef(ev: dict[str, Any], severity: str, version: str) -> str:
    level = str(ev.get("level") or "INFO").upper()
    sev = _SEV_CEF.get(severity, 0) if level == "ALERT" else _LEVEL_CEF.get(level, 2)
    et = str(ev.get("event_type") or "EVENT")
    ext = {
        "rt": ev.get("ts", ""),
        "dvchost": ev.get("host", ""),
        "deviceExternalId": ev.get("agent_id", ""),
        "cs1Label": "level", "cs1": level,
        "cs2Label": "severity", "cs2": severity,
        "externalId": ev.get("id", ""),
        "msg": str(ev.get("message", ""))[:4000],
    }
    if ev.get("chain"):
        ext.update({"cs3Label": "auditChain", "cs3": ev["chain"]})
    body = " ".join(f"{k}={_cef_ext(v)}" for k, v in ext.items() if v != "")
    return f"CEF:0|OpenDLP|OpenDLP|{_cef_header(version)}|{_cef_header(et)}|{_cef_header(et)}|{sev}|{body}"


def format_json(ev: dict[str, Any], severity: str, _version: str) -> str:
    return json.dumps({**{k: ev.get(k) for k in ("id", "agent_id", "ts", "level", "event_type", "message", "host", "chain")},
                       "severity": severity, "product": "OpenDLP"}, ensure_ascii=False)


def syslog_line(ev: dict[str, Any], payload: str) -> bytes:
    pri = FACILITY * 8 + _LEVEL_SYSLOG.get(str(ev.get("level") or "INFO").upper(), 6)
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    host = (socket.gethostname() or "-").replace(" ", "_")[:255]
    return f"<{pri}>1 {ts} {host} opendlp - {str(ev.get('event_type') or '-')[:32]} - {payload}".encode("utf-8")


class Forwarder:
    def __init__(self, url: str, fmt: str = "cef", version: str = "", max_queue: int = 10000):
        u = urlparse(url)
        if u.scheme not in {"udp", "tcp", "tls"} or not u.hostname:
            raise ValueError("OPENDLP_SYSLOG must look like udp://host:514, tcp://host:514 or tls://host:6514")
        self.scheme, self.host, self.port = u.scheme, u.hostname, u.port or (6514 if u.scheme == "tls" else 514)
        self.fmt = format_json if fmt == "json" else format_cef
        self.version = version
        self.q: queue.Queue[bytes] = queue.Queue(max_queue)
        self.sent = 0
        self.dropped = 0
        self.last_error = ""
        self._sock: socket.socket | None = None
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, daemon=True, name="opendlp-siem")
        self._thread.start()

    def submit(self, ev: dict[str, Any], severity: str) -> None:
        try:
            self.q.put_nowait(syslog_line(ev, self.fmt(ev, severity, self.version)))
        except queue.Full:
            self.dropped += 1

    def status(self) -> dict[str, Any]:
        return {"target": f"{self.scheme}://{self.host}:{self.port}", "sent": self.sent, "dropped": self.dropped,
                "queued": self.q.qsize(), "lastError": self.last_error}

    def flush(self, timeout: float = 5.0) -> None:
        end = time.monotonic() + timeout
        while (self.q.unfinished_tasks) and time.monotonic() < end:
            time.sleep(0.02)

    def close(self) -> None:
        self._stop.set()

    def _connect(self) -> socket.socket:
        if self.scheme == "udp":
            return socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s = socket.create_connection((self.host, self.port), timeout=10)
        if self.scheme == "tls":
            s = ssl.create_default_context().wrap_socket(s, server_hostname=self.host)
        return s

    def _send(self, line: bytes) -> None:
        if self._sock is None:
            self._sock = self._connect()
        if self.scheme == "udp":
            self._sock.sendto(line[:64000], (self.host, self.port))
        else:
            self._sock.sendall(str(len(line)).encode() + b" " + line)

    def _run(self) -> None:
        backoff = 1.0
        while not self._stop.is_set():
            try:
                line = self.q.get(timeout=0.5)
            except queue.Empty:
                continue
            while not self._stop.is_set():
                try:
                    self._send(line)
                    self.sent += 1
                    backoff = 1.0
                    break
                except OSError as exc:
                    self.last_error = f"{type(exc).__name__}: {exc}"[:300]
                    try:
                        if self._sock:
                            self._sock.close()
                    except OSError:
                        pass
                    self._sock = None
                    time.sleep(backoff)
                    backoff = min(backoff * 2, 60)
            self.q.task_done()
