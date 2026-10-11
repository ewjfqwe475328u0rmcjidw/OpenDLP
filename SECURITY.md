# Security Policy & Threat Model (OpenDLP v0.7.1)

## 1. Product scope

OpenDLP is an **experimental endpoint audit and detection prototype**. Depending on configuration, it can observe configured file paths, inspect supported text/Office documents, log selected removable-drive and print-related events, monitor clipboard text in a user-session helper, and upload telemetry to a central server.

It is **not** a kernel-level DLP and must not be relied on to guarantee blocking of file copies, browser uploads, or data exfiltration. A browser extension is not included in this release. Some policy values describe future or best-effort behavior rather than reliable OS-level enforcement.

## 2. Trust boundaries

| Component | Trust assumption |
|---|---|
| Agent host | Local administrator may be able to tamper with or disable the agent |
| Local log key | Derived from AgentId + API token; demo-grade, not KMS/DPAPI |
| Network path | Use HTTPS in production; local sample may use HTTP |
| Agent token | Shared bearer token from `OPENDLP_TOKEN`, or optional per-agent tokens via `OPENDLP_AGENT_TOKENS` |
| Admin token | Separate `OPENDLP_ADMIN_TOKEN` for reading events and the agent list |
| Policy signature | HMAC-SHA256 with a key derived from the shared token; not asymmetric signing |
| SQLite DB | Access control depends on OS file permissions |

## 3. Known limitations

### Agent
- User-mode only; no minifilter driver and no guaranteed enforcement against file copy/upload.
- `FileSystemWatcher` can miss high-volume bursts or events during buffer overflow.
- Text extraction supports only selected formats and is bounded by the configured size limit.
- High entropy and extension/header mismatch are heuristics, not proof of malicious behavior.
- Clipboard monitoring requires a helper running in the interactive user's session; service/helper startup and IPC permissions need Windows testing.
- Local log encryption is demo-grade. A privileged user may delete logs, and the log key is derived from the API token.
- Telemetry uses a disk outbox for retry, but end-to-end crash/recovery behavior still requires stress testing.
- The heartbeat is independent of monitor health, so a hung monitor can still appear alive.

### Watchdog
- Prototype process supervisor; no code-integrity verification.
- Does not install or manage a Windows Service. Test the command-line mode and restart behavior separately.

### Server
- Bearer tokens only (shared, or optional per-agent); no mTLS and no rate limiting.
- The dashboard uses a single HTTP Basic password (`OPENDLP_DASHBOARD_PASSWORD`) and is disabled when unset. Put it behind HTTPS (e.g. a reverse proxy); never expose it over plain HTTP to the public internet.
- Event retention is a simple age-based purge at startup (`OPENDLP_RETENTION_DAYS`, default 90).
- If `OPENDLP_TOKEN` / `OPENDLP_ADMIN_TOKEN` are unset or shorter than 32 bytes, the related endpoints fail closed.

## 4. Privacy

Events can contain full file paths, filenames, user names, or snippets of event context. The content scanner masks matched samples, but operators should still treat logs as sensitive. Use data minimization, strict access controls, short retention, employee notice/consent where applicable, and legal review before deployment.

## 5. Before production use

1. Use HTTPS and protect/rotate tokens.
2. Add SSO/role-based authorization for the dashboard, audit logging, and rate limits.
3. Build and test on a clean Windows 10/11 host with .NET 8; test service lifecycle, helper IPC ACLs, clipboard permissions, removable media, and failure recovery.
4. Code-sign binaries and define a secure update process.
5. Validate policy behavior and verify that any claimed blocking is enforced at the OS level.
6. Run dependency, static-analysis, and security tests before each release.

## 6. Vulnerability reports

Please report vulnerabilities privately to the project maintainers with affected component, impact, and reproduction steps. Avoid posting sensitive reproduction details publicly before a fix is available.

## 7. Deployment statement

GPL-3.0-only software provided without warranty. It is an MVP detection framework, not a certified compliance control or substitute for commercial DLP/EDR.
