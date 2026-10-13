# Changelog

## 0.13.0 — browser extension, fingerprints, cloud scanning, fewer false positives
- **Browser extension (Chrome / Edge)**: warns about or blocks pasting, dropping and uploading sensitive data to AI chats (ChatGPT, Claude, Gemini, Copilot, ...), personal cloud drives and file-sharing sites; text inside Office/zip files; blocked-upload sites; self-enrolls, verifies the signed policy, reports `BROWSER_*` events; managed configuration for Intune / Group Policy. Tested end-to-end in real Chromium in CI.
- **File fingerprints**: register confidential files (hashed in the admin's browser, never uploaded); agents and the extension recognise exact copies even when renamed or zipped (`FINGERPRINT_MATCH`, critical).
- **Zip scanning**: agents and the extension inspect text and Office files inside `.zip` archives.
- **Fewer false positives**: rules can require nearby context words (`requireContext`, `contextWords`) and ignore matches (`exclude`); the default policy uses this for SSNs and documented example API keys.
- **Cloud drive scanning (report-only)**: Google Workspace and Microsoft 365 files shared with "anyone with the link" that contain sensitive data or fingerprinted files → `CLOUD_PUBLIC_SHARE` alerts. Tested against simulated APIs; see docs/CLOUD-SCAN.md.
- **Optional AI classification** with a self-hosted Ollama model for documents no rule matched (off by default; docs/AI-CLASSIFICATION.md).
- Shared detector test vectors (`tests/vectors/detectors.json`) run against the C#, JavaScript and Python implementations.
- Monthly report counts browser, fingerprint, cloud and AI detections.

## 0.12.0 — monthly PDF report
- **Monthly data protection report (PDF)**: endpoints reporting, alerts by severity, alerts per day chart, what was detected (content, removable drives, printing, clipboard, disguised and high-entropy files), most triggered rules, endpoints with most alerts, endpoints not reporting or revoked. Download from the dashboard or `GET /api/v1/reports/monthly.pdf?month=YYYY-MM`; optionally e-mailed on the 1st of each month (`OPENDLP_REPORT_EMAIL=1`, `OPENDLP_ORG_NAME`). States plainly that it is audit evidence, not a compliance certification.
- "Hosted OpenDLP - interest" issue template to gauge demand for a managed server.

## 0.11.0 — verified install, macOS/Linux agent, fleet deployment
Every item below is exercised by CI on clean Windows, macOS and Linux VMs.
- **macOS and Linux agent** (`agent-unix/`): shares the detection core with the Windows agent (content rules, policy signing, encrypted log, telemetry, self-enrollment); removable-volume auditing; `install.sh` / `uninstall.sh` for launchd and systemd (automatic restart). Token and config stored root-only (0600).
- **Fleet deployment:** `Deploy-OpenDLP.ps1` (GPO / Intune / RMM) and `deploy-opendlp.sh` (Jamf / Kandji / MDM / SSH / Ansible) download the right package, enforce SHA-256, are idempotent, and log. New dashboard page **Deploy agents** with ready-to-copy commands. Guide: `docs/DEPLOYMENT.md`.
- **Dashboard charts:** alerts per hour (24 h) and events per day (7 d), with a table view; `GET /api/v1/stats/timeseries`.
- **Reliable print auditing:** reads the Windows PrintService operational log (event 307: printer, user, pages, document) instead of WMI polling, which missed short jobs. Print is now a mandatory CI check.
- **Watchdog rewritten** for service deployments (`--service OpenDLPAgent`); previously it launched a second console-mode agent.
- **Installer fixes for worldwide use:** well-known SIDs instead of localized account names; `New-Service` (paths with spaces on PowerShell 5.1); helper can run while the config stays admin-only; no config copy with secrets left in Downloads; previous install stopped before copying; `-SensitivePaths`.
- Windows packages are self-contained (no .NET install needed). Release builds Windows x64, macOS arm64/x64 and Linux x64 with one `SHA256SUMS.txt`.
- Fixes: USB monitor `EventArrivedEventHandler` lambdas (did not compile); E2E JSON-array unrolling; issue template YAML; `server/env.example` (dot-files are skipped by GitHub's web uploader).

## 0.10.1
- Fix: removed the `System.IO.Pipes.AccessControl` 8.0.0 package reference (that version does not exist; the API is built into .NET 8). This broke every Agent build.
- CI: compiler/NuGet/test errors are re-emitted as public annotations (`tools/ci/run.ps1`).
- **End-to-end test on a clean Windows VM** in CI (`tests/e2e/run-e2e.ps1`): server + agent, self-enrollment, DPAPI credential store, signed policy, telemetry, content detection with masking, and revocation.

## 0.10.0 — "ready for small businesses" round
Server fully tested (43 tests). Agent changes compile-checked by CI only.
- **Self-enrollment:** `POST /api/v1/enroll` exchanges a one-time `OPENDLP_ENROLL_CODE` for a per-machine token. Agent stores it encrypted with DPAPI (machine scope); re-enrolling rotates it; admins can revoke/unrevoke/delete agents.
- **Roles:** `OPENDLP_VIEWER_TOKEN` and a read-only dashboard login (`viewer`); only the admin token can change policy or agents.
- **Notifications:** generic JSON webhook (Slack/Discord/Teams/Mattermost/n8n) and SMTP e-mail for alerts ≥ `OPENDLP_NOTIFY_MIN_SEVERITY`, with per-agent/event cooldown; `POST /api/v1/admin/notify/test`.
- **Dashboard:** 24-hour severity tiles, host / version / enrolled / revoked columns, role badge.
- **Installer:** `install-service.ps1 -ServerUrl … -EnrollmentCode …` writes the config for you.
- **HTTPS in one command:** `docker compose --profile https up -d` with Caddy + Let's Encrypt (`deploy/Caddyfile`).
- **International detectors:** `us_ssn`, multilingual `passport` (EN/FR/DE/ES/IT/RU/ZH/JA/KO context words); default policy reordered international-first with multilingual confidentiality keywords.
- Docs: `docs/QUICKSTART-SMB.md`, `docs/COMPLIANCE.md` (GDPR / CCPA / PDPA / PIPL / LGPD mapping, employee-notice checklist).

## 0.9.0
Agent detection, agent unit tests, asymmetric policy signing, service installer. **Agent still unverified on real hardware — CI compiles and unit-tests it on GitHub's Windows runners.**
- New built-in detectors: `api_key` (AWS/GitHub/Slack/Google/Stripe/OpenAI-style tokens and `api_key=` assignments), `private_key` (PEM headers), `tw_passport` (needs "passport"/"護照" context), `iban` (mod-97). Default policy ships rules for all four; the server validates detector names.
- `agent.tests/` xunit project (checksums, scanner rules, masking, heuristics, policy store, signatures); runs in CI and before every release.
- Optional **ECDSA P-256 policy signatures**: server `OPENDLP_SIGNING_KEY` (generate with `server/tools/gen_signing_key.py`), agent `PolicySigningPublicKey`. When configured on the agent the asymmetric signature is mandatory; HMAC remains for compatibility.
- `agent/install-service.ps1` / `uninstall-service.ps1`: service install with restart-on-failure, locked-down install folder, helper logon task, optional watchdog task. Included in release zips. **Untested by maintainers.**
- Agent reports its real assembly version (`X-Agent-Version`, banner).

## 0.8.0
Server tooling, deployment and release automation (Agent source unchanged).
- Event search & filters (level, type, agent, time, text) in the API and dashboard; CSV export (`/api/v1/events.csv`, formula-injection safe); `/api/v1/stats`.
- Agent online/offline status (`OPENDLP_OFFLINE_AFTER_SECONDS`, default 300).
- Policy admin API: `GET/PUT /api/v1/admin/policy` with validation, `.bak` backup and guaranteed version bump.
- Docker image + `docker-compose.yml`; CI builds it.
- `release.yml`: pushing a `v*` tag builds the Windows Agent/Watchdog on GitHub and attaches a zip + SHA-256 to a pre-release, so testers can download it.
- CONTRIBUTING.md and issue templates (Windows test report, bug report).
- 30 server tests.

## 0.7.1
Server hardening and integration (Agent C# logic unchanged apart from version string).
- **Breaking:** `/api/v1/events` and `/api/v1/agents` now require a separate `OPENDLP_ADMIN_TOKEN`; agent tokens can no longer read other agents' events.
- **Breaking:** the dashboard is disabled unless `OPENDLP_DASHBOARD_PASSWORD` is set (HTTP Basic). `OPENDLP_DASHBOARD_INSECURE=1` is for local development only.
- Optional per-agent tokens (`OPENDLP_AGENT_TOKENS`); policy signatures use the requesting agent's own token, so no Agent change is needed.
- Policy is validated before signing (rule types, severities, actions, regex compile, duplicate IDs).
- Policy version defaults to the policy file's mtime, so edits propagate automatically.
- Telemetry field validation/normalisation, request body size limit (413), configurable retention purge.
- 25 server tests (was 11); GitHub Actions CI builds the Agent and Watchdog on Windows and runs server tests on Linux.

## 0.7.0
Integrated agent + FastAPI server with signed policy endpoint.
