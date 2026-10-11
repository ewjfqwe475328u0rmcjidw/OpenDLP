# Changelog

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
