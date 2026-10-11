# OpenDLP v0.11.0

Open-source **endpoint audit & detection MVP**: a Windows Agent + Watchdog + FastAPI central server. It is an **audit-first prototype**, not a finished commercial DLP product.

[繁體中文說明](README.zh-TW.md) · [Changelog](CHANGELOG.md) · [Security policy](SECURITY.md)

> **Verification status:** every change is built and tested automatically on clean Windows VMs — unit tests, a console end-to-end test and a full Windows-service install/detect/recover/uninstall test (see [docs/RELEASE_AUDIT.md](docs/RELEASE_AUDIT.md)). USB devices and the interactive clipboard are not covered by automation yet; reports from real machines are very welcome.
>
> **Limitations:** Current features focus on auditing, content detection and event reporting. USB, clipboard, print and browser policy fields do **not** mean reliable OS-level blocking exists in every scenario, and the browser extension is not included in this release. Do not rely on OpenDLP as your only line of defense against data leakage.

**New here?** Read [docs/QUICKSTART-SMB.md](docs/QUICKSTART-SMB.md) — server + first PC in ~15 minutes. Compliance notes: [docs/COMPLIANCE.md](docs/COMPLIANCE.md).

## Features

- **Agent (.NET 8, Windows):** file-activity monitoring on configured paths, content inspection of supported text/Office files (payment cards, IBAN, US SSN, passports in 9 languages, API keys/tokens, private keys, Taiwan national ID, bulk phone/e-mail, multilingual keywords, custom regex), removable-drive and print events, clipboard monitoring via a user-session helper, encrypted local log with a durable upload outbox.
- **Server (FastAPI + SQLite):** telemetry ingestion, signed policy distribution (HMAC + optional ECDSA) with versioning, **agent self-enrollment** with per-machine tokens and revocation, admin/viewer roles, dashboard with 24 h severity tiles and filters, CSV export, **Slack/Teams/webhook and e-mail alerts**, age-based retention, one-command HTTPS deployment.
- **Watchdog:** prototype process supervisor that restarts the agent when its heartbeat goes stale.

## Project layout

```text
OpenDLP/
├── agent/                  .NET 8 Windows endpoint agent (+ install scripts)
├── agent.tests/            xunit tests for the agent
├── watchdog/               Agent watchdog prototype
├── server/                 FastAPI API + dashboard
├── policies/default-policy.json
├── docs/RELEASE_AUDIT.md
├── CHANGELOG.md
├── SECURITY.md
└── LICENSE                 GPL-3.0-only
```

## Requirements

- Windows Agent: Windows 10/11 and the .NET 8 SDK (some monitors need elevated permissions).
- Server: Python 3.10+.

## Run the central server (development)

Linux/macOS:

```bash
cd server
python -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
export OPENDLP_TOKEN="a random secret of at least 32 bytes"          # used by agents
export OPENDLP_ADMIN_TOKEN="another random secret, >= 32 bytes"      # read events / agent list
export OPENDLP_DASHBOARD_PASSWORD="your dashboard password"          # dashboard is disabled if unset
uvicorn main:app --host 127.0.0.1 --port 8000
```

Windows PowerShell:

```powershell
cd server
py -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
$env:OPENDLP_TOKEN = "a random secret of at least 32 bytes"
$env:OPENDLP_ADMIN_TOKEN = "another random secret, >= 32 bytes"
$env:OPENDLP_DASHBOARD_PASSWORD = "your dashboard password"
uvicorn main:app --host 127.0.0.1 --port 8000
```

Generate secrets with `python -c "import secrets; print(secrets.token_urlsafe(48))"`.

Dashboard: <http://127.0.0.1:8000/> (HTTP Basic, user `admin`). Use HTTPS (e.g. a TLS reverse proxy) outside of local testing. All environment variables are listed in `server/env.example`.

### API overview

| Endpoint | Auth | Purpose |
|---|---|---|
| `POST /api/v1/telemetry` | Agent token + `X-Agent-Id` | Upload event batches |
| `GET /api/v1/policy?version=N` | Agent token + `X-Agent-Id` | Signed policy; `304` if up to date |
| `GET /api/v1/events` | Admin token | List recent events |
| `GET /api/v1/agents` | Admin token | List agents and last-seen time |
| `POST /api/v1/enroll` | enrollment code | Self-enroll; returns a per-machine token |
| `GET /api/v1/stats`, `/events.csv` | Admin or viewer token | Statistics, CSV export |
| `GET/PUT /api/v1/admin/policy` | viewer / admin | Read / replace the policy (validated) |
| `POST /api/v1/admin/agents/{id}/revoke`, `/unrevoke`, `DELETE …/agents/{id}` | Admin token | Agent lifecycle |
| `POST /api/v1/admin/notify/test` | Admin token | Send a test alert to webhook / e-mail |
| `GET /health` | none | Liveness check |

The default policy is `policies/default-policy.json` (override with `OPENDLP_POLICY`). It is validated before being signed. Policies are signed with HMAC-SHA256 using a key derived from the agent's token — a shared-secret prototype design, not asymmetric signing. Use TLS and protect your tokens.

### Docker

```bash
cp server/env.example .env      # fill in the secrets
docker compose up -d             # server on 127.0.0.1:8000; put a TLS reverse proxy in front for remote access
```

Public HTTPS with automatic certificates: `OPENDLP_DOMAIN=dlp.example.com docker compose --profile https up -d`.

## Configure and run the Agent

**Recommended (self-enrollment):** download `OpenDLP-windows-vX.Y.Z.zip` from [Releases](../../releases), extract it, and in an elevated PowerShell in the `agent` folder run (requires the [.NET 8 Desktop Runtime](https://dotnet.microsoft.com/download/dotnet/8.0)):

```powershell
.\install-service.ps1 -ServerUrl https://dlp.example.com -EnrollmentCode "<OPENDLP_ENROLL_CODE from the server .env>" -WithWatchdog
```

The agent exchanges the code for its own token on first start and stores it encrypted (DPAPI, machine scope). Revoke a machine any time via the admin API.

**Manual / development:**
1. Copy `agent.config.example.json` to `agent.config.json`; set `ServerUrl` and either `EnrollmentCode` or `ApiToken` (or the `OPENDLP_TOKEN` env var). Never commit a real token.
2. Run:

```powershell
dotnet build
dotnet run -- --mode console
```

Uninstall: `& "C:\Program Files\OpenDLP\uninstall-service.ps1"`.

**Asymmetric policy signing (recommended):** on the server run `python tools/gen_signing_key.py /etc/opendlp/policy-signing.pem`, set `OPENDLP_SIGNING_KEY` to that path, and paste the printed public key into each agent's `PolicySigningPublicKey`. Agents then reject any policy not signed by the server's private key, even if the shared token leaks.

Modes: `--mode console` for development, `--mode service` for Windows Service integration tests, `--mode helper` for the user-session helper. Service installation, helper startup and IPC permissions still need verification on a clean Windows test machine.

Local logs may contain file paths and other sensitive information. Test only on authorized devices and check your organization's policy and applicable law first.

## Testing

```bash
cd server
pip install -r requirements-dev.txt
python -m pytest -q
```

Agent unit tests (Windows, .NET 8 SDK): `dotnet test agent.tests/OpenDLP.Agent.Tests.csproj`

GitHub Actions (`.github/workflows/ci.yml`) runs the server tests and Docker build on Linux, and builds + unit-tests the Agent and Watchdog on Windows. Pushing a `v*` tag publishes a Windows zip to Releases.

For manual Windows testing, also cover: valid/invalid token, bad policy signature, offline retry, log retention, helper IPC permissions, and service start/stop.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). 
Issues and pull requests are welcome — especially Windows test reports (OS version, .NET SDK version, build output, observed behavior). Please do not post secrets, personal data or sensitive logs.

## License

GNU GPL v3 only. See [LICENSE](LICENSE).
