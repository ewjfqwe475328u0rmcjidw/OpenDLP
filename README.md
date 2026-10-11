# OpenDLP v0.7.1

Open-source **endpoint audit & detection MVP**: a Windows Agent + Watchdog + FastAPI central server. It is an **audit-first prototype**, not a finished commercial DLP product.

[繁體中文說明](README.zh-TW.md) · [Changelog](CHANGELOG.md) · [Security policy](SECURITY.md)

> **⚠️ The Windows Agent is not yet verified.** The maintainers have not yet completed a C# build and real-device test on a clean Windows 10/11 + .NET 8 machine. Community testing is welcome — please use a disposable, authorized test machine, not a production or critical computer.
>
> **Limitations:** Current features focus on auditing, content detection and event reporting. USB, clipboard, print and browser policy fields do **not** mean reliable OS-level blocking exists in every scenario, and the browser extension is not included in this release. Do not rely on OpenDLP as your only line of defense against data leakage.

## Features

- **Agent (.NET 8, Windows):** file-activity monitoring on configured paths, content inspection of supported text/Office files (Taiwan national ID, credit card, bulk phone/email, custom keywords and regex), removable-drive and print events, clipboard monitoring via a user-session helper, encrypted local log with a durable upload outbox.
- **Server (FastAPI + SQLite):** telemetry ingestion, HMAC-signed policy distribution with versioning (`304 Not Modified`), per-agent tokens (optional), separate admin token, password-protected dashboard, age-based event retention.
- **Watchdog:** prototype process supervisor that restarts the agent when its heartbeat goes stale.

## Project layout

```text
OpenDLP/
├── agent/                  .NET 8 Windows endpoint agent
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

Dashboard: <http://127.0.0.1:8000/> (HTTP Basic, user `admin`). Use HTTPS (e.g. a TLS reverse proxy) outside of local testing. All environment variables are listed in `server/.env.example`.

### API overview

| Endpoint | Auth | Purpose |
|---|---|---|
| `POST /api/v1/telemetry` | Agent token + `X-Agent-Id` | Upload event batches |
| `GET /api/v1/policy?version=N` | Agent token + `X-Agent-Id` | Signed policy; `304` if up to date |
| `GET /api/v1/events` | Admin token | List recent events |
| `GET /api/v1/agents` | Admin token | List agents and last-seen time |
| `GET /health` | none | Liveness check |

The default policy is `policies/default-policy.json` (override with `OPENDLP_POLICY`). It is validated before being signed. Policies are signed with HMAC-SHA256 using a key derived from the agent's token — a shared-secret prototype design, not asymmetric signing. Use TLS and protect your tokens.

## Configure and run the Agent

1. On Windows, open the `agent` folder.
2. Copy the example config: `Copy-Item agent.config.example.json agent.config.json`.
3. Set `ServerUrl`, `AgentId` and sensitive paths. Prefer the `OPENDLP_TOKEN` environment variable over writing the token into the file, and never commit a real token.
4. The agent's token must match the server's token (or that agent's entry in `OPENDLP_AGENT_TOKENS`).
5. Run:

```powershell
dotnet build
dotnet run -- --mode console
```

Modes: `--mode console` for development, `--mode service` for Windows Service integration tests, `--mode helper` for the user-session helper. Service installation, helper startup and IPC permissions still need verification on a clean Windows test machine.

Local logs may contain file paths and other sensitive information. Test only on authorized devices and check your organization's policy and applicable law first.

## Testing

```bash
cd server
pip install -r requirements-dev.txt
python -m pytest -q
```

GitHub Actions (`.github/workflows/ci.yml`) runs the server tests on Linux and builds the Agent and Watchdog on Windows with .NET 8.

For manual Windows testing, also cover: valid/invalid token, bad policy signature, offline retry, log retention, helper IPC permissions, and service start/stop.

## Contributing

Issues and pull requests are welcome — especially Windows test reports (OS version, .NET SDK version, build output, observed behavior). Please do not post secrets, personal data or sensitive logs.

## License

GNU GPL v3 only. See [LICENSE](LICENSE).
