# OpenDLP quick start for small businesses

Goal: a working server and your first monitored PC in about 15 minutes, without being a security specialist.

> OpenDLP is **audit and alert** software. It tells you when sensitive data moves in risky ways; it is not (yet) a tool that hard-blocks every copy. Read the README warnings before relying on it.

## 1. Server (any Linux VM, 1 vCPU / 1 GB is plenty)

```bash
git clone https://github.com/<you>/OpenDLP.git && cd OpenDLP
cp server/env.example .env
python3 -c "import secrets; [print(secrets.token_urlsafe(48)) for _ in range(4)]"   # four secrets
nano .env            # paste them into OPENDLP_TOKEN, OPENDLP_ADMIN_TOKEN, OPENDLP_ENROLL_CODE; set OPENDLP_DASHBOARD_PASSWORD
```

**Internal network only:** `docker compose up -d` → dashboard at http://SERVER-IP:8000 (edit `ports:` in docker-compose.yml to expose it beyond localhost, and only do so inside your LAN/VPN).

**Public HTTPS (recommended):** point a DNS name at the server, open ports 80/443, then
`OPENDLP_DOMAIN=dlp.yourcompany.com docker compose --profile https up -d`. Certificates are issued and renewed automatically.

Log in to the dashboard as `admin` with the dashboard password. Create a read-only login for managers with `OPENDLP_DASHBOARD_VIEWER_PASSWORD`.

## 2. Alerts to Slack / Teams / e-mail

Add one of these to `.env` and restart (`docker compose up -d`):
- `OPENDLP_WEBHOOK_URL=` an incoming-webhook URL (Slack, Discord, Teams, Mattermost, n8n…)
- or the `OPENDLP_SMTP_*` settings for e-mail.

Test with: `curl -X POST -H "Authorization: Bearer $OPENDLP_ADMIN_TOKEN" https://dlp.yourcompany.com/api/v1/admin/notify/test`

## 3. Install the agent on a PC

1. Download `OpenDLP-windows-x64-vX.Y.Z.zip` from the Releases page and extract it (no .NET install needed).
2. Open **PowerShell as Administrator** in the `agent` folder:
   ```powershell
   .\install-service.ps1 -ServerUrl https://dlp.yourcompany.com -EnrollmentCode "<OPENDLP_ENROLL_CODE>" -WithWatchdog
   ```
3. The PC appears in the dashboard within a minute. Its own access token is created automatically and stored encrypted on the machine — the enrollment code is never stored there.

Macs and Linux machines: `curl -fsSL https://github.com/<owner>/<repo>/releases/download/v0.13.0/deploy-opendlp.sh | sudo bash -s -- --server-url https://dlp.yourcompany.com --enrollment-code "<code>"`. Rolling out to the whole company: the dashboard's **Deploy agents** page and [DEPLOYMENT.md](DEPLOYMENT.md).

Lost or stolen laptop? Dashboard/API → revoke the agent: `POST /api/v1/admin/agents/<id>/revoke`.

## 4. Tune the policy

`policies/default-policy.json` ships with international rules (payment cards, IBAN, US SSN, passports, API keys, private keys, multilingual "confidential" markers) plus Taiwan-specific IDs. Edit the file (or `PUT /api/v1/admin/policy`) — every agent picks up the change on its next poll (≤ 60 s). Remove rules you do not need to reduce noise.

## 5. Tell your staff

Most jurisdictions require informing employees about monitoring. See `docs/COMPLIANCE.md` for a starting point and talk to a lawyer for your country.
