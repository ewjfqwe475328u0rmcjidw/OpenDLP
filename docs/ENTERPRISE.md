# Audit trail, SIEM, group policies and single sign-on

These features are aimed at organisations that answer to auditors, customers' security questionnaires or an
existing security team. All are optional and configured with environment variables (see `server/env.example`).

## Tamper-evident audit log

Every stored record — agent events, cloud-scan findings and administrator actions — is linked to the previous one:

```
chain(n) = HMAC-SHA256(LEAKWARDEN_AUDIT_KEY, chain(n-1) | record(n))
```

Editing, deleting or re-ordering any record breaks every link after it. Check at any time:

```bash
curl -H "Authorization: Bearer $LEAKWARDEN_VIEWER_TOKEN" https://dlp.example.com/api/v1/admin/audit/verify
# {"ok": true, "checked": 18234, "head": "9f2c…", "keyed": true}
# {"ok": false, "firstBadId": 1042, "reason": "event modified"}
```

The dashboard shows the result as a tile, and the monthly PDF report includes an **Audit log integrity** section.

- **Set `LEAKWARDEN_AUDIT_KEY`** (32 random bytes, hex) and keep it outside the database, e.g. in your secrets
  manager. Without it a plain SHA-256 chain is used: accidental damage and casual edits are still detected, but
  someone with write access to the database file could rebuild the chain.
- Do not change the key later; records written under the old key will no longer verify.
- Retention purges (`LEAKWARDEN_RETENTION_DAYS`) delete the oldest records and move a verified anchor forward, so the
  chain keeps verifying.
- Records written by versions before 0.13.0 are not covered; the chain starts with the first record after upgrade.
- For evidence that must survive a full server compromise, also forward events to a SIEM (below): the `cs3`
  field of every CEF message carries the chain value, so the copy in your SIEM can be compared with the server.

### Administrator actions

Policy changes, group changes, endpoint assignment, fingerprint registration, agent revoke / delete, cloud scans
and dashboard sign-ins (including refused ones) are recorded as `ADMIN_ACTION` events from agent `server`:

```
actor=sso:it@example.com action=agent_group_assign agent=FIN-LAPTOP-07 group="Finance"
actor=api-admin-token action=policy_update rules=14
```

## SIEM forwarding

```env
LEAKWARDEN_SYSLOG=tls://siem.example.com:6514   # or udp://host:514, tcp://host:514
LEAKWARDEN_SYSLOG_FORMAT=cef                    # or json
```

Every stored event is sent as an RFC 5424 syslog message (facility `authpriv`). TCP and TLS use octet-counting
framing (RFC 6587); TLS verifies the server certificate against the system CA store. Sending happens on a
background queue (10,000 messages); if the SIEM is unreachable the server retries with back-off and, when the
queue is full, drops and counts messages instead of slowing down agents. Status:
`GET /api/v1/admin/siem` → `sent`, `dropped`, `queued`, `lastError`.

CEF mapping:

| CEF field | Value |
|---|---|
| Device Vendor / Product | `Leakwarden` / `Leakwarden` |
| Signature ID / Name | event type, e.g. `USB_BLOCK`, `FILE_SENSITIVE`, `CLOUD_PUBLIC_SHARE`, `ADMIN_ACTION` |
| Severity | alerts: low 3, medium 5, high 8, critical 10; other events by level |
| `rt` | event time (agent clock, UTC) |
| `dvchost` / `deviceExternalId` | endpoint host name / agent id |
| `cs1` level, `cs2` severity, `cs3` audit chain value, `externalId` server event id, `msg` details |

Works with Splunk (syslog input or Splunk Connect for Syslog), Microsoft Sentinel (CEF via AMA), IBM QRadar,
Wazuh, Graylog and Elastic. Pulling instead of pushing is also possible with the read-only API
(`GET /api/v1/events`, `/events.csv`) and `LEAKWARDEN_VIEWER_TOKEN`.

## Department / group policies

The company policy (`policies/default-policy.json`) applies to every endpoint. A group adds an **overlay**:

```bash
curl -X PUT -H "Authorization: Bearer $LEAKWARDEN_ADMIN_TOKEN" -H "Content-Type: application/json" \
  https://dlp.example.com/api/v1/admin/groups/Finance -d '{
    "usb": {"mode": "block"},
    "browser": {"mode": "block"},
    "rules": [{"id": "CREDIT-CARD", "type": "builtin", "detector": "credit_card", "severity": "critical", "action": "block"}],
    "disableRules": ["TW-MOBILE"]
  }'
```

Merge rules:

- `rules`: a rule whose `id` already exists replaces it; a new `id` is added.
- `disableRules`: rule ids removed for this group.
- objects such as `usb`, `browser`, `ai`, `clipboard`: keys are merged (other keys keep the company value).
- anything else replaces the company value.

The merged policy is validated before it is saved. Assign endpoints in the dashboard (**Group** column) or:

```bash
curl -X POST -H "Authorization: Bearer $LEAKWARDEN_ADMIN_TOKEN" -H "Content-Type: application/json" \
  https://dlp.example.com/api/v1/admin/agents/FIN-LAPTOP-07/group -d '{"group": "Finance"}'
```

`{"group": null}` returns the endpoint to the company policy. Agents pick up the change on their next policy poll
(about a minute). `GET /api/v1/admin/agents/{id}/effective-policy` shows exactly what an endpoint receives.
Groups are assigned by administrators only; an endpoint cannot choose its own group.

## Dashboard single sign-on (OpenID Connect)

```env
LEAKWARDEN_PUBLIC_URL=https://dlp.example.com
LEAKWARDEN_OIDC_ISSUER=...
LEAKWARDEN_OIDC_CLIENT_ID=...
LEAKWARDEN_OIDC_CLIENT_SECRET=...
LEAKWARDEN_OIDC_ADMINS=it@example.com,owner@example.com
LEAKWARDEN_OIDC_VIEWERS=@example.com
LEAKWARDEN_SESSION_SECRET=<random, keeps sign-ins across restarts>
```

Register the redirect URI **`https://dlp.example.com/auth/callback`** with your provider.

| Provider | Issuer | Notes |
|---|---|---|
| Microsoft Entra ID | `https://login.microsoftonline.com/<tenant-id>/v2.0` | App registrations → New → Web redirect URI; create a client secret. Use the tenant id, not `common`. |
| Google Workspace | `https://accounts.google.com` | Google Cloud console → Credentials → OAuth client ID (Web application); set the consent screen to *Internal*. |
| Okta | `https://<your-org>.okta.com` | Applications → Create App Integration → OIDC, Web Application. |
| Keycloak / Authentik | the realm / provider issuer URL | Confidential client, standard flow. |

How it works: authorization code flow with PKCE; the server verifies the ID token signature against the
provider's published keys (RS256 / ES256), the issuer, audience, expiry and a one-time nonce. The e-mail address
(or, for Entra ID, the sign-in name) decides the role: entries in `LEAKWARDEN_OIDC_ADMINS` are administrators,
entries in `LEAKWARDEN_OIDC_VIEWERS` read-only; `@domain` matches a whole domain; everyone else is refused and the
refusal is logged. Unverified e-mail addresses are ignored. Sessions are signed, HTTP-only cookies valid for
`LEAKWARDEN_SESSION_HOURS` (default 8).

The Basic-auth login (`LEAKWARDEN_DASHBOARD_PASSWORD`) keeps working as a break-glass account; leave it unset if you
want SSO only. Dashboard pages that change data only accept requests coming from the dashboard itself (Origin
check); automation should use the bearer-token API.

## Endpoint user identity

Agents on Windows report the signed-in Windows / Active Directory account (`DOMAIN\user`) for clipboard and
print events, and the host name for every event. Entra ID / Google identities are used for dashboard access only.

## Verification status

See [RELEASE_AUDIT.md](RELEASE_AUDIT.md). The audit chain, group policies and SIEM forwarding over UDP/TCP are
tested in CI; SSO is tested against a simulated provider with real signatures, not yet against a live tenant.
