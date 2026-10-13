# Cloud drive scanning (Google Workspace / Microsoft 365)

Finds files that are shared with **anyone who has the link** and contain sensitive data (same rules as the agents) or are copies of a registered confidential file. **Report-only**: OpenDLP never changes sharing settings - an admin reviews the alert and fixes the link.

Each organisation connects its **own** tenant, so no third-party app verification is involved and file contents are processed only on your OpenDLP server. Scans run every `OPENDLP_CLOUD_SCAN_HOURS` (default 24, `0` = off) or on demand: `POST /api/v1/admin/cloudscan/run`. Status: `GET /api/v1/admin/cloudscan`.

Findings appear as `CLOUD_PUBLIC_SHARE` alerts (agent `cloud-google` / `cloud-m365`) with owner, file name and link, are sent to your webhook / e-mail, and are counted in the monthly report. A `CLOUD_SCAN_SUMMARY` event records each run.

> Status: implemented and tested against simulated Google and Microsoft APIs (`server/tests/test_cloudscan.py`). Not yet verified against a real tenant - please report results.

## Google Workspace

1. Google Cloud console → create a project → enable **Admin SDK API** and **Google Drive API**.
2. Create a **service account**, create a JSON key, save it on the server (e.g. `/etc/opendlp/google-sa.json`, readable only by the server).
3. Google Admin console → Security → Access and data control → API controls → **Domain-wide delegation** → add the service account's client ID with scopes:
   `https://www.googleapis.com/auth/admin.directory.user.readonly,https://www.googleapis.com/auth/drive.readonly`
4. Server environment:
   ```
   OPENDLP_GOOGLE_SA_FILE=/etc/opendlp/google-sa.json
   OPENDLP_GOOGLE_ADMIN_EMAIL=admin@yourcompany.com     # an admin the service account impersonates to list users
   OPENDLP_GOOGLE_DOMAIN=yourcompany.com
   ```

Scanned: files each user **owns** with visibility "anyone with the link" or "public on the web" (Google Docs/Sheets/Slides are exported as text; other files up to 10 MB are downloaded). Shared drives are not scanned yet.

## Microsoft 365 (OneDrive)

1. Entra admin center → App registrations → **New registration** (single tenant).
2. API permissions → Microsoft Graph → **Application** permissions: `User.Read.All`, `Files.Read.All` → **Grant admin consent**.
3. Certificates & secrets → new client secret.
4. Server environment:
   ```
   OPENDLP_M365_TENANT_ID=<directory (tenant) id>
   OPENDLP_M365_CLIENT_ID=<application (client) id>
   OPENDLP_M365_CLIENT_SECRET=<secret value>
   ```

Scanned: files in each user's OneDrive whose sharing link scope is **anonymous** ("anyone with the link"), up to 10 MB. SharePoint sites and Teams files are not scanned yet.

## Privacy

Downloaded content is scanned in memory and discarded; only masked samples, owner, file name and link are stored as events. Limit who can read events (viewer/admin roles) and tell employees that shared links are audited.
