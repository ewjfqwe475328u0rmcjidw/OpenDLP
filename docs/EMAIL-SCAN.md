# Outbound e-mail scanning (report-only)

Finds e-mails sent to people **outside your organisation** whose body or attachments contain sensitive data
(the same rules as the agents) or an exact copy of a fingerprinted file. Every hour the server reads the
*Sent* folder of each mailbox for messages sent since the previous run and raises an
`EMAIL_EXTERNAL_SENSITIVE` alert per message:

```
severity=high rules=CREDIT-CARDx1 samples=CREDIT-CARD:41**************11 channel=email from=alice@acme.com
to=friend@gmail.com subject="Payment" attachments="customers.xlsx" sent=2026-10-02T09:00:00+00:00
```

**Report-only by design.** It never blocks, deletes, moves or modifies mail, and only reads messages that already
left. Matched values are masked; message bodies and attachments are never stored on the OpenDLP server.

## Before you enable it

Reading employees' outgoing mail is monitoring. In most countries you must tell employees in writing (e.g. in the
acceptable-use policy) and, in the EU/UK, document a legitimate interest or DPIA. Ask your legal adviser; see also
[COMPLIANCE.md](COMPLIANCE.md). Keep the number of people who can see alerts small (viewer accounts, SSO groups).

## Setup

E-mail scanning reuses the cloud scanning credentials ([CLOUD-SCAN.md](CLOUD-SCAN.md)) with one extra read-only
permission:

| Provider | Extra permission |
|---|---|
| Microsoft 365 | `Mail.Read` (**application** permission) on the same app registration, then *Grant admin consent*. To limit it to some mailboxes, use an Exchange [application access policy / RBAC for Applications](https://learn.microsoft.com/graph/auth-limit-mailbox-access). |
| Google Workspace | Add the scope `https://www.googleapis.com/auth/gmail.readonly` to the service account's domain-wide delegation (Admin console → Security → API controls). |

```env
OPENDLP_EMAIL_SCAN=1
# Domains that count as "inside" (default: the user's own domain / OPENDLP_GOOGLE_DOMAIN).
# Add subsidiaries and trusted partners to avoid alerts on mail to them.
OPENDLP_EMAIL_INTERNAL_DOMAINS=acme.com,acme.co.uk,payroll-partner.com
```

Restart the server. Check or run it now:

```bash
curl -H "Authorization: Bearer $OPENDLP_VIEWER_TOKEN" https://dlp.example.com/api/v1/admin/emailscan
curl -X POST -H "Authorization: Bearer $OPENDLP_ADMIN_TOKEN" https://dlp.example.com/api/v1/admin/emailscan/run
```

## What is inspected

- Recipients in To, Cc and Bcc; only messages with at least one external recipient are inspected, and only the
  external addresses are reported.
- Subject, body (HTML converted to text) and file attachments up to 10 MB: text, Office (docx/xlsx/pptx) and zip.
  Exact copies of fingerprinted files are found by hash in any format.
- At most 300 sent messages per mailbox per run. The first run covers the last 24 hours. If a mailbox fails, the
  window is not advanced, so the next run retries it (a message may then be reported twice).

Each run also records an `EMAIL_SCAN_SUMMARY` event (mailboxes, messages, external messages, findings, errors).

## Verification status

Tested against simulated Microsoft Graph and Gmail APIs (`server/tests/test_emailscan.py`); not yet run against a
real tenant. Reports from real deployments are welcome.
