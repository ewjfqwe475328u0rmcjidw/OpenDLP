# Compliance notes (starting point, not legal advice)

OpenDLP helps with the *technical and organisational measures* many data-protection laws require. It does not make an organisation compliant by itself. Check the specifics with counsel in your jurisdiction.

## How the features map

| OpenDLP capability | GDPR (EU/UK) | CCPA/CPRA (California) | PDPA (Taiwan 個資法) | PIPL (China) | LGPD (Brazil) |
|---|---|---|---|---|---|
| Detects personal data at rest / in motion (IDs, cards, passports, bulk e-mail) | Art. 32 security of processing; Art. 30 records help | §1798.150 reasonable security | 第27條 安全維護措施 | Art. 51 security measures | Art. 46 security measures |
| Alert + audit trail with timestamps | Art. 33/34 breach detection & notification evidence | Breach notification evidence | 第12條 事故通知 | Art. 57 breach notification | Art. 48 incident notification |
| Policy signing, token per machine, revocation | Art. 25 data protection by design | — | 施行細則第12條 | Art. 51 | Art. 46 |
| Event retention limit (`OPENDLP_RETENTION_DAYS`) | Art. 5(1)(e) storage limitation | — | 第11條 | Art. 19 | Art. 15–16 |
| Masked samples (never stores full matched values) | Art. 5(1)(c) data minimisation | — | 第5條 | Art. 6 | Art. 6 |

## Employee monitoring — do this before deployment

- **Inform employees** in writing what is monitored (file paths, clipboard text patterns, USB/print events), why, and for how long logs are kept. Many countries (EU, Germany in particular, Taiwan 勞基法 practice, Brazil) require notice; some require works-council agreement.
- **Minimise**: monitor company folders, not personal profiles; keep retention short; restrict dashboard access (viewer vs admin).
- **Document** the lawful basis (usually legitimate interest / legal obligation) and a short DPIA if you are in the EU/UK.
- **Secure the server**: HTTPS only, strong tokens, no public dashboard without a password.

## What OpenDLP does *not* give you

Certified controls (ISO 27001, SOC 2), legal hold, e-discovery, encryption of data at rest on endpoints, or guaranteed blocking. Describe it honestly in your own policies as a detection and alerting control.
