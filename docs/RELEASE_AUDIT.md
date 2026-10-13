# OpenDLP v0.12.0 — Release audit

## Verification status

| Area | How it is verified | Status |
|---|---|---|
| Server API (enrollment, roles, notifications, policy, charts, deploy page, PDF report, CSV, retention) | 52 automated tests, every push | ✅ |
| Docker image | built in CI, every push | ✅ |
| Windows agent + watchdog compile, unit tests (detectors, checksums, masking, policy store, ECDSA, DPAPI) | CI on `windows-latest` | ✅ |
| Windows console E2E: enrollment, DPAPI token, signed policy, telemetry, detection with masking, revocation | `tests/e2e/run-e2e.ps1` | ✅ |
| Windows fleet/service E2E: `Deploy-OpenDLP.ps1` (checksum refusal, idempotent), service install, `.docx`/`.xlsx`, **printing**, crash recovery, clean uninstall | `tests/e2e/run-service-e2e.ps1` | ✅ |
| macOS + Linux agent build and console E2E | `run-e2e.ps1` on `macos-latest` / `ubuntu-latest` | ✅ |
| macOS + Linux fleet/service E2E: `deploy-opendlp.sh`, launchd / systemd, 0600 secrets, detection, restart after crash, uninstall | `tests/e2e/run-unix-service-e2e.ps1` | ✅ |
| USB hardware, interactive clipboard helper, macOS Full Disk Access prompts, long-running stability | real hardware / desktop session needed | ❌ community reports welcome |
| OS-level blocking | Windows USB `block` dismounts drives (untested on hardware); everything else is audit/alert | ⚠️ |

## Scope

This package integrates the pasted v0.7.0 agent implementation with the existing FastAPI server and policy endpoint. It is an experimental audit/detection prototype, not a production-certified DLP product.

## Changes made during integration

- Replaced the old .NET agent entry point with the supplied .NET 8 Windows agent files.
- Added `policies/default-policy.json` and `GET /api/v1/policy`, including HMAC-SHA256 signatures compatible with the agent's key derivation.
- Added `304 Not Modified` behavior when the agent already has the current policy version.
- Server API authentication now fails closed if `OPENDLP_TOKEN` is unset or shorter than 32 bytes; there is no built-in fallback token.
- Telemetry requires `X-Agent-Id` and rejects a mismatch between the header and JSON payload.
- Removed local/legacy agent config files; only an example config is included and real config is ignored by Git.
- Added API tests for missing/weak/incorrect tokens, required Agent ID, Agent-ID mismatch, telemetry ingestion and batch limits, policy signature, unchanged policy responses, and missing policy files.
- Added a clear note that the browser extension is not implemented; its policy fields are placeholders.

## Checks performed

- Python syntax compilation.
- JSON parsing of policy and example configuration; XML parsing of both `.csproj` files.
- FastAPI tests: **11 passed** in this environment.
- Confirmed no real `agent.config.json` or runtime SQLite database is included in the release archive.
- Added explicit Windows packages for named-pipe ACL support and Big5/code-page decoding; registered the code-page provider.
- Corrected the watchdog heartbeat default to match the agent default log directory.
- .NET build was not run because the .NET SDK is not available in this environment.

## Important limitations / follow-up before production

- Build and test the agent on a clean Windows 10/11 machine with .NET 8. Test service lifecycle, helper IPC ACLs, clipboard permissions, removable media variants, and shutdown/restart behavior.
- The dashboard currently has no built-in authentication. Bind only to localhost or place it behind an authenticated reverse proxy; do not expose it publicly.
- The policy signature uses a shared secret derived from the API token. This is a prototype approach, not asymmetric code signing. Use TLS and protect/rotate the token.
- Audit events may contain sensitive file paths and filenames. Apply access controls, retention limits, consent/legal review, and data minimization.
- “block” policy values do not by themselves guarantee OS-level enforcement. Describe detections as audit/alert unless enforcement is implemented and tested.
- The watchdog has not been integrated into a formal Windows Service installer.
- Run dependency and static security scans before publishing releases.


## Community testing request

The Windows Agent has not yet been built or tested by maintainers on a clean Windows 10/11 + .NET 8 environment. Community testing is welcome, but only on an authorized, non-critical test device. Please report OS version, SDK version, build output, and observed behavior; do not submit secrets, personal data, or sensitive logs.
