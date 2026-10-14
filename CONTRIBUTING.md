# Contributing to Leakwarden

Thanks for helping! The most valuable contribution right now is **testing the Windows Agent** on a real machine.

## Test the Agent (no coding needed)
1. Download the latest zip from [Releases](../../releases) (check the SHA-256 in `SHA256SUMS.txt`).
2. Use a **disposable, authorized** Windows 10/11 machine or VM — never a production computer.
3. Follow the Agent section of the [README](README.md).
4. Open a **Windows test report** issue with what worked and what did not. Never include secrets, tokens, personal data or sensitive logs.

## Develop
- Server: `cd server && pip install -r requirements.txt -r requirements-dev.txt && python -m pytest -q`
- Agent: `.NET 8 SDK`, `dotnet build agent/Leakwarden.Agent.csproj`
- Please add or update tests for server changes and keep the README/CHANGELOG accurate. Do not describe a detection as "blocking" unless OS-level enforcement exists and is tested.

## Security issues
Report privately — see [SECURITY.md](SECURITY.md).

By contributing you agree your work is licensed under GPL-3.0-only.
