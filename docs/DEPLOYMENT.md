# Deploying OpenDLP to many machines

The fastest way: open **Dashboard → Deploy agents** (admin login). It shows every command below with your server URL and enrollment code already filled in.

Every machine enrolls itself with the shared enrollment code and receives its **own token** (Windows: DPAPI-encrypted; macOS/Linux: root-only file). Rotate the enrollment code after a rollout; enrolled machines are not affected. Revoke a single machine with `POST /api/v1/admin/agents/<id>/revoke`.

Both deploy scripts:
- download the package for the right OS/CPU from the GitHub release (or use a local / file-share copy),
- **refuse to install if the SHA-256 does not match** `SHA256SUMS.txt`,
- are **idempotent** - machines that already run the requested version are skipped, so you can schedule them repeatedly,
- exit `0` on success / already installed and non-zero on failure (management tools report this).

These behaviours are exercised in CI on clean Windows, macOS and Linux VMs (`tests/e2e/`).

## Windows

`Deploy-OpenDLP.ps1` (attached to every release). Runs on Windows PowerShell 5.1 and PowerShell 7, any display language. Packages are self-contained: no .NET install needed. Log: `%ProgramData%\OpenDLP\deploy.log`.

```powershell
.\Deploy-OpenDLP.ps1 -ServerUrl https://dlp.example.com -EnrollmentCode "CODE"
# offline / LAN share
.\Deploy-OpenDLP.ps1 -ServerUrl https://dlp.example.com -EnrollmentCode "CODE" `
    -PackagePath \\fileserver\it\OpenDLP-windows-x64-v0.12.0.zip -ExpectedSha256 <hash>
# optional: -SensitivePaths "D:\Finance","{AllUsers}\Documents"   -Force (reinstall)
```

**Microsoft Intune** - Devices → Scripts and remediations → Platform scripts → Add (Windows 10 and later). Upload a small wrapper:

```powershell
$f = Join-Path $env:TEMP 'Deploy-OpenDLP.ps1'
Invoke-WebRequest -UseBasicParsing 'https://github.com/<owner>/<repo>/releases/download/v0.12.0/Deploy-OpenDLP.ps1' -OutFile $f
& $f -ServerUrl 'https://dlp.example.com' -EnrollmentCode 'CODE'
exit $LASTEXITCODE
```

Run this script using the logged on credentials: **No**. Run script in 64-bit PowerShell host: **Yes**. Assign to a device group.

**Group Policy** - Computer Configuration → Policies → Windows Settings → Scripts (Startup/Shutdown) → Startup → *PowerShell Scripts* tab → Add `Deploy-OpenDLP.ps1` (copy it to `\\domain\SYSVOL\...\Scripts\Startup`) with parameters `-ServerUrl https://dlp.example.com -EnrollmentCode CODE -PackagePath \\fileserver\it\OpenDLP-windows-x64-v0.12.0.zip -ExpectedSha256 <hash>`. Startup scripts run as SYSTEM at boot.

**RMM / PDQ / SCCM** - run the script as SYSTEM with the same parameters.

## macOS and Linux

`deploy-opendlp.sh` (attached to every release) picks `macos-arm64`, `macos-x64` or `linux-x64` automatically; macOS uses launchd, Linux uses systemd. The service manager restarts the agent if it stops.

```bash
curl -fsSL https://github.com/<owner>/<repo>/releases/download/v0.12.0/deploy-opendlp.sh \
  | sudo bash -s -- --server-url https://dlp.example.com --enrollment-code "CODE"
# local copy:  --package /path/OpenDLP-macos-arm64-v0.12.0.tar.gz --sha256 <hash>
# passed to install.sh:  --paths "{AllUsers}/Documents,/srv/finance"  --agent-id NAME  --display-name "Finance laptop"
```

**Jamf Pro / Kandji / Mosyle / Intune for Mac** - add the one-liner above as a policy script (runs as root).

**Full Disk Access (macOS)** - macOS privacy protection (TCC) hides Desktop, Documents and Downloads from background services. Grant `/Library/Application Support/OpenDLP/bin/opendlp-agent` Full Disk Access: manually in System Settings → Privacy & Security → Full Disk Access, or with a PPPC (Privacy Preferences Policy Control) configuration profile from your MDM. Folders outside the protected locations work without it.

**Linux fleets** - Ansible example:

```yaml
- hosts: workstations
  become: true
  tasks:
    - name: Deploy OpenDLP agent
      ansible.builtin.shell: >
        curl -fsSL https://github.com/<owner>/<repo>/releases/download/v0.12.0/deploy-opendlp.sh
        | bash -s -- --server-url https://dlp.example.com --enrollment-code "{{ opendlp_enroll_code }}"
```

## Uninstall

- Windows: `& "C:\Program Files\OpenDLP\uninstall-service.ps1"` (add `-RemoveLogs` to delete local logs and the machine token)
- macOS: `sudo "/Library/Application Support/OpenDLP/bin/uninstall.sh" --remove-data`
- Linux: `sudo /opt/opendlp/uninstall.sh --remove-data`

Then delete the agent on the server: `DELETE /api/v1/admin/agents/<id>`.
