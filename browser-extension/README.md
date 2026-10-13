# OpenDLP browser extension (Chrome / Edge)

Stops sensitive data from being **pasted, dropped or uploaded** into AI chats, personal cloud drives and file-sharing sites - the most common way data leaves a company today.

- Checks pasted text, dragged text/files and `<input type=file>` uploads on the sites listed in the policy (`browser.monitoredDomains`; default: ChatGPT, Claude, Gemini, Copilot, Perplexity, DeepSeek, Google Drive/Docs, Dropbox, OneDrive, Box, WeTransfer, MEGA, Pastebin, Gist, WhatsApp/Telegram Web).
- Same detection rules as the endpoint agents (cards, IBAN, SSN, passports, API keys, private keys, keywords, custom regex), including text inside `.docx/.xlsx/.pptx/.zip`, and **file fingerprints** (exact copies of registered confidential files, even renamed).
- `browser.mode`: `audit` (record only), `warn` (show a warning, allow), `block` (stop it). `browser.blockedUploadDomains`: no uploads at all to these sites.
- Self-enrolls with the server, verifies the signed policy (HMAC, and ECDSA when `policySigningPublicKey` is set) and reports events (`BROWSER_PASTE`, `BROWSER_DROP`, `BROWSER_UPLOAD`) with masked samples. The content itself never leaves the browser.

## Install for a whole company (managed)

1. Publish the `src` folder (or the release's `OpenDLP-browser-extension-*.zip`) to the **Chrome Web Store** and/or **Microsoft Edge Add-ons** under your own developer account, or host it internally.
2. Force-install it with **Intune** / **Group Policy** (`ExtensionInstallForcelist`) or your MDM.
3. Configure it with the managed-storage policy (`3rdparty → extensions → <extension id>`), e.g. for Intune / GPO JSON:

```json
{ "serverUrl": "https://dlp.example.com", "enrollmentCode": "<OPENDLP_ENROLL_CODE>", "displayName": "Company laptops" }
```

Optional: `agentId`, `policySigningPublicKey`. Managed settings cannot be changed by the user.

## Try it on one machine

`chrome://extensions` (or `edge://extensions`) → enable *Developer mode* → *Load unpacked* → select `browser-extension/src`. Open the extension's options to enter the server URL and enrollment code.

## Limits (be honest with your users)

- It protects the browsers it is installed in. Block other browsers or make the extension mandatory via policy.
- Files larger than 25 MB and formats other than text / Office / zip are not content-inspected (fingerprints still apply up to 25 MB).
- Sites that read the clipboard through custom APIs or upload via non-standard widgets may bypass the checks.

## Tests

`node --test test/detectors.test.js` (shared vectors) and `node test/e2e.mjs` (real Chromium + server: enrollment, signed policy, blocked/allowed paste, blocked/allowed upload, fingerprint, events). Both run in CI.
