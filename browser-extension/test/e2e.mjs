// End-to-end test of the browser extension against a real Leakwarden server, in Chromium.
// Usage: node browser-extension/test/e2e.mjs   (needs: playwright, python with server requirements)
import { chromium } from "playwright";
import { spawn } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import crypto from "node:crypto";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(here, "..", "..");
const extDir = path.join(root, "browser-extension", "src");
const work = fs.mkdtempSync(path.join(os.tmpdir(), "leakwarden-ext-"));
const SERVER = "http://127.0.0.1:8771", PAGE = "http://127.0.0.1:8772/page.html";
const ADMIN = crypto.randomBytes(24).toString("hex"), ENROLL = crypto.randomBytes(12).toString("hex");
const H = { Authorization: "Bearer " + ADMIN, "Content-Type": "application/json" };
const procs = [];
let failed = false;

function fail(msg) { console.log("::error::EXTENSION-E2E: " + msg); failed = true; throw new Error(msg); }
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
async function waitUntil(fn, seconds, what) {
  for (let i = 0; i < seconds * 2; i++) { try { const r = await fn(); if (r) { console.log("ok: " + what); return r; } } catch {} await sleep(500); }
  fail("timed out waiting for: " + what);
}
const api = async (p, opt = {}) => (await fetch(SERVER + p, { headers: H, ...opt })).json();
const events = async (type) => (await api("/api/v1/events?limit=500&event_type=" + type));

// policy: block mode on the test host
const policy = JSON.parse(fs.readFileSync(path.join(root, "policies", "default-policy.json"), "utf8"));
policy.browser = { mode: "block", monitoredDomains: ["127.0.0.1"], blockedUploadDomains: [] };
fs.writeFileSync(path.join(work, "policy.json"), JSON.stringify(policy));

const py = process.platform === "win32" ? "python" : "python3";
procs.push(spawn(py, ["-m", "uvicorn", "main:app", "--host", "127.0.0.1", "--port", "8771"], {
  cwd: path.join(root, "server"), stdio: "inherit",
  env: { ...process.env, LEAKWARDEN_TOKEN: crypto.randomBytes(24).toString("hex"), LEAKWARDEN_ADMIN_TOKEN: ADMIN,
         LEAKWARDEN_ENROLL_CODE: ENROLL, LEAKWARDEN_DB: path.join(work, "db.sqlite"), LEAKWARDEN_POLICY: path.join(work, "policy.json") },
}));
procs.push(spawn(py, ["-m", "http.server", "8772", "--bind", "127.0.0.1", "--directory", path.join(here, "fixtures")], { stdio: "ignore" }));

let context;
try {
  await waitUntil(async () => (await fetch(SERVER + "/health")).ok, 30, "server up");
  context = await chromium.launchPersistentContext(path.join(work, "profile"), {
    channel: "chromium", headless: true,
    args: [`--disable-extensions-except=${extDir}`, `--load-extension=${extDir}`],
  });
  let [sw] = context.serviceWorkers();
  if (!sw) sw = await context.waitForEvent("serviceworker", { timeout: 15000 });

  await sw.evaluate(([url, code]) => chrome.storage.local.set({ serverUrl: url, enrollmentCode: code }), [SERVER, ENROLL]);
  const agent = await waitUntil(async () => (await api("/api/v1/agents")).find((a) => a.agent_id.startsWith("browser-") && a.enrolled), 30, "extension enrolled");
  await waitUntil(async () => (await sw.evaluate(() => chrome.storage.local.get("policy"))).policy?.browser?.mode === "block", 30, "signed policy applied");

  const page = await context.newPage();
  await page.goto(PAGE);
  await sleep(800);

  // 1. sensitive paste is blocked
  const pasteBlocked = await page.evaluate(() => {
    const dt = new DataTransfer(); dt.setData("text/plain", "Customer card number: 4111 1111 1111 1111");
    const ok = document.getElementById("t").dispatchEvent(new ClipboardEvent("paste", { bubbles: true, cancelable: true, clipboardData: dt }));
    return { canceled: !ok, seen: window.pasteSeen };
  });
  if (!pasteBlocked.canceled || pasteBlocked.seen !== 0) fail("sensitive paste was not blocked: " + JSON.stringify(pasteBlocked));
  console.log("ok: sensitive paste blocked");

  // 2. ordinary paste goes through
  const pasteOk = await page.evaluate(() => {
    const dt = new DataTransfer(); dt.setData("text/plain", "Can you summarise this meeting agenda?");
    const ok = document.getElementById("t").dispatchEvent(new ClipboardEvent("paste", { bubbles: true, cancelable: true, clipboardData: dt }));
    return { canceled: !ok, seen: window.pasteSeen };
  });
  if (pasteOk.canceled || pasteOk.seen !== 1) fail("harmless paste was blocked: " + JSON.stringify(pasteOk));
  console.log("ok: harmless paste allowed");

  // 3. upload of a file with an SSN is blocked; the page never sees it
  await page.setInputFiles("#f", { name: "payroll.csv", mimeType: "text/csv", buffer: Buffer.from("name,ssn\nAlice,123-45-6789\n") });
  await sleep(1500);
  const up1 = await page.evaluate(() => ({ seen: window.changeSeen, files: document.getElementById("f").files.length }));
  if (up1.seen !== 0 || up1.files !== 0) fail("sensitive upload was not blocked: " + JSON.stringify(up1));
  console.log("ok: sensitive upload blocked");

  // 4. clean upload is replayed to the page
  await page.setInputFiles("#f", { name: "agenda.txt", mimeType: "text/plain", buffer: Buffer.from("Agenda: roadmap, hiring, lunch") });
  await waitUntil(() => page.evaluate(() => window.changeSeen === 1 && window.lastFiles[0] === "agenda.txt"), 10, "clean upload reaches the page");

  // 5. fingerprinted confidential file (renamed) is blocked
  const secret = Buffer.from("Project Falcon - acquisition target list (draft)");
  await api("/api/v1/admin/fingerprints", { method: "POST", body: JSON.stringify({ name: "Board plan", sha256: crypto.createHash("sha256").update(secret).digest("hex") }) });
  await sw.evaluate(() => syncPolicy());
  await waitUntil(async () => ((await sw.evaluate(() => chrome.storage.local.get("policy"))).policy?.fingerprints || []).length === 1, 20, "fingerprint received");
  await page.reload(); await sleep(800);
  await page.setInputFiles("#f", { name: "holiday-notes.txt", mimeType: "text/plain", buffer: secret });
  await sleep(1500);
  const up2 = await page.evaluate(() => ({ seen: window.changeSeen, files: document.getElementById("f").files.length }));
  if (up2.seen !== 0 || up2.files !== 0) fail("fingerprinted upload was not blocked: " + JSON.stringify(up2));
  console.log("ok: fingerprinted upload blocked");

  // 6. the server received the events, with masked values
  await sw.evaluate(() => flush());
  const paste = await waitUntil(async () => (await events("BROWSER_PASTE")).find((e) => /action=blocked/.test(e.message)), 20, "BROWSER_PASTE event on server");
  if (/4111 1111 1111 1111/.test(paste.message)) fail("raw card number leaked: " + paste.message);
  const ups = await waitUntil(async () => { const u = await events("BROWSER_UPLOAD"); return u.length >= 2 ? u : null; }, 20, "BROWSER_UPLOAD events on server");
  if (!ups.some((e) => /US-SSN/.test(e.message) && /action=blocked/.test(e.message))) fail("no blocked SSN upload event");
  if (!ups.some((e) => /FINGERPRINT/.test(e.message) && /action=blocked/.test(e.message))) fail("no blocked fingerprint upload event");
  if (paste.agent_id !== agent.agent_id || paste.level !== "ALERT") fail("unexpected event metadata: " + JSON.stringify(paste));
  console.log("EXTENSION E2E PASSED");
} catch (e) {
  if (!failed) console.log("::error::EXTENSION-E2E: " + e.message);
  process.exitCode = 1;
} finally {
  if (context) await context.close().catch(() => {});
  for (const p of procs) p.kill();
}
