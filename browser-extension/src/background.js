// OpenDLP browser extension - service worker - GPL-3.0-only
// Enrolls with the OpenDLP server, keeps the signed policy, queues and uploads events.
const VERSION = chrome.runtime.getManifest().version;
const POLL_MINUTES = 1;

async function getConfig() {
  let managed = {};
  try { managed = await chrome.storage.managed.get(null); } catch { /* not managed */ }
  const local = await chrome.storage.local.get(["serverUrl", "enrollmentCode", "agentId", "displayName", "policySigningPublicKey", "installId"]);
  let installId = local.installId;
  if (!installId) {
    installId = crypto.randomUUID().replace(/-/g, "").slice(0, 10);
    await chrome.storage.local.set({ installId });
  }
  const pick = (k) => (managed[k] !== undefined && managed[k] !== "" ? managed[k] : local[k] || "");
  return {
    serverUrl: String(pick("serverUrl")).replace(/\/+$/, ""),
    enrollmentCode: pick("enrollmentCode"),
    agentId: pick("agentId") || "browser-" + installId,
    displayName: pick("displayName") || "Browser extension",
    publicKey: pick("policySigningPublicKey"),
    managed: Object.keys(managed).length > 0,
  };
}

let defaultPolicy = null;
async function currentPolicy() {
  const { policy } = await chrome.storage.local.get("policy");
  if (policy) return policy;
  if (!defaultPolicy) defaultPolicy = await (await fetch(chrome.runtime.getURL("policy.default.json"))).json();
  return { ...defaultPolicy, version: 0 };
}

// ---------- crypto helpers ----------
const enc = new TextEncoder();
const hex = (buf) => [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");

async function verifyHmac(token, policyJson, sig) {
  const keyHex = hex(await crypto.subtle.digest("SHA-256", enc.encode(token)));
  const key = await crypto.subtle.importKey("raw", enc.encode(keyHex), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const mac = hex(await crypto.subtle.sign("HMAC", key, enc.encode(policyJson)));
  if (mac.length !== String(sig).length) return false;
  let diff = 0;
  for (let i = 0; i < mac.length; i++) diff |= mac.charCodeAt(i) ^ String(sig).toLowerCase().charCodeAt(i);
  return diff === 0;
}

function derToRaw(der) {
  // ECDSA DER SEQUENCE(INTEGER r, INTEGER s) -> 64-byte r||s for WebCrypto
  let p = 2;
  if (der[1] & 0x80) p = 2 + (der[1] & 0x7f);
  const read = () => { p++; const len = der[p++]; const v = der.slice(p, p + len); p += len; return v; };
  const fix = (v) => { while (v.length > 32 && v[0] === 0) v = v.slice(1); const o = new Uint8Array(32); o.set(v, 32 - v.length); return o; };
  const r = fix(read()), s = fix(read());
  const out = new Uint8Array(64); out.set(r, 0); out.set(s, 32); return out;
}

async function verifyEcdsa(pem, policyJson, pubSig) {
  if (!pubSig) return false;
  const b64 = pem.replace(/-----[^-]+-----/g, "").replace(/\s+/g, "");
  const spki = Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
  const key = await crypto.subtle.importKey("spki", spki, { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"]);
  const sig = derToRaw(Uint8Array.from(atob(pubSig), (c) => c.charCodeAt(0)));
  return crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, key, sig, enc.encode(policyJson));
}

// ---------- server communication ----------
async function headers(cfg, token) {
  return { Authorization: "Bearer " + token, "X-Agent-Id": cfg.agentId, "X-Agent-Version": VERSION, "Content-Type": "application/json" };
}

async function ensureToken(cfg) {
  const { token } = await chrome.storage.local.get("token");
  if (token) return token;
  if (!cfg.serverUrl || !cfg.enrollmentCode) return "";
  const r = await fetch(cfg.serverUrl + "/api/v1/enroll", {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ agentId: cfg.agentId, enrollmentCode: cfg.enrollmentCode, host: "browser", displayName: cfg.displayName }),
  });
  if (!r.ok) { await setStatus("Enrollment failed: HTTP " + r.status); return ""; }
  const body = await r.json();
  await chrome.storage.local.set({ token: body.token });
  await queueEvent("INFO", "BROWSER_ENROLLED", "Browser extension enrolled (" + navigator.userAgent.split(") ")[0] + ")");
  return body.token;
}

async function setStatus(s) { await chrome.storage.local.set({ status: s, statusAt: new Date().toISOString() }); }

async function syncPolicy() {
  const cfg = await getConfig();
  if (!cfg.serverUrl) { await setStatus("Not connected: no server configured (local default policy)"); return; }
  try {
    const token = await ensureToken(cfg);
    if (!token) return;
    const pol = await currentPolicy();
    const r = await fetch(cfg.serverUrl + "/api/v1/policy?version=" + (pol.version || 0), { headers: await headers(cfg, token) });
    if (r.status === 304) { await setStatus("Connected, policy v" + pol.version); return; }
    if (r.status === 401 || r.status === 403) {
      await setStatus("Rejected by server (HTTP " + r.status + "): revoked or wrong token");
      if (r.status === 403) await chrome.storage.local.remove("token");
      return;
    }
    if (!r.ok) { await setStatus("Policy fetch failed: HTTP " + r.status); return; }
    const env = await r.json();
    let ok = await verifyHmac(token, env.policyJson, env.sig);
    if (ok && cfg.publicKey) ok = await verifyEcdsa(cfg.publicKey, env.policyJson, env.pubSig);
    if (!ok) { await queueEvent("ALERT", "POLICY_SIG_INVALID", "severity=high Policy signature mismatch; keeping current policy"); return; }
    const doc = JSON.parse(env.policyJson);
    doc.version = env.version;
    await chrome.storage.local.set({ policy: doc });
    await queueEvent("INFO", "POLICY_UPDATED", "Policy version " + env.version + " applied");
    await setStatus("Connected, policy v" + env.version);
  } catch (e) {
    await setStatus("Server unreachable: " + e.message);
  }
}

async function queueEvent(level, eventType, message) {
  const { queue = [] } = await chrome.storage.local.get("queue");
  queue.push({ ts: new Date().toISOString(), level, eventType, message: String(message).slice(0, 4000), host: "browser" });
  await chrome.storage.local.set({ queue: queue.slice(-1000) });
  flushSoon();
}

let flushTimer = null;
function flushSoon() { if (!flushTimer) flushTimer = setTimeout(() => { flushTimer = null; flush(); }, 1500); }

async function flush() {
  const cfg = await getConfig();
  const { queue = [], token } = await chrome.storage.local.get(["queue", "token"]);
  if (!queue.length || !cfg.serverUrl || !token) return;
  const batch = queue.slice(0, 200);
  try {
    const r = await fetch(cfg.serverUrl + "/api/v1/telemetry", {
      method: "POST", headers: await headers(cfg, token),
      body: JSON.stringify({ agentId: cfg.agentId, sentAt: new Date().toISOString(), events: batch }),
    });
    if (r.ok) {
      const { queue: latest = [] } = await chrome.storage.local.get("queue");
      await chrome.storage.local.set({ queue: latest.slice(batch.length) });
      if (latest.length > batch.length) flushSoon();
    }
  } catch { /* retry on next event / alarm */ }
}

// ---------- messages from content scripts ----------
function domainMatches(host, list) {
  host = String(host || "").toLowerCase();
  return (list || []).some((d) => { d = String(d).toLowerCase().replace(/^\*\./, ""); return host === d || host.endsWith("." + d); });
}

chrome.runtime.onMessage.addListener((msg, _sender, reply) => {
  (async () => {
    if (msg.type === "policyFor") {
      const pol = await currentPolicy();
      const b = pol.browser || {};
      const blockedUpload = domainMatches(msg.host, b.blockedUploadDomains);
      const monitored = !b.monitoredDomains || b.monitoredDomains.length === 0 || domainMatches(msg.host, b.monitoredDomains);
      reply({ active: monitored || blockedUpload, mode: b.mode || "audit", blockedUpload, rules: pol.rules || [],
        fingerprints: (pol.fingerprints || []).map((f) => ({ sha256: String(f.sha256).toLowerCase(), name: f.name })) });
    } else if (msg.type === "event") {
      await queueEvent(msg.level, msg.eventType, msg.message);
      reply({ ok: true });
    } else if (msg.type === "status") {
      reply({ ...(await chrome.storage.local.get(["status", "statusAt", "policy"])), config: await getConfig() });
    } else if (msg.type === "sync") {
      await syncPolicy(); await flush(); reply({ ok: true });
    }
  })();
  return true;
});

chrome.alarms.create("opendlp-sync", { periodInMinutes: POLL_MINUTES });
chrome.alarms.onAlarm.addListener(() => { syncPolicy().then(flush); });
chrome.runtime.onInstalled.addListener(() => syncPolicy().then(flush));
chrome.runtime.onStartup.addListener(() => syncPolicy().then(flush));
chrome.storage.onChanged.addListener((changes, area) => {
  if (area === "managed" || (area === "local" && (changes.serverUrl || changes.enrollmentCode))) {
    chrome.storage.local.remove(["token", "policy"]).then(syncPolicy).then(flush);
  }
});
