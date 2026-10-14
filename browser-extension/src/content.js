// Leakwarden browser extension - content script - GPL-3.0-only
// Watches paste, drag-and-drop and file uploads on monitored sites. Text is checked synchronously; files are
// checked asynchronously (in block mode the original event is held and replayed only if the files are clean).
(() => {
  "use strict";
  const D = globalThis.LeakwardenDetectors;
  if (!D || window.__leakwardenLoaded) return;
  window.__leakwardenLoaded = true;

  const host = location.hostname;
  let cfg = null;
  const replayed = new WeakSet();
  const MAX_FILE = 25 * 1024 * 1024;

  async function load() {
    try { cfg = await chrome.runtime.sendMessage({ type: "policyFor", host }); } catch { cfg = null; }
  }
  load();
  setInterval(load, 60000);

  function send(level, eventType, message) {
    try { chrome.runtime.sendMessage({ type: "event", level, eventType, message }); } catch { /* extension reloaded */ }
  }

  // ---------- UI ----------
  function toast(text, kind) {
    try {
      const hostEl = document.createElement("div");
      hostEl.setAttribute("data-leakwarden-toast", kind);
      const root = hostEl.attachShadow({ mode: "closed" });
      const bg = kind === "blocked" ? "#7f1d1d" : "#78350f";
      root.innerHTML = `<div style="position:fixed;top:16px;right:16px;z-index:2147483647;max-width:380px;background:${bg};
        color:#fff;font:14px/1.4 system-ui,sans-serif;padding:12px 14px;border-radius:10px;box-shadow:0 8px 24px rgba(0,0,0,.35)">
        <b>Leakwarden</b><br></div>`;
      root.querySelector("div").append(document.createTextNode(text));
      (document.body || document.documentElement).appendChild(hostEl);
      setTimeout(() => hostEl.remove(), 7000);
    } catch { /* page without DOM access */ }
  }

  // ---------- decisions ----------
  function verdict(hits) {
    if (!hits.length || !cfg) return { block: false, alert: false };
    const alert = hits.some((h) => h.action === "alert" || h.action === "block");
    const block = cfg.mode === "block" ? alert : false;
    return { block, alert };
  }

  function describe(hits) {
    return [...new Set(hits.map((h) => h.name || h.ruleId))].slice(0, 3).join(", ");
  }

  function record(channel, hits, blocked, extra) {
    const v = verdict(hits);
    const msg = `${D.summarize(hits)} action=${blocked ? "blocked" : "allowed"} channel=${channel} site=${host}${extra || ""}`;
    send(v.alert || blocked ? "ALERT" : "INFO", "BROWSER_" + channel.toUpperCase(), msg);
  }

  function scanText(text) {
    return cfg && text ? D.scan(cfg.rules, text) : [];
  }

  async function scanFiles(files) {
    const hits = [];
    const names = [];
    for (const f of files) {
      names.push(f.name);
      if (f.size > MAX_FILE) continue;
      const bytes = new Uint8Array(await f.arrayBuffer());
      if (cfg.fingerprints && cfg.fingerprints.length) {
        const known = new Map(cfg.fingerprints.map((x) => [x.sha256, x.name]));
        for (const h of await D.hashesOfBytes(f.name, bytes)) {
          if (known.has(h.sha256)) {
            hits.push({ ruleId: "FINGERPRINT", name: "Confidential file: " + known.get(h.sha256), severity: "critical", action: "block", count: 1, sample: h.name });
            break;
          }
        }
      }
      const text = await D.textOfBytes(f.name, bytes).catch(() => "");
      hits.push(...D.scan(cfg.rules, text));
    }
    return { hits, names };
  }

  function stop(e) { e.preventDefault(); e.stopImmediatePropagation(); }

  // ---------- text paste / drop (synchronous) ----------
  function onText(e, channel, text) {
    const hits = scanText(text);
    if (!hits.length) return;
    const v = verdict(hits);
    if (v.block) {
      stop(e);
      toast(`Paste blocked: ${describe(hits)} on ${host}. Contact IT if this is needed for work.`, "blocked");
    } else if (cfg.mode === "warn" && v.alert) {
      toast(`Careful: this looks like ${describe(hits)}. Pasting it into ${host} may leak company data.`, "warn");
    }
    record(channel, hits, v.block);
  }

  // ---------- files (asynchronous) ----------
  function handleFiles(e, files, channel, replay, onDone) {
    const done = () => { try { if (onDone) onDone(); } catch { /* ignore */ } };
    if (cfg.blockedUpload && cfg.mode !== "audit") {
      done();
      stop(e);
      if (channel === "upload") e.target.value = "";
      toast(`Uploads to ${host} are not allowed by company policy.`, "blocked");
      send("ALERT", "BROWSER_" + channel.toUpperCase(),
        `severity=high rules=BLOCKED-SITEx1 samples=BLOCKED-SITE:${host} action=blocked channel=${channel} site=${host} files=${files.length}`);
      return;
    }
    const holding = cfg.mode === "block";
    if (holding) stop(e);
    scanFiles(files).then(({ hits, names }) => {
      done();
      const v = verdict(hits);
      const fileInfo = ` file="${names.join("|").replace(/"/g, "'").slice(0, 200)}"`;
      if (hits.length) record(channel, hits, holding && v.block, fileInfo);
      if (holding && v.block) {
        if (channel === "upload") e.target.value = "";
        toast(`Upload blocked: ${describe(hits)} found in ${names.join(", ").slice(0, 80)}.`, "blocked");
        return;
      }
      if (!holding && cfg.mode === "warn" && v.alert) {
        toast(`Careful: ${names.join(", ").slice(0, 80)} contains ${describe(hits)}.`, "warn");
      }
      if (holding) replay();
    }).catch(() => { done(); if (holding) replay(); });
  }

  window.addEventListener("paste", (e) => {
    if (!cfg || !cfg.active || replayed.has(e) || !e.clipboardData) return;
    const files = [...e.clipboardData.files];
    if (files.length) {
      handleFiles(e, files, "paste", () => {
        const dt = new DataTransfer(); files.forEach((f) => dt.items.add(f));
        const ev = new ClipboardEvent("paste", { bubbles: true, cancelable: true, clipboardData: dt });
        replayed.add(ev); e.target.dispatchEvent(ev);
      });
    } else {
      onText(e, "paste", e.clipboardData.getData("text/plain"));
    }
  }, true);

  window.addEventListener("drop", (e) => {
    if (!cfg || !cfg.active || replayed.has(e) || !e.dataTransfer) return;
    const files = [...e.dataTransfer.files];
    if (files.length) {
      handleFiles(e, files, "drop", () => {
        const dt = new DataTransfer(); files.forEach((f) => dt.items.add(f));
        const ev = new DragEvent("drop", { bubbles: true, cancelable: true, dataTransfer: dt, clientX: e.clientX, clientY: e.clientY });
        replayed.add(ev); e.target.dispatchEvent(ev);
      });
    } else {
      onText(e, "drop", e.dataTransfer.getData("text/plain"));
    }
  }, true);

  // <input type=file>: the page reacts to "input" and "change"; hold both until the files are cleared.
  const pendingInputs = new WeakSet();
  function onFileInput(e) {
    const t = e.target;
    if (!cfg || !cfg.active || replayed.has(e) || !(t instanceof HTMLInputElement) || t.type !== "file" || !t.files || !t.files.length) return;
    const holding = cfg.mode === "block" || (cfg.blockedUpload && cfg.mode !== "audit");
    if (pendingInputs.has(t)) { if (holding) stop(e); return; }   // the "change" that follows "input"
    const files = [...t.files];
    pendingInputs.add(t);   // also in audit/warn mode, so "input" + "change" are reported once
    handleFiles(e, files, "upload", () => {
      for (const type of ["input", "change"]) {
        const ev = new Event(type, { bubbles: true });
        replayed.add(ev); t.dispatchEvent(ev);
      }
    }, () => pendingInputs.delete(t));
  }
  window.addEventListener("input", onFileInput, true);
  window.addEventListener("change", onFileInput, true);
})();
