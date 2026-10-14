// Leakwarden browser extension - content detectors - GPL-3.0-only
// JavaScript port of agent/Scanner.cs. Tested against tests/vectors/detectors.json like the C# and Python ports.
(function () {
  "use strict";

  // .NET "(?i)" prefixes are not valid in JavaScript: strip them and use the "i" flag.
  function rx(source, flags) {
    let f = flags || "";
    let s = source;
    if (s.startsWith("(?i)")) { s = s.slice(4); if (!f.includes("i")) f += "i"; }
    return new RegExp(s, f.includes("g") ? f : f + "g");
  }

  const NID = rx("(?<![A-Za-z0-9])[A-Z][12]\\d{8}(?!\\d)");
  const CARD = rx("(?<!\\d)(?:\\d[ -]?){12,18}\\d(?!\\d)");
  const MOBILE = rx("(?<!\\d)09\\d{2}[- ]?\\d{3}[- ]?\\d{3}(?!\\d)");
  const EMAIL = rx("[A-Za-z0-9._%+\\-]+@[A-Za-z0-9.\\-]+\\.[A-Za-z]{2,}");
  const TW_PASSPORT = rx("(?:passport|護照)[^\\d]{0,20}(?<![\\d])([1-3]\\d{8})(?!\\d)", "i");
  const API_KEY = rx(
    "(?:AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{22,}|xox[baprs]-[A-Za-z0-9-]{10,}" +
    "|AIza[0-9A-Za-z_\\-]{35}|sk_(?:live|test)_[0-9A-Za-z]{16,}|sk-[A-Za-z0-9]{20,}" +
    "|(?:[Aa][Pp][Ii][_-]?[Kk][Ee][Yy]|[Ss][Ee][Cc][Rr][Ee][Tt][_-]?[Kk][Ee][Yy]|[Aa][Cc][Cc][Ee][Ss][Ss][_-]?[Tt][Oo][Kk][Ee][Nn])" +
    "\\s*[:=]\\s*[\"']?[A-Za-z0-9_\\-]{16,})");
  const PRIVATE_KEY = rx("-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----");
  const IBAN = rx("(?<![A-Z0-9])[A-Z]{2}\\d{2}(?:[ ]?[A-Z0-9]{4}){2,7}[ ]?[A-Z0-9]{1,4}(?![A-Z0-9])");
  const SSN = rx("(?<![\\d-])(?!000|666|9\\d{2})\\d{3}-(?!00)\\d{2}-(?!0000)\\d{4}(?![\\d-])");
  const PASSPORT = rx("(?:passport|passeport|reisepass|pasaporte|passaporto|паспорт|护照|護照|パスポート|여권)" +
    "[\\s\\S]{0,20}?(?<![A-Za-z0-9])(?=[A-Z]*\\d)([A-Z0-9]{6,9})(?![A-Za-z0-9])", "i");

  const DEFAULT_CONTEXT = {
    credit_card: ["card", "credit", "visa", "mastercard", "amex", "payment", "cvv", "expiry", "信用卡", "卡號"],
    us_ssn: ["ssn", "social security", "taxpayer"],
    iban: ["iban", "bank", "account", "swift", "bic"],
    tw_national_id: ["身分證", "身份證", "national id", "id no", "統一編號"],
    tw_mobile: ["手機", "電話", "mobile", "phone", "tel"],
    email: ["email", "e-mail", "mail", "信箱"],
  };

  function isValidTwId(s) {
    const letters = "ABCDEFGHJKLMNPQRSTUVXYWZIO";
    if (s.length !== 10) return false;
    const idx = letters.indexOf(s[0]);
    if (idx < 0 || !/^\d{9}$/.test(s.slice(1))) return false;
    const code = idx + 10;
    const w = [1, 9, 8, 7, 6, 5, 4, 3, 2, 1, 1];
    let sum = Math.floor(code / 10) * w[0] + (code % 10) * w[1];
    for (let i = 1; i <= 9; i++) sum += Number(s[i]) * w[i + 1];
    return sum % 10 === 0;
  }

  function isValidCard(raw) {
    const d = [...raw].filter((c) => c >= "0" && c <= "9").map(Number);
    if (d.length < 13 || d.length > 19 || d[0] < 3 || d[0] > 6) return false;
    let sum = 0, dbl = false;
    for (let i = d.length - 1; i >= 0; i--) {
      let x = d[i];
      if (dbl) { x *= 2; if (x > 9) x -= 9; }
      sum += x; dbl = !dbl;
    }
    return sum % 10 === 0;
  }

  function isValidIban(raw) {
    const s = raw.replace(/ /g, "").toUpperCase();
    if (s.length < 15 || s.length > 34) return false;
    const r = s.slice(4) + s.slice(0, 4);
    let rem = 0;
    for (const c of r) {
      let v;
      if (c >= "0" && c <= "9") v = c.charCodeAt(0) - 48;
      else if (c >= "A" && c <= "Z") v = c.charCodeAt(0) - 55;
      else return false;
      rem = v < 10 ? (rem * 10 + v) % 97 : (rem * 100 + v) % 97;
    }
    return rem === 1;
  }

  const any = () => true;
  const BUILTIN = {
    tw_national_id: [NID, isValidTwId], credit_card: [CARD, isValidCard], tw_mobile: [MOBILE, any],
    email: [EMAIL, any], tw_passport: [TW_PASSPORT, any], api_key: [API_KEY, any], private_key: [PRIVATE_KEY, any],
    iban: [IBAN, isValidIban], us_ssn: [SSN, any], passport: [PASSPORT, any],
  };

  function mask(s) {
    return s.length <= 4 ? "*".repeat(s.length) : s.slice(0, 2) + "*".repeat(s.length - 4) + s.slice(-2);
  }

  function hasContext(text, index, length, words) {
    const around = text.slice(Math.max(0, index - 60), index + length + 60).toLowerCase();
    return words.some((w) => w && around.includes(String(w).toLowerCase()));
  }

  const cache = new Map();
  function compile(p) {
    if (!p) return null;
    if (!cache.has(p)) { try { cache.set(p, rx(p)); } catch { cache.set(p, null); } }
    const r = cache.get(p);
    if (r) r.lastIndex = 0;
    return r;
  }

  function matchesOf(re, text) {
    re.lastIndex = 0;
    return [...text.matchAll(re)];
  }

  function run(rule, text) {
    const type = String(rule.type || "builtin").toLowerCase();
    if (type === "keywords") {
      let total = 0, sample = "";
      const low = text.toLowerCase();
      for (const kw of rule.keywords || []) {
        if (!kw) continue;
        const k = String(kw).toLowerCase();
        let n = 0, pos = 0;
        while ((pos = low.indexOf(k, pos)) >= 0) { n++; pos += k.length; }
        if (n && !sample) sample = kw;
        total += n;
      }
      return [total, sample];
    }
    if (type === "regex") {
      const re = compile(rule.pattern);
      if (!re) return [0, ""];
      const ms = matchesOf(re, text);
      return [ms.length, ms.length ? mask(ms[0][0]) : ""];
    }
    const det = String(rule.detector || "").toLowerCase();
    const b = BUILTIN[det];
    if (!b) return [0, ""];
    const excludes = (rule.exclude || []).map(compile).filter(Boolean);
    const ctx = rule.contextWords && rule.contextWords.length ? rule.contextWords : DEFAULT_CONTEXT[det] || [];
    let n = 0, sample = "";
    for (const m of matchesOf(b[0], text)) {
      const v = m[0];
      if (!b[1](v)) continue;
      if (excludes.some((x) => { x.lastIndex = 0; return x.test(v); })) continue;
      if (rule.requireContext && ctx.length && !hasContext(text, m.index, v.length, ctx)) continue;
      n++;
      if (!sample) sample = mask(v);
    }
    return [n, sample];
  }

  function scan(rules, text) {
    const hits = [];
    if (!text) return hits;
    for (const r of rules || []) {
      let res;
      try { res = run(r, text); } catch { continue; }
      if (res[0] >= Math.max(1, r.minMatches || 1)) {
        hits.push({ ruleId: r.id || "", name: r.name || "", severity: r.severity || "medium",
          action: String(r.action || "alert").toLowerCase(), count: res[0], sample: res[1] });
      }
    }
    return hits;
  }

  function worstSeverity(hits) {
    const rank = { critical: 4, high: 3, medium: 2, low: 1 };
    return hits.map((h) => h.severity).sort((a, b) => (rank[b] || 0) - (rank[a] || 0))[0] || "low";
  }

  function summarize(hits) {
    return "severity=" + worstSeverity(hits) + " rules=" + hits.map((h) => h.ruleId + "x" + h.count).join(",") +
      " samples=" + hits.map((h) => h.ruleId + ":" + h.sample).join(",");
  }

  // ---- minimal ZIP reader (stored + deflate) for .docx/.xlsx/.pptx/.zip uploads ----
  const TEXT_EXT = /\.(txt|csv|tsv|log|json|xml|md|html?|ini|ya?ml|sql|eml)$/i;
  const OOXML_PARTS = {
    docx: (n) => n === "word/document.xml",
    xlsx: (n) => n === "xl/sharedStrings.xml" || (n.startsWith("xl/worksheets/") && n.endsWith(".xml")),
    pptx: (n) => n.startsWith("ppt/slides/slide") && n.endsWith(".xml"),
  };

  async function inflateRaw(bytes) {
    const ds = new DecompressionStream("deflate-raw");
    const out = new Response(new Blob([bytes]).stream().pipeThrough(ds));
    return new Uint8Array(await out.arrayBuffer());
  }

  async function zipEntries(buf, maxEntries = 300) {
    const dv = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
    let eocd = -1;
    for (let i = buf.length - 22; i >= Math.max(0, buf.length - 66000); i--) {
      if (dv.getUint32(i, true) === 0x06054b50) { eocd = i; break; }
    }
    if (eocd < 0) return [];
    const count = dv.getUint16(eocd + 10, true);
    let p = dv.getUint32(eocd + 16, true);
    const td = new TextDecoder();
    const entries = [];
    for (let i = 0; i < Math.min(count, maxEntries); i++) {
      if (dv.getUint32(p, true) !== 0x02014b50) break;
      const method = dv.getUint16(p + 10, true);
      const flags = dv.getUint16(p + 8, true);
      const csize = dv.getUint32(p + 20, true);
      const nlen = dv.getUint16(p + 28, true), elen = dv.getUint16(p + 30, true), clen = dv.getUint16(p + 32, true);
      const local = dv.getUint32(p + 42, true);
      const name = td.decode(buf.subarray(p + 46, p + 46 + nlen));
      p += 46 + nlen + elen + clen;
      if (flags & 1) continue; // encrypted
      const lnlen = dv.getUint16(local + 26, true), lelen = dv.getUint16(local + 28, true);
      const start = local + 30 + lnlen + lelen;
      const data = buf.subarray(start, start + csize);
      entries.push({ name, read: async () => (method === 0 ? data : method === 8 ? inflateRaw(data) : new Uint8Array()) });
    }
    return entries;
  }

  async function textOfBytes(name, bytes, depth = 0) {
    const ext = (name.split(".").pop() || "").toLowerCase();
    if (TEXT_EXT.test(name)) return new TextDecoder().decode(bytes);
    if (OOXML_PARTS[ext] || ext === "zip") {
      let out = "";
      for (const e of await zipEntries(bytes)) {
        if (OOXML_PARTS[ext]) {
          if (OOXML_PARTS[ext](e.name)) out += new TextDecoder().decode(await e.read()).replace(/<[^>]+>/g, " ") + " ";
        } else if (depth === 0 && !e.name.endsWith("/")) {
          out += (await textOfBytes(e.name, await e.read(), 1)) + "\n";
        }
        if (out.length > 4000000) break;
      }
      return out;
    }
    return "";
  }

  async function sha256Hex(bytes) {
    const d = await crypto.subtle.digest("SHA-256", bytes);
    return [...new Uint8Array(d)].map((b) => b.toString(16).padStart(2, "0")).join("");
  }

  /** SHA-256 of the file and, for .zip, of every entry. */
  async function hashesOfBytes(name, bytes) {
    const out = [{ name, sha256: await sha256Hex(bytes) }];
    if (/\.zip$/i.test(name)) {
      for (const e of await zipEntries(bytes)) {
        if (!e.name.endsWith("/")) out.push({ name: e.name, sha256: await sha256Hex(await e.read()) });
      }
    }
    return out;
  }

  const api = { scan, summarize, worstSeverity, mask, hasContext, isValidCard, isValidTwId, isValidIban,
    textOfBytes, hashesOfBytes, sha256Hex, zipEntries, DEFAULT_CONTEXT };
  if (typeof module !== "undefined" && module.exports) module.exports = api;
  else globalThis.LeakwardenDetectors = api;
})();
