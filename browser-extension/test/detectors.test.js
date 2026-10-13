// Run: node --test browser-extension/test
const test = require("node:test");
const assert = require("node:assert");
const fs = require("node:fs");
const path = require("node:path");
const D = require("../src/detectors.js");

const vectors = JSON.parse(fs.readFileSync(path.join(__dirname, "..", "..", "tests", "vectors", "detectors.json"), "utf8"));

test("validators match shared vectors", () => {
  for (const [s, e] of vectors.luhn) assert.strictEqual(D.isValidCard(s), e, "luhn " + s);
  for (const [s, e] of vectors.tw_national_id) assert.strictEqual(D.isValidTwId(s), e, "twid " + s);
  for (const [s, e] of vectors.iban) assert.strictEqual(D.isValidIban(s), e, "iban " + s);
});

for (const c of vectors.scan) {
  test("scan: " + c.name, () => {
    const got = Object.fromEntries(D.scan(c.rules, c.text).map((h) => [h.ruleId, h.count]));
    assert.deepStrictEqual(got, c.expect);
  });
}

test("masked samples never contain the full value", () => {
  const hits = D.scan([{ id: "CC", type: "builtin", detector: "credit_card" }], "Card 4111 1111 1111 1111");
  assert.ok(!hits[0].sample.includes("1111 1111 1111"));
  assert.match(D.summarize(hits), /^severity=medium rules=CCx1 samples=CC:41/);
});

test("reads text inside docx and zip, hashes zip entries", async () => {
  const fx = path.join(__dirname, "fixtures");
  const docx = new Uint8Array(fs.readFileSync(path.join(fx, "sample.docx")));
  assert.match(await D.textOfBytes("sample.docx", docx), /GB82 WEST 1234 5698 7654 32/);
  const zip = new Uint8Array(fs.readFileSync(path.join(fx, "bundle.zip")));
  const text = await D.textOfBytes("bundle.zip", zip);
  assert.match(text, /4111 1111 1111 1111/);
  assert.match(text, /GB82 WEST 1234 5698 7654 32/);  // docx nested in zip
  const secret = fs.readFileSync(path.join(fx, "secret.txt"));
  const want = require("node:crypto").createHash("sha256").update(secret).digest("hex");
  const hashes = await D.hashesOfBytes("bundle.zip", zip);
  assert.ok(hashes.some((h) => h.sha256 === want && h.name === "renamed.txt"));
});

test("bundled default policy matches policies/default-policy.json", () => {
  const a = JSON.parse(fs.readFileSync(path.join(__dirname, "..", "src", "policy.default.json"), "utf8"));
  const b = JSON.parse(fs.readFileSync(path.join(__dirname, "..", "..", "policies", "default-policy.json"), "utf8"));
  assert.deepStrictEqual(a, b, "copy policies/default-policy.json to browser-extension/src/policy.default.json");
});
