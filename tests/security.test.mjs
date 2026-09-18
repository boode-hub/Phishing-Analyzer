// Hardening regressions.
//
// Each of these is a property the app must keep, not a behaviour a user sees:
// an inline handler, a third-party asset or an open relay would all pass every
// other suite while quietly re-opening a hole.
// Run: node tests/security.test.mjs

import assert from "node:assert/strict";
import { readFileSync, readdirSync } from "node:fs";

let passed = 0;
const failures = [];
function test(name, fn) {
  try {
    fn();
    passed++;
  } catch (e) {
    failures.push({ name, message: e.message });
  }
}

const root = new URL("../", import.meta.url);
const read = (p) => readFileSync(new URL(p, root), "utf8");
const html = read("index.html");
const scripts = readdirSync(new URL("scripts/", root))
  .filter((f) => f.endsWith(".js"))
  .map((f) => [f, read(`scripts/${f}`)]);

test("the page ships a Content-Security-Policy that blocks remote script", () => {
  const meta = html.match(/http-equiv="Content-Security-Policy"[\s\S]*?content="([^"]+)"/i);
  assert.ok(meta, "no CSP meta tag in index.html");
  const policy = meta[1];
  for (const directive of [
    "default-src 'self'",
    "script-src 'self'",
    "object-src 'none'",
    "base-uri 'none'",
    "form-action 'none'",
  ]) {
    assert.ok(policy.includes(directive), `CSP is missing ${directive}`);
  }
  assert.ok(!/script-src[^;]*unsafe-inline/.test(policy), "script-src must not allow inline script");
});

test("no inline event handlers anywhere — they cannot run under that policy", () => {
  const offenders = [];
  for (const [name, src] of [["index.html", html], ...scripts]) {
    // Only markup attributes count: an attribute is written on…="…", while a
    // JavaScript property assignment (reader.onload = fn) is unaffected by the
    // policy and perfectly fine.
    for (const m of src.matchAll(/\son(click|toggle|load|error|mouse\w+|submit|change)\s*=\s*["']/gi)) {
      offenders.push(`${name}: ${m[0].trim()}`);
    }
  }
  assert.deepEqual(offenders, [], `inline handlers found: ${offenders.join(", ")}`);
});

test("result buttons carry data-act and nothing is exposed on window", () => {
  const render = scripts.find(([n]) => n === "render.js")[1];
  const main = scripts.find(([n]) => n === "main.js")[1];
  assert.ok(render.includes('data-act="vt"'), "lookup buttons should use data-act");
  assert.ok(main.includes('document.addEventListener("click"'), "a delegated click listener is required");
  const globals = [...main.matchAll(/^window\.(\w+)\s*=/gm)].map((m) => m[1]);
  assert.deepEqual(globals, [], `functions still on window: ${globals.join(", ")}`);
});

test("escaping covers the apostrophe as well as the angle brackets", () => {
  const render = scripts.find(([n]) => n === "render.js")[1];
  assert.ok(/replace\(\/'\/g, "&#39;"\)/.test(render), "render.js esc() must escape '");
});

test("nothing is fetched from a third party at page load", () => {
  // Assets the browser fetches by itself. A link the reader may click — the
  // repository link in Settings — is not one of them.
  const remote = [
    ...html.matchAll(/<(?:link|script|img|iframe|source)\b[^>]*\b(?:src|href)="(https?:\/\/[^"]+)"/gi),
    ...html.matchAll(/@import\s+url\(["']?(https?:\/\/[^"')]+)/gi),
  ].map((m) => m[1]);
  assert.deepEqual(remote, [], `remote assets in index.html: ${remote.join(", ")}`);
  assert.ok(html.includes('href="styles/fonts.css"'), "fonts must be served locally");
  const fonts = readdirSync(new URL("fonts/", root)).filter((f) => f.endsWith(".woff2"));
  assert.ok(fonts.length >= 2, "the woff2 files must ship with the app");
});

test("the app refuses to run inside a frame", () => {
  const main = scripts.find(([n]) => n === "main.js")[1];
  assert.ok(
    /window\.top !== window\.self/.test(main),
    "static hosting cannot send X-Frame-Options, so the check must be in the code",
  );
});

test("the local server binds loopback only", () => {
  const server = read("server.js");
  assert.ok(
    /server\.listen\(\s*PORT\s*,\s*"127\.0\.0\.1"/.test(server),
    "server.js must listen on 127.0.0.1, not on every interface",
  );
});

test("the optional relay is not an open proxy", () => {
  const worker = read("cors-worker.js");
  assert.ok(worker.includes("ALLOWED_HOSTS"), "the worker needs a host allow-list");
  for (const host of ["www.virustotal.com", "api.abuseipdb.com"]) {
    assert.ok(worker.includes(host), `${host} should be allowed`);
  }
  assert.ok(/target\.protocol !== "https:"/.test(worker), "the worker must require https");
});

test("local DNS and WHOIS accept only a bare domain or IP", async () => {
  const { validTarget } = await import("../lookup-local.js");
  assert.deepEqual(validTarget("example.com"), { kind: "domain", value: "example.com" });
  assert.deepEqual(validTarget("8.8.8.8"), { kind: "ip", value: "8.8.8.8" });
  assert.equal(validTarget("example.com; rm -rf /"), null);
  assert.equal(validTarget("http://example.com/path"), null);
  assert.equal(validTarget("-flag.example.com"), null);
  assert.equal(validTarget(""), null);
});

test("a payload in every header and in the body never becomes markup", async () => {
  const [{ parseHeaders }, { parseAuth }, { parseBody }, { extractIOCs }, { analyzeIdentity }, { calculateScore }, { buildHtmlReport }] =
    await Promise.all([
      import("../scripts/parse-headers.js"),
      import("../scripts/parse-auth.js"),
      import("../scripts/parse-body.js"),
      import("../scripts/extract-iocs.js"),
      import("../scripts/analyze-identity.js"),
      import("../scripts/score.js"),
      import("../scripts/report.js"),
    ]);

  const xss = `"><script>window.pwned=1</script><img src=x onerror=window.pwned=2><svg/onload=window.pwned=3>`;
  const raw = [
    `From: ${xss} <a@evil.test>`,
    `Reply-To: "${xss}" <r@evil.test>`,
    `Subject: ${xss}`,
    `X-Mailer: ${xss}`,
    `Message-ID: <${xss}@evil.test>`,
    `Received: from ${xss} ([203.0.113.5]) by mx.test; Mon, 1 Jan 2024 10:00:00 +0000`,
    `Authentication-Results: mx.test; spf=fail (${xss}) smtp.mailfrom=evil.test; dkim=fail; dmarc=fail`,
    `Content-Type: text/html`,
    ``,
    `<html><body><a href="javascript:window.pwned=4">${xss}</a><a href="https://evil.test/${xss}">https://paypal.com</a></body></html>`,
  ].join("\r\n");

  const headers = parseHeaders(raw);
  const auth = parseAuth(headers);
  const body = parseBody(raw);
  const iocs = extractIOCs(headers, body);
  const identity = analyzeIdentity(headers);
  const score = calculateScore(auth, iocs, null, headers, identity);
  const html = buildHtmlReport({ headers, auth, iocs, score, identity }, {});

  // Escaped payload in text is inert; a handler or a script inside a tag is not,
  // so only tag contents are inspected.
  const tags = [...html.matchAll(/<[^>]*>/g)].map((m) => m[0]);
  const dangerous = tags.filter(
    (t) => /\son\w+\s*=/i.test(t) || /javascript:/i.test(t) || /^<script/i.test(t) || /\ssrc\s*=\s*["']?https?:/i.test(t),
  );
  assert.deepEqual(dangerous, [], `markup escaped into the report: ${dangerous.slice(0, 2).join(" ")}`);
  assert.ok(tags.length > 100, "report looks truncated");
});

test("the exported report still cannot load or run anything", async () => {
  const { buildHtmlReport } = await import("../scripts/report.js");
  const out = buildHtmlReport({ headers: {}, auth: {}, iocs: {}, score: {} }, {});
  assert.ok(out.includes("default-src 'none'"), "report CSP missing");
  assert.ok(!/<script/i.test(out), "report must contain no script");
  assert.ok(!/src="https?:/i.test(out), "report must load nothing remote");
});

console.log(`\n${passed} passed, ${failures.length} failed`);
for (const f of failures) console.error(`  FAIL  ${f.name}\n        ${f.message}`);
process.exit(failures.length ? 1 : 0);
