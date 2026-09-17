// Link and IOC extraction tests.
// Run: node tests/links.test.mjs
//
// Every case here came out of a pre-production review of a realistic phishing
// message, where each one was producing a wrong or missing finding.

import assert from "node:assert/strict";
import { parseHeaders } from "../scripts/parse-headers.js";
import { parseBody } from "../scripts/parse-body.js";
import { extractIOCs } from "../scripts/extract-iocs.js";

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

const html = (body) => `From: a@sender.test
Content-Type: text/html

<html><body>${body}</body></html>`;

const analyse = (raw) => {
  const headers = parseHeaders(raw);
  const body = parseBody(raw);
  return { body, iocs: extractIOCs(headers, body) };
};

// --- mismatched links --------------------------------------------------------

test("ordinary link text is not a mismatch", () => {
  const { body } = analyse(
    html(`<a href="https://newsletter.test/offer">View invoice</a> <a href="https://x.test">Click here</a>`),
  );
  assert.equal(
    body.links.filter((l) => l.isMismatch).length,
    0,
    "flagging every 'Click here' made normal newsletters look like phishing",
  );
});

test("a URL shown as text that points elsewhere is a mismatch", () => {
  const { body } = analyse(html(`<a href="https://evil.test/login">https://www.paypal.com/signin</a>`));
  assert.equal(body.links[0].isMismatch, true);
});

test("a bare domain shown as text counts as link-like", () => {
  const { body } = analyse(html(`<a href="https://evil.test/">paypal.com</a>`));
  assert.equal(body.links[0].isMismatch, true);
});

test("same organization is not a mismatch", () => {
  const { body } = analyse(html(`<a href="https://accounts.paypal.com/x">www.paypal.com</a>`));
  assert.equal(body.links[0].isMismatch, false);
});

test("a Safe Links rewrite of the same destination is not a mismatch", () => {
  const href =
    "https://nam02.safelinks.protection.outlook.com/?url=" +
    encodeURIComponent("https://www.paypal.com/signin") +
    "&data=x";
  const { body } = analyse(html(`<a href="${href}">https://www.paypal.com/signin</a>`));
  assert.equal(body.links[0].isMismatch, false, "the gateway rewrote it; nothing is hidden");
});

test("a Safe Links rewrite hiding a different domain IS a mismatch", () => {
  const href =
    "https://nam02.safelinks.protection.outlook.com/?url=" +
    encodeURIComponent("https://xn--pypal-4ve.com/signin") +
    "&data=x";
  const { body } = analyse(html(`<a href="${href}">https://www.paypal.com/signin</a>`));
  assert.equal(body.links[0].isMismatch, true);
});

test("anchors wrapping other markup are still captured", () => {
  const { body } = analyse(html(`<a href="https://evil.test/"><span><b>https://bank.test</b></span></a>`));
  assert.equal(body.links.length, 1, "the old pattern skipped any <a> containing tags");
  assert.equal(body.links[0].isMismatch, true);
});

test("HTML entities in href are decoded", () => {
  const { body } = analyse(html(`<a href="https://x.test/?a=1&amp;b=2">go</a>`));
  assert.equal(body.links[0].href, "https://x.test/?a=1&b=2");
});

// --- remote resources ---------------------------------------------------------

test("tracking pixels and remote images become URL IOCs", () => {
  const { iocs } = analyse(
    html(`<img src="https://track.evil.test/open.gif?u=abc" width="1" height="1"><img src="cid:logo">`),
  );
  const pixel = iocs.urls.find((u) => u.value.startsWith("https://track.evil.test/"));
  assert.ok(pixel, "remote image URL must be extracted");
  assert.match(pixel.source, /Remote resource/);
  assert.ok(!iocs.urls.some((u) => u.value.startsWith("cid:")), "cid: references are not URLs");
});

// --- unwrapped destinations -----------------------------------------------------

test("the real destination behind Safe Links becomes its own flagged IOC", () => {
  const href =
    "https://nam02.safelinks.protection.outlook.com/?url=" +
    encodeURIComponent("https://xn--pypal-4ve.com/verify") +
    "&data=x";
  const { iocs } = analyse(html(`<a href="${href}">Verify</a>`));
  const real = iocs.urls.find((u) => u.value === "https://xn--pypal-4ve.com/verify");
  assert.ok(real, "unwrapped destination must be listed");
  assert.match(real.source, /Safe Links/);
  assert.ok(
    real.risks.some((r) => r.type === "punycode"),
    "the punycode flag must fire on the real destination",
  );
});

test("an unwrapped destination does not double-count the mismatch", () => {
  const href =
    "https://nam02.safelinks.protection.outlook.com/?url=" +
    encodeURIComponent("https://evil.test/x") +
    "&data=x";
  const { iocs } = analyse(html(`<a href="${href}">https://bank.test/login</a>`));
  const mismatched = iocs.urls.filter((u) => u.risks.some((r) => r.type === "mismatch"));
  assert.equal(mismatched.length, 1);
});

// --- domains --------------------------------------------------------------------

test("domains are collected from URLs, unwrapped URLs and sender addresses", () => {
  const href =
    "https://nam02.safelinks.protection.outlook.com/?url=" +
    encodeURIComponent("https://xn--pypal-4ve.com/v") +
    "&data=x";
  const raw = `From: "PayPal" <service@paypal.com>
Reply-To: support@paypa1-alerts.test
Content-Type: text/html

<html><body><a href="${href}">Verify</a><img src="https://track.evil.test/p.gif"></body></html>`;
  const { iocs } = analyse(raw);
  const domains = iocs.domains.map((d) => d.value);
  for (const expected of [
    "paypal.com",
    "paypa1-alerts.test",
    "xn--pypal-4ve.com",
    "track.evil.test",
    "nam02.safelinks.protection.outlook.com",
  ]) {
    assert.ok(domains.includes(expected), `missing ${expected}; got ${domains.join(", ")}`);
  }
  assert.ok(
    iocs.domains.find((d) => d.value === "xn--pypal-4ve.com").risks.some((r) => r.type === "punycode"),
  );
});

test("IP-address hosts are not listed as domains", () => {
  const { iocs } = analyse(html(`<a href="http://203.0.113.9/login">x</a>`));
  assert.ok(!iocs.domains.some((d) => d.value === "203.0.113.9"));
});

// --- summary and verdict rendering ------------------------------------------------

const { parseAuth } = await import("../scripts/parse-auth.js");
const { calculateScore } = await import("../scripts/score.js");
const { renderSummary, renderVerdict } = await import("../scripts/render.js");

const spoof = `Authentication-Results: spf=fail (sender IP is 203.0.113.50) smtp.mailfrom=paypa1-alerts.test; dkim=none (message not signed) header.d=none;dmarc=fail action=quarantine header.from=paypal.com
From: "PayPal" <service@paypal.com>
Return-Path: <bounce@paypa1-alerts.test>
Subject: =?UTF-8?B?${Buffer.from("Account suspended").toString("base64")}?=
Content-Type: text/html

<html><body><a href="https://evil.test/x">https://www.paypal.com/</a></body></html>`;

const fullAnalysis = () => {
  const headers = parseHeaders(spoof);
  const auth = parseAuth(headers);
  const body = parseBody(spoof);
  const iocs = extractIOCs(headers, body);
  return { headers, auth, body, iocs, score: calculateScore(auth, iocs, null, headers) };
};

await (async () => {
  const a = fullAnalysis();
  const c = { innerHTML: "" };
  try {
    await renderSummary(c, a, {});
    const html = c.innerHTML;
    assert.match(html, /summary-verdict tier-high/, "verdict leads the summary");
    assert.match(html, /Not verified — fails DMARC/, "spoofed sender is not shown as safe");
    assert.match(html, /None — replies go to From/, "no Reply-To header means none, not Return-Path");
    assert.ok(!/bounce@paypa1-alerts\.test/.test(html.split("Reply-To")[1]?.split("Message")[0] || ""),
      "Return-Path must not appear under Reply-To");
    assert.match(html, /Account suspended/, "decoded subject is shown");
    passed++;
  } catch (e) {
    failures.push({ name: "renderSummary shows verdict, spoof status, real Reply-To and subject", message: e.message });
  }

  const v = { innerHTML: "" };
  try {
    renderVerdict(v, a.score, null);
    assert.match(v.innerHTML, /score-fill high/, "a high auth score is drawn red, not green");
    assert.match(v.innerHTML, /score-reasons/, "reasons are grouped under their bars");
    passed++;
  } catch (e) {
    failures.push({ name: "renderVerdict colours bars by severity and groups reasons", message: e.message });
  }
})();

console.log(`\n${passed} passed, ${failures.length} failed`);
for (const f of failures) console.error(`  FAIL  ${f.name}\n        ${f.message}`);
process.exit(failures.length ? 1 : 0);
