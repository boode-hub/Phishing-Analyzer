// Detection added in this version: sender identity, link shapes, attachment
// content, ARC, header anomalies, and the payment-fraud floor.
// Run: node tests/detection.test.mjs

import assert from "node:assert/strict";
import { analyzeIdentity, lookalikeOf, skeleton, isMixedScript } from "../scripts/analyze-identity.js";
import { sniffFileType, inspectAttachment } from "../scripts/file-type.js";
import { extractIOCs } from "../scripts/extract-iocs.js";
import { parseHeaders } from "../scripts/parse-headers.js";
import { parseAuth } from "../scripts/parse-auth.js";
import { analyzeLanguage } from "../scripts/analyze-language.js";
import { calculateScore } from "../scripts/score.js";

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

const bytes = (...values) => Uint8Array.from(values);
const ascii = (s) => Uint8Array.from([...s].map((c) => c.charCodeAt(0)));
const idsOf = (headers) => analyzeIdentity(headers).findings.map((f) => f.id);

// ===== identity =====

test("a display name carrying another address is flagged", () => {
  const ids = idsOf({ from: { email: "attacker@gmail.com", name: "PayPal Service <service@paypal.com>" } });
  assert.ok(ids.includes("display-name-address"), ids.join());
});

test("a brand display name on an unrelated domain is flagged", () => {
  const ids = idsOf({ from: { email: "billing@random-host.test", name: "Microsoft Account Team" } });
  assert.ok(ids.includes("display-name-brand"), ids.join());
});

test("the brand's own mail is not flagged", () => {
  assert.deepEqual(idsOf({ from: { email: "service@paypal.com", name: "PayPal" } }), []);
  assert.deepEqual(idsOf({ from: { email: "no-reply@accounts.google.com", name: "Google" } }), []);
});

test("lookalike domains are classified", () => {
  assert.equal(lookalikeOf("paypa1.com")?.kind, "confusable");
  assert.equal(lookalikeOf("micorsoft.com")?.kind, "typosquat");
  assert.equal(lookalikeOf("paypal.secure-login.test")?.kind, "contains");
  assert.equal(lookalikeOf("paypal.com"), null);
  assert.equal(lookalikeOf("github.com"), null);
  assert.equal(lookalikeOf("example.com"), null);
});

test("digit and rn/vv tricks fold to the shape the eye sees", () => {
  assert.equal(skeleton("paypa1"), "paypal");
  assert.equal(skeleton("rnicrosoft"), "microsoft");
  assert.equal(skeleton("APP1E-ID"), "appleid");
});

test("a label mixing alphabets is caught even without xn--", () => {
  assert.equal(isMixedScript("pаypal"), true); // Cyrillic а
  assert.equal(isMixedScript("paypal"), false);
});

test("a free-webmail Reply-To on another domain is a medium finding", () => {
  const ids = idsOf({
    from: { email: "ceo@company.test", name: "CEO" },
    replyTo: { email: "ceo.private@gmail.com" },
  });
  assert.ok(ids.includes("replyto-freemail"), ids.join());
});

// ===== link shapes =====

const urlFlags = (text) => {
  const iocs = extractIOCs({ from: { email: "a@b.test" } }, { text, links: [], attachments: [] });
  return Object.fromEntries(iocs.urls.map((u) => [u.value, u.risks.map((r) => r.type)]));
};

test("credentials, downloads, ports and abused TLDs are flagged", () => {
  const flags = urlFlags(
    "https://accounts.paypal.com@evil.test/x http://a.test:8443/y http://b.test/setup.exe https://promo.zip/win",
  );
  assert.deepEqual(flags["https://accounts.paypal.com@evil.test/x"], ["credentials-url"]);
  assert.deepEqual(flags["http://a.test:8443/y"], ["odd-port"]);
  assert.deepEqual(flags["http://b.test/setup.exe"], ["direct-download"]);
  assert.deepEqual(flags["https://promo.zip/win"], ["risky-tld"]);
});

test("a lookalike link host is flagged even when the text is innocent", () => {
  const flags = urlFlags("http://paypa1-verify.com/login");
  assert.deepEqual(flags["http://paypa1-verify.com/login"], ["brand-lookalike"]);
});

test("an ordinary link carries no flags", () => {
  assert.deepEqual(urlFlags("https://github.com/boode-hub"), { "https://github.com/boode-hub": [] });
});

// ===== attachment content =====

test("content is identified from its first bytes", () => {
  assert.equal(sniffFileType(bytes(0x4d, 0x5a, 0x90, 0x00)).label, "Windows executable (PE)");
  assert.equal(sniffFileType(ascii("%PDF-1.7")).label, "PDF document");
  assert.equal(sniffFileType(bytes(0x50, 0x4b, 3, 4)).extensions.includes("docx"), true);
  assert.equal(sniffFileType(bytes(1, 2)), null);
});

test("a program wearing a document name is a high finding", () => {
  const flags = inspectAttachment({ value: "Invoice.pdf", bytes: bytes(0x4d, 0x5a, 0x90, 0) });
  assert.equal(flags[0].type, "high");
  assert.match(flags[0].message, /Windows executable/);
});

test("a real PDF named .pdf raises nothing", () => {
  assert.deepEqual(inspectAttachment({ value: "report.pdf", bytes: ascii("%PDF-1.4 ...") }), []);
});

test("an HTML attachment that builds and downloads a file is smuggling", () => {
  const page = ascii(
    `<html><script>const b = new Blob([atob("${"A".repeat(600)}")]);const a=document.createElement("a");a.download="invoice.iso";a.click();</script></html>`,
  );
  const flags = inspectAttachment({ value: "invoice.html", contentType: "text/html", bytes: page });
  assert.ok(flags.some((f) => f.label === "HTML smuggling"), JSON.stringify(flags));
});

test("attachment findings reach the IOC list", () => {
  const iocs = extractIOCs(
    {},
    { text: "", links: [], attachments: [{ filename: "Invoice.pdf", contentType: "application/pdf", size: 4, bytes: bytes(0x4d, 0x5a, 0x90, 0), inline: false }] },
  );
  const labels = iocs.attachments[0].riskFlags.map((f) => f.label);
  assert.ok(labels.includes("Executable content"), labels.join());
  assert.equal(iocs.attachments[0].risky, true);
});

// ===== ARC and header anomalies =====

const headersOf = (raw) => parseHeaders(raw.replace(/\n/g, "\r\n"));

test("an ARC chain is summarised, and a broken seal warns", () => {
  const auth = parseAuth(
    headersOf(`From: a@list.test
Subject: x
ARC-Seal: i=1; cv=none; d=list.test; s=s1; b=aaa
ARC-Authentication-Results: i=1; list.test; spf=pass smtp.mailfrom=sender.test; dkim=pass header.d=sender.test; dmarc=pass
ARC-Seal: i=2; cv=fail; d=relay.test; s=s2; b=bbb

body`),
  );
  assert.equal(auth.arc.present, true);
  assert.equal(auth.arc.sets, 2);
  assert.equal(auth.arc.oldest.spf, "pass");
  assert.equal(auth.arc.chainValid, false);
  assert.ok(auth.trust.warnings.some((w) => /ARC chain is marked broken/.test(w)));
});

test("a message with no ARC headers reports none", () => {
  const auth = parseAuth(headersOf("From: a@b.test\nSubject: x\n\nbody"));
  assert.equal(auth.arc.present, false);
});

test("reply headers on a message that is not a reply are an anomaly", () => {
  const auth = parseAuth(
    headersOf(`From: a@b.test
Subject: Invoice attached
In-Reply-To: <old@b.test>
Message-ID: <new@b.test>

body`),
  );
  assert.ok(auth.anomalies.some((a) => /not a reply/.test(a.message)), JSON.stringify(auth.anomalies));
});

test("a Message-ID issued by another domain is a low anomaly", () => {
  const auth = parseAuth(headersOf("From: a@company.test\nSubject: x\nMessage-ID: <1@mailer.other>\n\nbody"));
  const found = auth.anomalies.find((a) => /Message-ID was issued/.test(a.message));
  assert.ok(found, JSON.stringify(auth.anomalies));
  assert.equal(found.severity, "low");
});

test("a normal message raises no anomalies", () => {
  const auth = parseAuth(
    headersOf("From: a@company.test\nSubject: Hello\nMessage-ID: <1@company.test>\n\nbody"),
  );
  assert.deepEqual(auth.anomalies, []);
});

// ===== scoring =====

const cleanAuth = {
  mechanisms: { spf: { status: "pass" }, dkim: { status: "pass" }, dmarc: { status: "pass" } },
  domainAlignment: { dmarcAligned: true, mismatches: [] },
  trust: { warnings: [] },
  anomalies: [],
};
const noIocs = { urls: [], domains: [], ips: [], emails: [], attachments: [] };

test("CEO fraud from a fully authenticated mailbox is at least Suspicious", () => {
  const lang = analyzeLanguage(
    "I'm currently in a meeting and need you to process a wire transfer immediately. Account: 1234567890 Routing: 987654321. Do not delay, just handle it.",
  );
  const score = calculateScore(cleanAuth, noIocs, lang, { subject: "Urgent payment" });
  assert.equal(score.tier, "Suspicious");
  assert.ok(score.caveats.some((c) => /by phone/.test(c)), score.caveats.join(" | "));
});

test("one payment phrase in ordinary business mail does not raise the tier", () => {
  const lang = analyzeLanguage("Please approve the payment schedule attached, thanks.");
  assert.equal(calculateScore(cleanAuth, noIocs, lang, {}).tier, "Low Risk");
});

test("identity findings raise the authentication score and are explained", () => {
  const identity = analyzeIdentity({ from: { email: "billing@paypa1-verify.com", name: "PayPal Support" } });
  const score = calculateScore(cleanAuth, noIocs, null, {}, identity);
  assert.ok(score.breakdown.auth > 0);
  assert.ok(score.reasons.some((r) => /imitates paypal/i.test(r)), score.reasons.join(" | "));
});

// ===== lookup buttons =====

test("with no API key the lookup control is a real link, not a scripted popup", async () => {
  const { renderIOCs } = await import("../scripts/render.js");
  const container = { innerHTML: "" };
  renderIOCs(
    container,
    {
      urls: [],
      domains: [{ value: "evil.test", source: "URL", riskFlags: [], risks: [] }],
      ips: [{ value: "198.51.100.5", source: "Received", riskFlags: [], risks: [] }],
      emails: [],
      attachments: [],
    },
    {}, // no keys saved
  );
  // window.open is blocked by default in many browsers, so clicking a button
  // that called it did nothing at all. An anchor always opens.
  assert.ok(!/data-act="vendor"/.test(container.innerHTML), "no-key lookups must not be scripted");
  assert.match(container.innerHTML, /<a class="btn-ioc-lookup btn-vt no-key" href="https:\/\/www\.virustotal\.com\/gui\/domain\/evil\.test"[^>]*target="_blank"/);
  assert.match(container.innerHTML, /<a class="btn-ioc-lookup btn-abuse no-key" href="https:\/\/www\.abuseipdb\.com\/check\/198\.51\.100\.5"/);
  assert.match(container.innerHTML, /rel="noopener noreferrer"/);
});

test("with keys saved the lookup stays an in-page button", async () => {
  const { renderIOCs } = await import("../scripts/render.js");
  const container = { innerHTML: "" };
  renderIOCs(
    container,
    { urls: [], domains: [], ips: [{ value: "198.51.100.5", source: "Received", riskFlags: [], risks: [] }], emails: [], attachments: [] },
    { virustotal: "k", abuseipdb: "k" },
  );
  assert.match(container.innerHTML, /data-act="vt"/);
  assert.match(container.innerHTML, /data-act="abuse"/);
  assert.ok(!/no-key/.test(container.innerHTML));
});

console.log(`\n${passed} passed, ${failures.length} failed`);
for (const f of failures) console.error(`  FAIL  ${f.name}\n        ${f.message}`);
process.exit(failures.length ? 1 : 0);
