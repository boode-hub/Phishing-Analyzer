// Report export tests.
// Run: node tests/report.test.mjs
//
// The critical property: no live indicator may appear anywhere in either
// report. Each test builds a realistic analysis through the real pipeline.

import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { parseHeaders } from "../scripts/parse-headers.js";
import { parseAuth } from "../scripts/parse-auth.js";
import { parseBody } from "../scripts/parse-body.js";
import { extractIOCs } from "../scripts/extract-iocs.js";
import { calculateScore } from "../scripts/score.js";
import { sha256Bytes, md5Bytes } from "../scripts/hash-utils.js";
import {
  buildMarkdownReport,
  buildCsvReport,
  reportFilename,
  defangUrl,
  defangIp,
  defangEmail,
  defangDomain,
  defangText,
  CSV_COLUMNS,
} from "../scripts/report.js";

let passed = 0;
const failures = [];
async function test(name, fn) {
  try {
    await fn();
    passed++;
  } catch (e) {
    failures.push({ name, message: e.message });
  }
}

// --- a realistic analysis ------------------------------------------------------

const exe = Buffer.from(Array.from({ length: 300 }, (_, i) => (i * 7) % 256));
const victim = Buffer.from("cfo@target.test").toString("base64").replace(/=+$/, "");
const safelink =
  "https://nam12.safelinks.protection.outlook.com/?url=" +
  encodeURIComponent(`https://xn--pypal-4ve.com/verify#${victim}`) +
  "&data=x";

const EML = `Received: from mx.relay.test (mx.relay.test [198.51.100.7]) by inbox.test; Mon, 15 Sep 2025 09:14:05 +0000
Received: from gw.evil.test (gw.evil.test [203.0.113.50]) by mx.relay.test; Mon, 15 Sep 2025 09:14:02 +0000
Received: from DESKTOP (unknown [10.1.2.3]) by gw.evil.test; Mon, 15 Sep 2025 09:14:00 +0000
Received: from v6.evil.test (v6.evil.test [IPv6:2001:db8::7]) by gw.evil.test; Mon, 15 Sep 2025 09:13:59 +0000
Authentication-Results: spf=fail (sender IP is 203.0.113.50) smtp.mailfrom=evil.test; dkim=none (message not signed) header.d=none;dmarc=fail action=quarantine header.from=paypal.com
Received-SPF: Fail (protection.outlook.com: domain of evil.test does not designate 203.0.113.50 as permitted sender) client-ip=203.0.113.50; helo=gw.evil.test;
From: "PayPal | Security" <service@paypal.com>
Reply-To: help@evil.test
Return-Path: <bounce@evil.test>
To: cfo@target.test
Subject: =@SUM(1) Your account paypal.com is *locked*
Message-ID: <abc@evil.test>
Content-Type: multipart/mixed; boundary="B"

--B
Content-Type: text/html

<html><body><a href="${safelink}">https://www.paypal.com/signin</a>
<a href="http://203.0.113.9/x|y">Pay here</a>
<img src="https://track.evil.test/p.gif"></body></html>
--B
Content-Type: application/octet-stream; name="Invoice.pdf.exe"
Content-Disposition: attachment; filename="Invoice.pdf.exe"
Content-Transfer-Encoding: base64

${exe.toString("base64")}
--B--`;

async function analysis() {
  const headers = parseHeaders(EML);
  const auth = parseAuth(headers);
  const body = parseBody(EML);
  const iocs = extractIOCs(headers, body);
  for (const a of iocs.attachments) {
    a.sha256 = await sha256Bytes(a.bytes);
    a.md5 = md5Bytes(a.bytes);
  }
  return { headers, auth, body, iocs, score: calculateScore(auth, iocs, null, headers) };
}

const NOW = new Date("2026-09-17T13:45:00Z");

/** Every raw indicator value that must never appear un-defanged. */
function liveValues(a) {
  const i = a.iocs;
  return [
    ...i.urls.map((u) => u.value),
    ...i.domains.map((d) => d.value),
    ...i.ips.map((ip) => ip.value),
    ...i.emails.map((e) => e.value),
    ...i.mismatchedLinks.map((l) => l.href),
  ].filter((v) => /[.:@]/.test(v));
}

// --- defang units ----------------------------------------------------------------

await test("URL defanging neutralises scheme and host", () => {
  assert.equal(defangUrl("https://evil.test/a.b/c?x=1"), "hxxps[://]evil[.]test/a.b/c?x=1");
  assert.equal(defangUrl("http://user@evil.test:8080/"), "hxxp[://]user[@]evil[.]test:8080/");
  assert.equal(defangUrl("http://203.0.113.9/login"), "hxxp[://]203[.]0[.]113[.]9/login");
  assert.equal(
    defangUrl("https://r.test/go?u=https://evil.test/"),
    "hxxps[://]r[.]test/go?u=hxxps[://]evil[.]test/",
    "an embedded URL is defanged too",
  );
  assert.equal(
    defangUrl("https://nam12.safelinks.protection.outlook.com/?url=https%3A%2F%2Fevil.com%2Fx&e=v@corp.test"),
    "hxxps[://]nam12[.]safelinks[.]protection[.]outlook[.]com/?url=https%3A%2F%2Fevil[.]com%2Fx&e=v[@]corp[.]test",
    "a percent-encoded destination and an email in the query are defanged",
  );
});

await test("IP, email and domain defanging", () => {
  assert.equal(defangIp("203.0.113.50"), "203[.]0[.]113[.]50");
  assert.equal(defangIp("2001:db8::7"), "2001[:]db8[:][:]7");
  assert.equal(defangEmail("a.b@evil.test"), "a.b[@]evil[.]test");
  assert.equal(defangDomain("xn--pypal-4ve.com"), "xn--pypal-4ve[.]com");
});

await test("filenames and auth property names are not mistaken for domains", () => {
  assert.equal(defangText("attachment: Invoice_2025.pdf.exe"), "attachment: Invoice_2025.pdf.exe");
  assert.equal(defangText("fail — header.from=paypal.com"), "fail — header.from=paypal[.]com");
  assert.equal(defangText("smtp.mailfrom=evil.test"), "smtp.mailfrom=evil[.]test");
  assert.equal(defangText("lure at evil.zip"), "lure at evil[.]zip", ".zip is a real TLD");
});

await test("markdown escaping stays readable as plain text but blocks link injection", async () => {
  const md = buildMarkdownReport({
    headers: { subject: "Pay evil.com [now](javascript:alert(1)) *urgent* Invoice_2025" },
    auth: {}, iocs: {}, score: {},
  }, { now: NOW });
  const subjectRow = md.split("\n").find((l) => l.startsWith("| Subject"));
  assert.ok(subjectRow.includes("evil[.]com"), "no backslashes around defang brackets");
  assert.ok(subjectRow.includes("]\\("), "injected link syntax is broken");
  assert.ok(subjectRow.includes("\\*urgent\\*"));
  assert.ok(subjectRow.includes("Invoice_2025"), "intraword underscore left alone");
});

await test("an @mention in attacker-controlled text cannot ping anyone", async () => {
  const md = buildMarkdownReport({ headers: { subject: "cc @security-team =@SUM(1)" }, auth: {}, iocs: {}, score: {} }, { now: NOW });
  const subjectRow = md.split("\n").find((l) => l.startsWith("| Subject"));
  assert.ok(!/(^|[^\\])@\w/.test(subjectRow), `unescaped mention: ${subjectRow}`);
});

await test("status icons do not misalign plain-text table columns", async () => {
  const a = await analysis();
  const md = buildMarkdownReport(a, { now: NOW });
  const lines = md.split("\n");
  const start = lines.findIndex((l) => /^\| Check\s+\| Result/.test(l));
  const rows = lines.slice(start, start + 5);
  assert.ok(start >= 0 && rows.length === 5 && rows[4].startsWith("| DMARC"), "found the auth table");
  const width = (s) => [...s].reduce((w, ch) => {
    const cp = ch.codePointAt(0);
    return cp === 0xfe0f ? w : w + (cp >= 0x1f000 || (cp >= 0x2600 && cp <= 0x27bf) ? 2 : 1);
  }, 0);
  const widths = new Set(rows.map(width));
  assert.equal(widths.size, 1, `rows render at different widths: ${[...widths]}`);
});

await test("free text is defanged in one pass", () => {
  assert.equal(
    defangText("Visit https://evil.test/x or paypal.com, mail a@b.test, ip 1.2.3.4"),
    "Visit hxxps[://]evil[.]test/x or paypal[.]com, mail a[@]b[.]test, ip 1[.]2[.]3[.]4",
  );
});

// --- markdown ------------------------------------------------------------------------

await test("markdown contains no live indicators", async () => {
  const a = await analysis();
  const md = buildMarkdownReport(a, { now: NOW });
  assert.ok(!/\b(https?|ftp):\/\//i.test(md), "no live scheme anywhere");
  for (const v of liveValues(a)) {
    assert.ok(!md.includes(v), `live indicator leaked: ${v}`);
  }
  assert.ok(!/[a-z0-9]@[a-z0-9-]+\.[a-z]/i.test(md), "no live email address");
});

await test("markdown keeps hashes intact", async () => {
  const a = await analysis();
  const md = buildMarkdownReport(a, { now: NOW });
  assert.ok(md.includes(createHash("sha256").update(exe).digest("hex")));
  assert.ok(md.includes(createHash("md5").update(exe).digest("hex")));
});

await test("markdown has the expected structure", async () => {
  const a = await analysis();
  const md = buildMarkdownReport(a, { now: NOW });
  for (const heading of [
    "# Phishing Analysis Report",
    "## Message",
    "## Verdict",
    "## Authentication",
    "## Sender Path",
    "## Indicators of Compromise",
    "### URLs",
    "### Domains",
    "### IP Addresses",
    "### Email Addresses",
    "### Attachments",
    "### Deceptive Links",
  ]) {
    assert.ok(md.includes(heading), `missing ${heading}`);
  }
  assert.match(md, /🔴 \*\*HIGH RISK\*\*/);
  assert.match(md, /Generated 2026-09-17 13:45 UTC/);
});

await test("every markdown table row has the same number of columns", async () => {
  const a = await analysis();
  const md = buildMarkdownReport(a, { now: NOW });
  const lines = md.split("\n");
  const cells = (line) => line.replace(/\\\|/g, "").split("|").length;
  let i = 0;
  let tables = 0;
  while (i < lines.length) {
    if (lines[i].startsWith("|")) {
      const expected = cells(lines[i]);
      tables++;
      while (i < lines.length && lines[i].startsWith("|")) {
        assert.equal(cells(lines[i]), expected, `ragged table row: ${lines[i]}`);
        i++;
      }
    } else i++;
  }
  assert.ok(tables >= 6, `expected several tables, found ${tables}`);
});

await test("pipes inside values do not break tables", async () => {
  const a = await analysis();
  const md = buildMarkdownReport(a, { now: NOW });
  // From display name "PayPal | Security" and a URL containing "|".
  assert.match(md, /PayPal \\\| Security/);
});

await test("pipes outside tables are not backslash-escaped", async () => {
  const a = await analysis();
  const md = buildMarkdownReport(a, { now: NOW });
  const urlLine = md.split("\n").find((l) => /^\d+\. .*203\[\.\]0\[\.\]113\[\.\]9/.test(l));
  assert.ok(urlLine, "IP URL listed");
  assert.ok(urlLine.includes("/x|y") && !urlLine.includes("\\|"), `literal backslash in list: ${urlLine}`);
});

await test("markdown special characters in the subject are escaped", async () => {
  const a = await analysis();
  const md = buildMarkdownReport(a, { now: NOW });
  assert.match(md, /\\\*locked\\\*/);
});

await test("an unwrapped destination is nested under its wrapper, not listed twice", async () => {
  const a = await analysis();
  const md = buildMarkdownReport(a, { now: NOW });
  const dest = defangUrl(`https://xn--pypal-4ve.com/verify#${victim}`);
  const occurrences = md.split(dest).length - 1;
  assert.ok(occurrences >= 1, "destination must be shown");
  assert.match(md, /\*\*Real destination:\*\* `hxxps\[:\/\/\]xn--pypal-4ve\[\.\]com/);
  const topLevel = md.split("\n").filter((l) => /^\d+\. /.test(l) && l.includes(dest));
  assert.equal(topLevel.length, 0, "must not also appear as its own numbered item");
});

await test("lookup results are included when available", async () => {
  const a = await analysis();
  const lookups = new Map([
    ["vt:203.0.113.50", "Malicious — 12/90 engines"],
    ["abuse:203.0.113.50", "87% confidence · 34 reports · RU"],
  ]);
  const md = buildMarkdownReport(a, { lookups, now: NOW });
  assert.match(md, /Malicious — 12\/90 engines/);
  assert.match(md, /87% confidence/);
  const plain = buildMarkdownReport(a, { now: NOW });
  assert.ok(!/\| AbuseIPDB/.test(plain), "no empty lookup column when nothing was looked up");
});

// --- csv ------------------------------------------------------------------------------

/** Minimal RFC 4180 parser, independent of the code under test. */
function parseCsv(text) {
  const rows = [];
  let row = [], field = "", quoted = false;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (quoted) {
      if (c === '"' && text[i + 1] === '"') { field += '"'; i++; }
      else if (c === '"') quoted = false;
      else field += c;
    } else if (c === '"') quoted = true;
    else if (c === ",") { row.push(field); field = ""; }
    else if (c === "\r" && text[i + 1] === "\n") { row.push(field); rows.push(row); row = []; field = ""; i++; }
    else field += c;
  }
  if (field || row.length) { row.push(field); rows.push(row); }
  return rows;
}

await test("csv is RFC 4180 with a BOM, CRLF, fixed columns", async () => {
  const a = await analysis();
  const csv = buildCsvReport(a);
  assert.ok(csv.startsWith("﻿"), "BOM so Excel reads UTF-8");
  assert.ok(!/[^\r]\n/.test(csv), "CRLF line endings only");
  const rows = parseCsv(csv.slice(1));
  assert.deepEqual(rows[0], CSV_COLUMNS);
  for (const r of rows) assert.equal(r.length, CSV_COLUMNS.length, `ragged row: ${r}`);
  const types = new Set(rows.slice(1).map((r) => r[0]));
  for (const t of ["url", "domain", "ip", "email", "filename", "sha256", "md5", "deceptive_link"]) {
    assert.ok(types.has(t), `missing type ${t}`);
  }
});

await test("csv indicator column contains no live indicators", async () => {
  const a = await analysis();
  const rows = parseCsv(buildCsvReport(a).slice(1)).slice(1);
  const whole = rows.map((r) => r.join("")).join("\n");
  assert.ok(!/\b(https?|ftp):\/\//i.test(whole));
  for (const v of liveValues(a)) assert.ok(!whole.includes(v), `live indicator leaked: ${v}`);
});

await test("csv guards against spreadsheet formula injection", () => {
  const fake = {
    iocs: {
      urls: [], domains: [], ips: [], attachments: [], mismatchedLinks: [],
      emails: [{ value: "=cmd@evil.test", source: "+SUM(A1)", riskFlags: [{ label: "-2+3" }] }],
    },
  };
  const rows = parseCsv(buildCsvReport(fake).slice(1));
  const r = rows[1];
  assert.ok(r[1].startsWith("'="), `indicator not guarded: ${r[1]}`);
  assert.ok(r[2].startsWith("'+"), `source not guarded: ${r[2]}`);
  assert.ok(r[3].startsWith("'-"), `flags not guarded: ${r[3]}`);
});

await test("csv raw column is opt-in and holds the original values", async () => {
  const a = await analysis();
  assert.ok(!parseCsv(buildCsvReport(a).slice(1))[0].includes("indicator_raw"));
  const rows = parseCsv(buildCsvReport(a, { includeRaw: true }).slice(1));
  assert.equal(rows[0].at(-1), "indicator_raw");
  const ipRow = rows.find((r) => r[0] === "ip" && r[1] === "203[.]0[.]113[.]50");
  assert.equal(ipRow.at(-1), "203.0.113.50");
});

await test("csv hashes are unmodified and tied to their file", async () => {
  const a = await analysis();
  const rows = parseCsv(buildCsvReport(a).slice(1));
  const sha = rows.find((r) => r[0] === "sha256");
  assert.equal(sha[1], createHash("sha256").update(exe).digest("hex"));
  assert.equal(sha[4], "file: Invoice.pdf.exe");
});

// --- filename -----------------------------------------------------------------------

await test("filename is dated, slugged and cut at a word boundary", () => {
  const name = reportFilename(
    { headers: { subject: "⚠ Action Required: Your account has been suspended today" } },
    "md",
    NOW,
  );
  assert.equal(name, "phishing-report_2026-09-17_action-required-your-account-has-been.md");
  assert.equal(reportFilename({ headers: {} }, "csv", NOW), "phishing-report_2026-09-17_email.csv");
});

console.log(`\n${passed} passed, ${failures.length} failed`);
for (const f of failures) console.error(`  FAIL  ${f.name}\n        ${f.message}`);
process.exit(failures.length ? 1 : 0);
