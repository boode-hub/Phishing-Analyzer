// Comparison and correlation.
//
// The point of the compare page is campaign detection: several messages that
// look unrelated until a shared IP, link or file hash lines them up.
// Run: node tests/compare.test.mjs

import assert from "node:assert/strict";
import { parseHeaders } from "../scripts/parse-headers.js";
import { parseAuth } from "../scripts/parse-auth.js";
import { parseBody } from "../scripts/parse-body.js";
import { extractIOCs } from "../scripts/extract-iocs.js";
import { analyzeLanguage } from "../scripts/analyze-language.js";
import { analyzeIdentity } from "../scripts/analyze-identity.js";
import { calculateScore } from "../scripts/score.js";
import { buildComparison, sharedIndicators, comparisonCsv, comparisonJson } from "../scripts/compare-model.js";

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

function analyse(raw) {
  const source = raw.replace(/\n/g, "\r\n");
  const headers = parseHeaders(source);
  const auth = parseAuth(headers);
  const body = parseBody(source);
  const iocs = extractIOCs(headers, body);
  const languageAnalysis = body?.text ? analyzeLanguage(body.text) : null;
  const identity = analyzeIdentity(headers);
  const score = calculateScore(auth, iocs, languageAnalysis, headers, identity);
  return { headers, auth, body, iocs, languageAnalysis, identity, score };
}

const campaign = (n, subject) => `From: "Microsoft Account Team" <alerts${n}@micros0ft-security.com>
Reply-To: recovery.desk@gmail.com
To: user${n}@corp.test
Subject: ${subject}
Message-ID: <camp${n}@mailer-hub.test>
Date: Mon, 1 Jan 2024 10:0${n}:00 +0000
X-Mailer: PHPMailer 6.1
Received: from smtp.mailer-hub.test (smtp.mailer-hub.test [198.51.100.77]) by mx.corp.test; Mon, 1 Jan 2024 10:0${n}:05 +0000
Authentication-Results: mx.corp.test; spf=pass smtp.mailfrom=micros0ft-security.com; dkim=none; dmarc=none
Content-Type: text/html

<html><body>Your account will be suspended. <a href="https://login.micros0ft-security.com/verify">sign in</a></body></html>`;

const unrelated = `From: notifications@github.com
To: dev@corp.test
Subject: Security alert
Message-ID: <abc@github.com>
Date: Tue, 2 Jan 2024 08:00:00 +0000
Received: from out.github.com (out.github.com [192.0.2.44]) by mx.corp.test; Tue, 2 Jan 2024 08:00:05 +0000
Authentication-Results: mx.corp.test; spf=pass smtp.mailfrom=github.com; dkim=pass header.d=github.com; dmarc=pass header.from=github.com
Content-Type: text/plain

A new key was added to your account.`;

const items = [
  { name: "a.eml", analysis: analyse(campaign(1, "Unusual sign-in activity")) },
  { name: "b.eml", analysis: analyse(campaign(2, "Unusual sign-in activity")) },
  { name: "c.eml", analysis: analyse(campaign(3, "Password expires in 24 hours")) },
  { name: "d.eml", analysis: analyse(unrelated) },
];

test("the table has one column per message and the expected properties", () => {
  const { rows, count } = buildComparison(items);
  assert.equal(count, 4);
  for (const row of rows) assert.equal(row.cells.length, 4, `${row.label} has ${row.cells.length} cells`);
  const labels = rows.map((r) => r.label);
  for (const expected of ["Verdict", "SPF", "DKIM", "DMARC", "From", "Sender IP", "Attachments", "Language flags"]) {
    assert.ok(labels.includes(expected), `missing row: ${expected}`);
  }
});

test("verdict cells carry the message's own tier and tone", () => {
  const { rows } = buildComparison(items);
  const verdict = rows.find((r) => r.key === "verdict");
  assert.match(verdict.cells[0].value, /Suspicious|High Risk/);
  assert.equal(verdict.cells[3].value, "Low Risk · 0/100");
  assert.equal(verdict.cells[3].tone, "good");
});

test("the shared sender IP, link, Reply-To and domain tie the campaign together", () => {
  const shared = sharedIndicators(items);
  const byType = (type) => shared.filter((s) => s.type === type).map((s) => s.value);
  assert.ok(byType("ip").includes("198.51.100.77"), JSON.stringify(byType("ip")));
  assert.ok(byType("replyTo").includes("recovery.desk@gmail.com"));
  assert.ok(byType("domain").includes("micros0ft-security.com"));
  assert.ok(byType("urlDomain").includes("login.micros0ft-security.com"));
  // The unrelated message must not be in any of those groups.
  for (const entry of shared) assert.ok(!entry.messages.includes(3), `${entry.value} wrongly includes the unrelated message`);
});

test("a subject that differs only by numbers still groups", () => {
  const two = [
    { name: "1", analysis: analyse(campaign(1, "Invoice 4021 overdue")) },
    { name: "2", analysis: analyse(campaign(2, "Invoice 5533 overdue")) },
  ];
  const subjects = sharedIndicators(two).filter((s) => s.type === "subject");
  assert.equal(subjects.length, 1, JSON.stringify(subjects));
  assert.equal(subjects[0].messages.length, 2);
});

test("messages with nothing in common produce no shared indicators", () => {
  const shared = sharedIndicators([
    { name: "x", analysis: analyse(unrelated) },
    { name: "y", analysis: analyse(campaign(9, "Totally different")) },
  ]);
  assert.deepEqual(shared, []);
});

test("cells holding a shared value are marked, unrelated ones are not", () => {
  const { rows } = buildComparison(items);
  const ip = rows.find((r) => r.key === "senderIp");
  assert.deepEqual(
    ip.cells.map((c) => c.shared),
    [true, true, true, false],
  );
});

test("rows where every message agrees are marked identical", () => {
  const { rows } = buildComparison(items.slice(0, 3));
  const replyTo = rows.find((r) => r.key === "replyTo");
  assert.equal(replyTo.identical, true);
  const subject = rows.find((r) => r.key === "subject");
  assert.equal(subject.identical, false);
});

test("shared indicators are defanged, never live", () => {
  for (const entry of sharedIndicators(items)) {
    assert.ok(!/^https?:\/\//i.test(entry.defanged), `live URL: ${entry.defanged}`);
    if (entry.type === "ip") assert.match(entry.defanged, /\[\.\]/);
    if (entry.type === "domain") assert.match(entry.defanged, /\[\.\]/);
  }
});

test("CSV holds every message column, the shared block, and guards formulas", () => {
  const csv = comparisonCsv(items);
  assert.ok(csv.startsWith("﻿"), "missing BOM");
  const lines = csv.split("\r\n");
  assert.equal(lines[0], "﻿property,a.eml,b.eml,c.eml,d.eml");
  assert.ok(csv.includes("shared indicator"), "shared block missing");
  for (const line of lines) assert.ok(!/^[=+@]/.test(line), `unguarded formula: ${line.slice(0, 20)}`);
});

test("JSON carries each message's properties and the shared list", () => {
  const data = JSON.parse(comparisonJson(items));
  assert.equal(data.messages.length, 4);
  assert.equal(data.messages[0].name, "a.eml");
  assert.ok(data.messages[0].properties.senderIp.includes("198.51.100.77"));
  const ip = data.shared.find((s) => s.type === "ip");
  assert.deepEqual(ip.seenIn, ["a.eml", "b.eml", "c.eml"]);
});

test("one message alone produces a table and no correlations", () => {
  const { rows, shared } = buildComparison([items[0]]);
  assert.ok(rows.length > 10);
  assert.deepEqual(shared, []);
});

console.log(`\n${passed} passed, ${failures.length} failed`);
for (const f of failures) console.error(`  FAIL  ${f.name}\n        ${f.message}`);
process.exit(failures.length ? 1 : 0);
