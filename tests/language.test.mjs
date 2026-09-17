// Language analysis tests.
// Run: node tests/language.test.mjs

import assert from "node:assert/strict";
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

const found = (text, category) =>
  (analyzeLanguage(text).categories[category]?.matches || []).map((m) => m.phrase.toLowerCase());

test("keywords match whole words, not fragments of ordinary words", () => {
  const benign =
    "Good morning, please find attached the first payment. Kindly confirm receipt at your earliest convenience. We define the terms swiftly as a courtesy, theirs and ours.";
  const r = analyzeLanguage(benign);
  for (const [cat, c] of Object.entries(r.categories)) {
    assert.equal(c.matchCount, 0, `${cat} matched ${c.matches.map((m) => m.phrase)} in ordinary text`);
  }
});

test("the real words still match", () => {
  assert.deepEqual(found("Notice from the IRS about a court date.", "authority").sort(), ["court", "irs"]);
  assert.deepEqual(found("Send it by SWIFT today.", "financial"), ["swift"]);
});

test("keywords with punctuation still match", () => {
  assert.ok(found("Please don't mention this to anyone.", "bec").includes("don't mention this"));
  assert.ok(found("Arrange a same-day payment.", "bec").includes("same-day payment"));
});

test("invoice fraud: changed bank details are detected", () => {
  const text =
    "Please note our bank account has changed. Kindly use the updated bank details below for the overdue invoice and send proof of payment once you process the payment.";
  const hits = found(text, "bec");
  for (const phrase of [
    "our bank account has changed",
    "updated bank details",
    "overdue invoice",
    "proof of payment",
    "process the payment",
  ]) {
    assert.ok(hits.includes(phrase), `missed "${phrase}"; got ${hits}`);
  }
});

test("CEO fraud: availability, secrecy and gift-card requests are detected", () => {
  const text =
    "Are you available? I need a favor. I'm in a meeting and can't talk right now. Please purchase gift cards for the team and send me the codes. Keep this confidential.";
  const hits = found(text, "bec");
  for (const phrase of [
    "are you available",
    "i need a favor",
    "i'm in a meeting",
    "can't talk right now",
    "purchase gift cards",
    "send me the codes",
    "keep this confidential",
  ]) {
    assert.ok(hits.includes(phrase), `missed "${phrase}"; got ${hits}`);
  }
});

test("payroll diversion is detected", () => {
  assert.ok(found("I would like to update my direct deposit before the next payroll.", "bec").includes("update my direct deposit"));
});

test("BEC has its own label and appears in the score reasons", () => {
  const lang = analyzeLanguage("Please use the new bank details for this urgent payment.");
  assert.equal(lang.categories.bec.label, "BEC / Payment Fraud");
  const auth = {
    mechanisms: { spf: { status: "pass" }, dkim: { status: "pass" }, dmarc: { status: "pass" } },
    domainAlignment: { dmarcAligned: true, mismatches: [] },
    trust: { warnings: [] },
  };
  const s = calculateScore(auth, { urls: [], domains: [], ips: [], emails: [], attachments: [] }, lang);
  assert.ok(s.reasons.some((r) => /BEC \/ payment-fraud phrase/.test(r)), `reasons: ${s.reasons}`);
  assert.ok(s.breakdown.language > 0);
});

console.log(`\n${passed} passed, ${failures.length} failed`);
for (const f of failures) console.error(`  FAIL  ${f.name}\n        ${f.message}`);
process.exit(failures.length ? 1 : 0);
