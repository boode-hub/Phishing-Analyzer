// Test Runner for Phishing Email Analyzer
// Run with: node tests/runner.mjs

import { parseHeaders } from "../scripts/parse-headers.js";
import { parseAuth } from "../scripts/parse-auth.js";
import { parseBody } from "../scripts/parse-body.js";
import { extractIOCs } from "../scripts/extract-iocs.js";
import { analyzeLanguage } from "../scripts/analyze-language.js";
import { calculateScore } from "../scripts/score.js";
import { readFileSync } from "fs";
import { dirname, join } from "path";
import { fileURLToPath } from "url";

const __dirname = dirname(fileURLToPath(import.meta.url));

// Test utilities
let passCount = 0;
let failCount = 0;
const failures = [];

function assert(condition, message) {
  if (condition) {
    passCount++;
    process.stdout.write(".");
  } else {
    failCount++;
    failures.push(message);
    process.stdout.write("F");
  }
}

function assertEqual(actual, expected, message) {
  if (actual === expected) {
    passCount++;
    process.stdout.write(".");
  } else {
    failCount++;
    failures.push(`${message}\n  Expected: ${expected}\n  Actual: ${actual}`);
    process.stdout.write("F");
  }
}

function assertTruthy(value, message) {
  assert(!!value, message);
}

function assertArrayLength(arr, expected, message) {
  assertEqual(arr?.length, expected, message);
}

function assertContains(str, substr, message) {
  assert(
    str && str.includes(substr),
    `${message}\n  Expected to contain: "${substr}"\n  Actual: "${str}"`,
  );
}

// Load sample files
function loadSample(name) {
  return readFileSync(join(__dirname, "..", "sample-data", name), "utf-8");
}

const legitEmail = loadSample("legitimate-email.eml");
const spoofedEmail = loadSample("phishing-spoofed.eml");
const urgencyEmail = loadSample("phishing-urgency.eml");

console.log("\n=== Phishing Email Analyzer Test Suite ===\n");

// ==================== PARSE HEADERS TESTS ====================
console.log("\n--- parse-headers.js ---");

// Test 1: Parse legitimate email headers
const legitHeaders = parseHeaders(legitEmail);
assertEqual(
  legitHeaders.from?.email,
  "notifications@github.com",
  "Legit: From email",
);
assertEqual(legitHeaders.to?.email, "user@example.com", "Legit: To email");
assertEqual(
  legitHeaders.subject,
  "Security alert for your GitHub account",
  "Legit: Subject",
);
assertEqual(
  legitHeaders.replyTo?.email,
  "notifications@github.com",
  "Legit: Reply-To",
);
assertEqual(
  legitHeaders.returnPath?.email,
  "notifications@github.com",
  "Legit: Return-Path",
);
assertArrayLength(legitHeaders.received, 1, "Legit: Received count");
assertTruthy(legitHeaders.domains?.length > 0, "Legit: Domains extracted");

// Test 2: Parse spoofed email headers
const spoofedHeaders = parseHeaders(spoofedEmail);
assertEqual(
  spoofedHeaders.from?.email,
  "security@paypa1.com",
  "Spoofed: From email",
);
assertEqual(
  spoofedHeaders.replyTo?.email,
  "support@paypa1-security.com",
  "Spoofed: Reply-To",
);
assertEqual(
  spoofedHeaders.returnPath?.email,
  "bounce@malicious-server.ru",
  "Spoofed: Return-Path",
);
assertContains(
  spoofedHeaders.subject,
  "Action Required",
  "Spoofed: Decoded subject",
);
assertArrayLength(spoofedHeaders.received, 1, "Spoofed: Received count");

// Test 3: Parse urgency email headers
const urgencyHeaders = parseHeaders(urgencyEmail);
assertEqual(
  urgencyHeaders.from?.email,
  "ceo@company-abc.com",
  "Urgency: From email",
);
assertEqual(
  urgencyHeaders.subject,
  "URGENT: Wire Transfer Needed Immediately",
  "Urgency: Subject",
);

// Test 4: Headers-only input (no body)
const headersOnly = `From: test@example.com\nTo: user@example.com\nSubject: Test\nDate: Mon, 15 Jan 2024 10:00:00 +0000`;
const headersOnlyResult = parseHeaders(headersOnly);
assertEqual(
  headersOnlyResult.from?.email,
  "test@example.com",
  "Headers-only: From",
);
assertEqual(headersOnlyResult.subject, "Test", "Headers-only: Subject");

// Test 5: RFC 2047 encoded subject
const encodedSubject = "=?UTF-8?B?QWN0aW9uIFJlcXVpcmVk?=";
const encodedHeader = `From: test@example.com\nSubject: ${encodedSubject}`;
const encodedResult = parseHeaders(encodedHeader);
assertContains(
  encodedResult.subject,
  "Action Required",
  "RFC 2047: Decoded subject",
);

// Test 6: Multiple Received headers
const multiReceived = `From: a@b.com\nReceived: from server1.com by mx1.com; Mon, 15 Jan 2024 10:00:00 +0000\nReceived: from server2.com by server1.com; Mon, 15 Jan 2024 09:00:00 +0000`;
const multiResult = parseHeaders(multiReceived);
assertArrayLength(multiResult.received, 2, "Multiple Received: Count");

// ==================== PARSE AUTH TESTS ====================
console.log("\n--- parse-auth.js ---");

// Test 7: Legitimate email auth
const legitAuth = parseAuth(legitHeaders);
assertEqual(legitAuth.mechanisms.spf.status, "pass", "Legit auth: SPF pass");
assertEqual(legitAuth.mechanisms.dkim.status, "pass", "Legit auth: DKIM pass");
assertEqual(
  legitAuth.mechanisms.dmarc.status,
  "pass",
  "Legit auth: DMARC pass",
);
assertEqual(legitAuth.overallStatus.level, "pass", "Legit auth: Overall pass");
assertTruthy(
  legitAuth.domainAlignment.aligned["Reply-To"],
  "Legit auth: Reply-To aligned",
);

// Test 8: Spoofed email auth
const spoofedAuth = parseAuth(spoofedHeaders);
assertEqual(
  spoofedAuth.mechanisms.spf.status,
  "fail",
  "Spoofed auth: SPF fail",
);
assertEqual(
  spoofedAuth.mechanisms.dkim.status,
  "none",
  "Spoofed auth: DKIM none",
);
assertEqual(
  spoofedAuth.mechanisms.dmarc.status,
  "fail",
  "Spoofed auth: DMARC fail",
);
assertEqual(
  spoofedAuth.overallStatus.level,
  "fail",
  "Spoofed auth: Overall fail",
);
assertTruthy(
  !spoofedAuth.domainAlignment.aligned["Reply-To"],
  "Spoofed auth: Reply-To misaligned",
);
assertTruthy(
  !spoofedAuth.domainAlignment.aligned["Return-Path"],
  "Spoofed auth: Return-Path misaligned",
);

// Test 9: Urgency email auth (all pass but language should flag)
const urgencyAuth = parseAuth(urgencyHeaders);
assertEqual(
  urgencyAuth.mechanisms.spf.status,
  "pass",
  "Urgency auth: SPF pass",
);
assertEqual(
  urgencyAuth.mechanisms.dkim.status,
  "pass",
  "Urgency auth: DKIM pass",
);
assertEqual(
  urgencyAuth.mechanisms.dmarc.status,
  "pass",
  "Urgency auth: DMARC pass",
);
assertEqual(
  urgencyAuth.overallStatus.level,
  "pass",
  "Urgency auth: Overall pass",
);

// ==================== PARSE BODY TESTS ====================
console.log("\n--- parse-body.js ---");

// Test 10: Parse legitimate email body
const legitBody = parseBody(legitEmail);
assertTruthy(legitBody.text, "Legit body: Has text");
assertContains(
  legitBody.text,
  "GitHub account",
  "Legit body: Contains expected text",
);
assertContains(
  legitBody.text,
  "https://github.com/settings/security",
  "Legit body: Contains URL",
);
assertArrayLength(legitBody.links, 1, "Legit body: Link count");

// Test 11: Parse spoofed email body (HTML)
const spoofedBody = parseBody(spoofedEmail);
assertTruthy(spoofedBody.html, "Spoofed body: Has HTML");
assertTruthy(spoofedBody.text, "Spoofed body: Has extracted text");
assertContains(spoofedBody.text, "PayPal", "Spoofed body: Contains PayPal");
assertArrayLength(spoofedBody.links, 1, "Spoofed body: Link count");
// "click here to verify" is ordinary link text, not a URL pretending to be a
// different one. This assertion used to require it be flagged — the false
// positive that marked every newsletter's "Click here" as a mismatched link.
assertTruthy(!spoofedBody.links[0].isMismatch, "Spoofed body: plain link text is not a mismatch");

// Test 12: Parse urgency email body
const urgencyBody = parseBody(urgencyEmail);
assertTruthy(urgencyBody.text, "Urgency body: Has text");
assertContains(
  urgencyBody.text,
  "wire transfer",
  "Urgency body: Contains wire transfer",
);
assertContains(urgencyBody.text, "$47,500", "Urgency body: Contains amount");

// Test 13: Multipart parsing
const multipartEmail = `From: test@example.com
Content-Type: multipart/alternative; boundary="boundary123"
MIME-Version: 1.0

--boundary123
Content-Type: text/plain; charset="utf-8"

This is the plain text part.

--boundary123
Content-Type: text/html; charset="utf-8"

<html><body><p>This is the HTML part.</p><a href="http://example.com">Link</a></body></html>

--boundary123--`;
const multipartBody = parseBody(multipartEmail);
assertContains(
  multipartBody.text,
  "This is the plain text part",
  "Multipart: Plain text",
);
assertContains(multipartBody.html, "<html>", "Multipart: HTML");
assertArrayLength(multipartBody.links, 1, "Multipart: Link count");

// Test 14: Base64 decoding
const base64Email = `From: test@example.com
Content-Type: text/plain; charset="utf-8"
Content-Transfer-Encoding: base64

VGhpcyBpcyBiYXNlNjQgZGVjb2RlZCB0ZXh0Lg==`;
const base64Body = parseBody(base64Email);
assertContains(
  base64Body.text,
  "base64 decoded text",
  "Base64: Decoded correctly",
);

// Test 15: Quoted-printable decoding
const qpEmail = `From: test@example.com
Content-Type: text/plain; charset="utf-8"
Content-Transfer-Encoding: quoted-printable

This is quoted=2Dprintable text with special chars: =C3=A9`;
const qpBody = parseBody(qpEmail);
assertContains(qpBody.text, "quoted-printable", "QP: Decoded correctly");

// ==================== EXTRACT IOCS TESTS ====================
console.log("\n--- extract-iocs.js ---");

// Test 16: Extract IOCs from legitimate email
const legitIOCs = extractIOCs(legitHeaders, legitBody);
assertArrayLength(legitIOCs.urls, 1, "Legit IOCs: URL count");
assertArrayLength(
  legitIOCs.emails,
  1,
  "Legit IOCs: Email count (From, Reply-To, Return-Path deduplicated)",
);
assertArrayLength(legitIOCs.ips, 2, "Legit IOCs: IP count (Received + body)");
assertEqual(
  legitIOCs.urls[0].value,
  "https://github.com/settings/security",
  "Legit IOCs: URL value",
);

// Test 17: Extract IOCs from spoofed email
const spoofedIOCs = extractIOCs(spoofedHeaders, spoofedBody);
assertArrayLength(spoofedIOCs.urls, 1, "Spoofed IOCs: URL count");
// See the note on the body test above: the link text is not a URL, so there is
// no display/destination mismatch, and a plain http URL carries no risk flag
// of its own. The message is still High Risk on its authentication failures.
assertArrayLength(
  spoofedIOCs.mismatchedLinks,
  0,
  "Spoofed IOCs: no mismatched link for plain link text",
);
assertArrayLength(
  spoofedIOCs.urls[0].risks,
  0,
  "Spoofed IOCs: plain URL carries no risk flags",
);
assertTruthy(
  Array.isArray(spoofedIOCs.urls[0].riskFlags),
  "Spoofed IOCs: URL has a risk flag list",
);
assertTruthy(
  spoofedIOCs.urls[0].defanged,
  "Spoofed IOCs: URL has defanged version",
);

// Test 18: Extract IOCs from urgency email
const urgencyIOCs = extractIOCs(urgencyHeaders, urgencyBody);
assertArrayLength(
  urgencyIOCs.emails,
  1,
  "Urgency IOCs: Email count (deduplicated)",
);
assertArrayLength(urgencyIOCs.ips, 1, "Urgency IOCs: IP count");

// Test 19: URL shortener detection
const shortenerEmail = `From: test@example.com
Content-Type: text/plain

Check this link: https://bit.ly/abc123`;
const shortenerHeaders = parseHeaders(shortenerEmail);
const shortenerBody = parseBody(shortenerEmail);
const shortenerIOCs = extractIOCs(shortenerHeaders, shortenerBody);
assertArrayLength(shortenerIOCs.urls, 1, "Shortener: URL count");
assertTruthy(
  shortenerIOCs.urls[0].risks.some((r) => r.type === "url-shortener"),
  "Shortener: Detected as URL shortener",
);

// Test 20: Punycode detection
const punycodeEmail = `From: test@example.com
Content-Type: text/plain

Visit: https://xn--pple-43d.com/login`;
const punycodeHeaders = parseHeaders(punycodeEmail);
const punycodeBody = parseBody(punycodeEmail);
const punycodeIOCs = extractIOCs(punycodeHeaders, punycodeBody);
assertTruthy(
  punycodeIOCs.urls[0].risks.some((r) => r.type === "punycode"),
  "Punycode: Detected",
);

// Test 21: Risky attachment detection
const attachmentEmail = `From: test@example.com
Content-Type: multipart/mixed; boundary="attboundary"
MIME-Version: 1.0

--attboundary
Content-Type: application/octet-stream
Content-Disposition: attachment; filename="invoice.pdf.exe"

fake content
--attboundary--`;
const attHeaders = parseHeaders(attachmentEmail);
const attBody = parseBody(attachmentEmail);
const attIOCs = extractIOCs(attHeaders, attBody);
assertArrayLength(attIOCs.attachments, 1, "Attachment: Count");
assertTruthy(attIOCs.attachments[0].risky, "Attachment: Marked as risky");
assertTruthy(
  attIOCs.attachments[0].risks.some((r) => r.type === "double-extension"),
  "Attachment: Double extension detected",
);

// ==================== ANALYZE LANGUAGE TESTS ====================
console.log("\n--- analyze-language.js ---");

// Test 22: Urgency detection
const urgencyText =
  "Your account will be suspended within 24 hours. Act now to verify your information immediately.";
const urgencyAnalysis = analyzeLanguage(urgencyText);
assertTruthy(
  urgencyAnalysis.categories.urgency.matchCount > 0,
  "Language: Urgency detected",
);
assertTruthy(
  urgencyAnalysis.categories.urgency.score > 0,
  "Language: Urgency score > 0",
);
assertContains(
  urgencyAnalysis.highlightedText,
  "<mark",
  "Language: Has highlights",
);

// Test 23: Authority/fear detection
const authorityText =
  "This is a final notice from the IRS. Legal action will be taken if you do not comply.";
const authorityAnalysis = analyzeLanguage(authorityText);
assertTruthy(
  authorityAnalysis.categories.authority.matchCount > 0,
  "Language: Authority detected",
);

// Test 24: Financial detection
const financialText =
  "Please process a wire transfer of $10,000 to the following account. Send gift cards immediately.";
const financialAnalysis = analyzeLanguage(financialText);
assertTruthy(
  financialAnalysis.categories.financial.matchCount > 0,
  "Language: Financial detected",
);

// Test 25: Credential harvesting detection
const credentialText =
  "Click here to verify your account and confirm your password. Login to secure your account now.";
const credentialAnalysis = analyzeLanguage(credentialText);
assertTruthy(
  credentialAnalysis.categories.credential.matchCount > 0,
  "Language: Credential detected",
);

// Test 26: Clean text
const cleanText =
  "Hello, I hope you are doing well. Please review the attached document when you have time.";
const cleanAnalysis = analyzeLanguage(cleanText);
assertEqual(cleanAnalysis.totalScore, 0, "Language: Clean text has 0 score");
assertContains(
  cleanAnalysis.summary,
  "No suspicious",
  "Language: Clean text summary",
);

// Test 27: Language detection
const englishText =
  "The quick brown fox jumps over the lazy dog. This is a simple test message.";
const englishAnalysis = analyzeLanguage(englishText);
assertEqual(
  englishAnalysis.detectedLanguage,
  "en",
  "Language: English detected",
);

// Test 28: Empty/null input
const nullAnalysis = analyzeLanguage(null);
assertEqual(nullAnalysis.totalScore, 0, "Language: Null input returns 0 score");
const emptyAnalysis = analyzeLanguage("");
assertEqual(
  emptyAnalysis.totalScore,
  0,
  "Language: Empty input returns 0 score",
);

// ==================== SCORE TESTS ====================
console.log("\n--- score.js ---");

// Test 29: Legitimate email score
const legitLang = analyzeLanguage(legitBody.text);
const legitScore = calculateScore(legitAuth, legitIOCs, legitLang);
assertEqual(legitScore.tier, "Low Risk", "Score: Legit is Low Risk");
assertTruthy(legitScore.score < 30, "Score: Legit score < 30");
assertEqual(
  legitScore.breakdown.authentication,
  0,
  "Score: Legit auth breakdown is 0",
);

// Test 30: Spoofed email score
const spoofedLang = analyzeLanguage(spoofedBody.text);
const spoofedScore = calculateScore(spoofedAuth, spoofedIOCs, spoofedLang);
assertEqual(spoofedScore.tier, "High Risk", "Score: Spoofed is High Risk");
assertTruthy(spoofedScore.score >= 60, "Score: Spoofed score >= 60");
assertTruthy(spoofedScore.reasons.length > 0, "Score: Spoofed has reasons");
assertContains(
  spoofedScore.reasons.join(" "),
  "SPF",
  "Score: Spoofed mentions SPF fail",
);

// Test 31: Urgency email score (auth passes but language flags)
const urgencyLang = analyzeLanguage(urgencyBody.text);
const urgencyScore = calculateScore(urgencyAuth, urgencyIOCs, urgencyLang);
assertTruthy(urgencyScore.score > 0, "Score: Urgency has elevated score");
assertTruthy(
  urgencyScore.reasons.some(
    (r) => r.includes("urgency") || r.includes("financial"),
  ),
  "Score: Urgency mentions language flags",
);

// Test 32: Score with null language
const noLangScore = calculateScore(legitAuth, legitIOCs, null);
assertEqual(noLangScore.tier, "Low Risk", "Score: No lang still works");

// Test 33: Score with no IOCs
const noIocScore = calculateScore(
  legitAuth,
  { urls: [], domains: [], ips: [], emails: [], attachments: [] },
  null,
);
assertEqual(noIocScore.tier, "Low Risk", "Score: No IOCs still works");

// ==================== END-TO-END TESTS ====================
console.log("\n--- end-to-end ---");

// Test 34: Full pipeline on legitimate email
assertEqual(
  legitScore.tier,
  "Low Risk",
  "E2E: Legitimate email scored as Low Risk",
);

// Test 35: Full pipeline on spoofed email
assertEqual(
  spoofedScore.tier,
  "High Risk",
  "E2E: Spoofed email scored as High Risk",
);

// Test 36: Full pipeline on urgency email
assertTruthy(urgencyScore.score > 0, "E2E: Urgency email has elevated score");

// ==================== SUMMARY ====================
console.log("\n\n=== Test Results ===");
console.log(`Passed: ${passCount}`);
console.log(`Failed: ${failCount}`);
console.log(`Total:  ${passCount + failCount}`);

if (failures.length > 0) {
  console.log("\n--- Failures ---");
  for (const failure of failures) {
    console.log(`\n${failure}`);
  }
  process.exit(1);
} else {
  console.log("\nAll tests passed!");
  process.exit(0);
}
