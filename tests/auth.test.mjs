// Authentication + alignment regression tests.
// Run: node tests/auth.test.mjs
//
// Every case here is a bug that shipped. If one fails, the parser regressed.

import assert from "node:assert/strict";
import { parseHeaders } from "../scripts/parse-headers.js";
import { parseAuth, orgDomain } from "../scripts/parse-auth.js";
import { calculateScore } from "../scripts/score.js";
import { renderAuth } from "../scripts/render.js";

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

const analyze = (raw) => parseAuth(parseHeaders(raw));

// ---------------------------------------------------------------------------
// Repeated headers. Every relay prepends its own Authentication-Results and
// Received-SPF, so these arrive as arrays. Calling .match() on an array threw.
// ---------------------------------------------------------------------------

test("multiple Authentication-Results headers do not throw", () => {
  const a = analyze(`Authentication-Results: mx.ourcompany.com; spf=fail smtp.mailfrom=evil.test; dkim=fail; dmarc=fail header.from=bank.test
Authentication-Results: relay.upstream.test; spf=pass smtp.mailfrom=bank.test; dkim=pass header.d=bank.test
From: alerts@bank.test
Return-Path: <bounce@evil.test>

body`);
  assert.equal(a.mechanisms.spf.status, "fail");
  assert.equal(a.trust.authResultsCount, 2);
});

test("topmost Authentication-Results wins over a forged lower one", () => {
  const a = analyze(`Authentication-Results: mx.ourcompany.com; spf=fail smtp.mailfrom=evil.test
Authentication-Results: attacker-supplied; spf=pass smtp.mailfrom=bank.test
From: alerts@bank.test

body`);
  assert.equal(a.mechanisms.spf.status, "fail", "must trust our own MTA");
  assert.ok(
    a.trust.warnings.some((w) => w.includes("lower Authentication-Results")),
    "should warn that a lower header disagrees",
  );
});

test("multiple DKIM-Signature headers are all parsed", () => {
  const a = analyze(`DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=example.com; s=one; bh=x; b=y
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=mailer.example.com; s=two; bh=x; b=y
From: news@example.com

body`);
  assert.equal(a.signatures.length, 2);
  assert.deepEqual(
    a.signatures.map((s) => s.domain),
    ["example.com", "mailer.example.com"],
  );
});

test("duplicate From headers are flagged", () => {
  const a = analyze(`From: real@bank.test
From: attacker@evil.test
Subject: hi

body`);
  assert.ok(a.trust.warnings.some((w) => w.includes("From headers")));
});

// ---------------------------------------------------------------------------
// SPF appearing in different headers, in different vendors' formats.
// ---------------------------------------------------------------------------

test("RFC 7208 Received-SPF puts the result in the first token", () => {
  const a = analyze(`Received-SPF: Pass (mx.example.com: domain of sender@example.com designates 192.0.2.1 as permitted sender) client-ip=192.0.2.1; envelope-from=sender@example.com; helo=mail.example.com
From: sender@example.com

body`);
  assert.equal(a.mechanisms.spf.status, "pass", "was 'unknown' before the fix");
  assert.equal(a.spf.clientIp, "192.0.2.1");
  assert.equal(a.spf.domain, "example.com");
});

test("Microsoft-style Received-SPF (result=...) still parses", () => {
  const a = analyze(`Received-SPF: None (protection.outlook.com: domain does not designate permitted sender hosts) result=softfail
From: sender@example.com

body`);
  assert.equal(a.mechanisms.spf.status, "none");
});

test("Authentication-Results takes precedence over Received-SPF", () => {
  const a = analyze(`Authentication-Results: mx.ourcompany.com; spf=fail smtp.mailfrom=evil.test
Received-SPF: Pass (comment) client-ip=192.0.2.1
From: sender@evil.test

body`);
  assert.equal(a.mechanisms.spf.status, "fail");
  assert.match(a.mechanisms.spf.source, /Authentication-Results/);
});

test("spf= inside a DKIM clause comment is not read as the SPF result", () => {
  const a = analyze(`Authentication-Results: mx.ourcompany.com; dkim=fail (bad signature, upstream said spf=pass) header.d=evil.test; dmarc=fail header.from=bank.test
From: alerts@bank.test

body`);
  assert.equal(
    a.mechanisms.spf.status,
    "unknown",
    "no spf clause exists; must not harvest 'spf=pass' from a comment",
  );
  assert.equal(a.mechanisms.dkim.status, "fail");
});

test("semicolons inside comments do not split clauses", () => {
  const a = analyze(`Authentication-Results: mx.ourcompany.com; spf=pass (ip is fine; really) smtp.mailfrom=example.com; dmarc=pass header.from=example.com
From: x@example.com

body`);
  assert.equal(a.mechanisms.spf.status, "pass");
  assert.equal(a.mechanisms.dmarc.status, "pass");
});

test("permerror and temperror stay distinct from fail and pass", () => {
  const perm = analyze(`Authentication-Results: mx.test; spf=permerror smtp.mailfrom=x.test
From: a@x.test

body`);
  assert.equal(perm.mechanisms.spf.status, "permerror");

  const temp = analyze(`Authentication-Results: mx.test; spf=temperror smtp.mailfrom=x.test
From: a@x.test

body`);
  assert.equal(temp.mechanisms.spf.status, "temperror");
});

test("neutral is not silently downgraded to none", () => {
  const a = analyze(`Authentication-Results: mx.test; spf=neutral smtp.mailfrom=x.test
From: a@x.test

body`);
  assert.equal(a.mechanisms.spf.status, "neutral");
});

test("a DKIM signature with no verification result is 'unverified', not a pass", () => {
  const a = analyze(`DKIM-Signature: v=1; a=rsa-sha256; d=example.com; s=sel; bh=x; b=y
From: x@example.com

body`);
  assert.equal(a.mechanisms.dkim.status, "unverified");
});

// ---------------------------------------------------------------------------
// SPF read from both headers. They can disagree, and one silently standing in
// for the other produces the wrong authentication verdict.
// ---------------------------------------------------------------------------

// Verbatim from a real Microsoft 365 message.
const MS_AR =
  "Authentication-Results: spf=pass (sender IP is 149.72.232.65) smtp.mailfrom=em6908.spglobal.com; dkim=pass (signature was verified) header.d=spglobal.com;dmarc=pass action=none header.from=spglobal.com;compauth=pass reason=100";
const MS_RSPF =
  "Received-SPF: Pass (protection.outlook.com: domain of em6908.spglobal.com designates 149.72.232.65 as permitted sender) receiver=protection.outlook.com; client-ip=149.72.232.65; helo=wrqvzvqk.outbound-mail.sendgrid.net; pr=C";

test("Microsoft A-R with no authserv-id keeps its SPF clause", () => {
  const a = analyze(`${MS_AR}
From: news@spglobal.com

body`);
  assert.equal(
    a.trust.authservId,
    null,
    "was 'spf=pass' — the SPF clause was eaten as the server name",
  );
  assert.equal(a.mechanisms.spf.status, "pass");
  assert.match(a.mechanisms.spf.source, /^Authentication-Results/);
  assert.equal(a.mechanisms.dkim.status, "pass");
  assert.equal(a.mechanisms.dmarc.status, "pass");
});

test("SPF IP is read from the A-R comment", () => {
  const a = analyze(`${MS_AR}
From: news@spglobal.com

body`);
  const ar = a.spf.sources.find((s) => s.header === "Authentication-Results");
  assert.equal(ar.ip, "149.72.232.65");
  assert.equal(ar.identity, "em6908.spglobal.com");
});

test("both SPF headers are kept and agree on result and IP", () => {
  const a = analyze(`${MS_AR}
${MS_RSPF}
From: news@spglobal.com

body`);
  assert.equal(a.spf.sources.length, 2);
  assert.equal(a.spf.resultsAgree, true);
  assert.equal(a.spf.ipsAgree, true);
  assert.ok(
    !a.trust.warnings.some((w) => /SPF headers/.test(w)),
    "agreeing headers must not warn",
  );
});

test("SPF headers that disagree on result are both shown and warned about", () => {
  const a = analyze(`Authentication-Results: mx.ourcompany.com; spf=fail (sender IP is 203.0.113.9) smtp.mailfrom=evil.test
Received-SPF: Pass (forged) client-ip=203.0.113.9; envelope-from=bounce@evil.test
From: a@bank.test

body`);
  assert.equal(a.mechanisms.spf.status, "fail", "A-R is authoritative");
  assert.equal(a.spf.resultsAgree, false);
  assert.ok(
    a.trust.warnings.some((w) => /SPF headers disagree/.test(w)),
    "disagreement must be a warning",
  );
  assert.equal(a.spf.sources.find((s) => s.header === "Received-SPF").status, "pass");
});

test("SPF headers that checked different IPs are warned about", () => {
  const a = analyze(`Authentication-Results: mx.test; spf=pass (sender IP is 203.0.113.9) smtp.mailfrom=x.test
Received-SPF: Pass (comment) client-ip=198.51.100.4; envelope-from=a@x.test
From: a@x.test

body`);
  assert.equal(a.spf.ipsAgree, false);
  assert.ok(a.trust.warnings.some((w) => /different IPs/.test(w)));
});

test("SPF IP is compared with the sender's public IP", () => {
  const a = analyze(`Received: from mx.test (mx.test [149.72.232.65]) by inbox.test; Mon, 1 Sep 2025 10:00:01 +0000
Received: from app.spglobal.test (app.spglobal.test [198.51.100.20]) by mx.test; Mon, 1 Sep 2025 10:00:00 +0000
${MS_AR}
From: news@spglobal.com

body`);
  assert.equal(a.spf.senderPublicIp, "198.51.100.20");
  assert.equal(a.spf.matchesSenderIp, false, "ESP relay differs from origin");
  assert.ok(
    !a.trust.warnings.some((w) => /sender/i.test(w) && /SPF/.test(w)),
    "a relay differing from the origin is normal, not a warning",
  );
});

test("a forged Received-SPF cannot supply the domain used for alignment", () => {
  // A-R records smtp.mailfrom as a bare domain (no @). That domain was being
  // dropped, and the alignment check fell back to the forged header's domain —
  // reporting a spoofed message as aligned.
  const a = analyze(`Authentication-Results: spf=fail (sender IP is 203.0.113.9) smtp.mailfrom=evil.test; dmarc=fail header.from=spglobal.com
Received-SPF: Pass (forged) client-ip=149.72.232.65; envelope-from=bounce@spglobal.com
From: news@spglobal.com
Return-Path: <bounce@evil.test>

body`);
  assert.equal(a.spf.domain, "evil.test", "bare-domain smtp.mailfrom must be read");
  const spfRow = a.domainAlignment.entries.find((e) => e.source === "Return-Path");
  assert.equal(spfRow.domain, "evil.test");
  assert.equal(spfRow.aligned, false, "evil.test does not align with spglobal.com");
});

test("renderAuth shows both SPF headers and a spelled-out alignment comparison", () => {
  const a = analyze(`${MS_AR}
${MS_RSPF}
From: news@spglobal.com
Return-Path: <bounces@em6908.spglobal.com>

body`);
  const c = { innerHTML: "" };
  renderAuth(c, a);
  const html = c.innerHTML;
  assert.match(html, /Authentication-Results/);
  assert.match(html, /Received-SPF/);
  assert.match(html, /149\.72\.232\.65/);
  assert.match(html, /Both headers agree/);
  assert.match(html, /Return-Path <span class="mono">\(em6908\.spglobal\.com\)/);
  assert.match(html, /relaxed — both under <span class="mono">spglobal\.com/);
});

// ---------------------------------------------------------------------------
// Alignment. This is where legitimate mail was being called phishing.
// ---------------------------------------------------------------------------

test("relaxed alignment is symmetric (subdomain in From, org domain in envelope)", () => {
  const a = analyze(`Authentication-Results: mx.test; spf=pass smtp.mailfrom=bounce@example.com
From: news@mail.example.com
Return-Path: <bounce@example.com>

body`);
  assert.deepEqual(
    a.domainAlignment.mismatches,
    [],
    "example.com and mail.example.com share an org domain in both directions",
  );
  assert.equal(a.domainAlignment.dmarcAligned, true);
});

test("multi-part public suffixes resolve to the right org domain", () => {
  assert.equal(orgDomain("mail.bbc.co.uk"), "bbc.co.uk");
  assert.equal(orgDomain("bbc.co.uk"), "bbc.co.uk");
  assert.equal(orgDomain("a.b.example.com"), "example.com");
  assert.equal(orgDomain("example.io"), "example.io");
  // co.uk alone is a suffix, not an org domain, but must not crash.
  assert.equal(orgDomain("co.uk"), "co.uk");
});

test("a differing Reply-To is NOT a DMARC alignment failure", () => {
  const a = analyze(`Authentication-Results: mx.test; spf=pass smtp.mailfrom=bounce@example.com; dkim=pass header.d=example.com; dmarc=pass header.from=example.com
From: no-reply@example.com
Reply-To: support@zendesk.test
Return-Path: <bounce@example.com>

body`);
  assert.deepEqual(
    a.domainAlignment.mismatches,
    [],
    "Reply-To is not a DMARC input",
  );
  assert.equal(a.domainAlignment.dmarcAligned, true);
  assert.equal(a.domainAlignment.replyToMismatch, true, "still reported");
});

test("DMARC passes when DKIM aligns even though SPF does not", () => {
  const a = analyze(`Authentication-Results: mx.test; spf=pass smtp.mailfrom=bounce@sendgrid.test; dkim=pass header.d=example.com
From: news@example.com
Return-Path: <bounce@sendgrid.test>

body`);
  assert.equal(
    a.domainAlignment.dmarcAligned,
    true,
    "DMARC needs SPF *or* DKIM alignment, not both",
  );
});

test("a genuinely spoofed sender is still caught", () => {
  const a = analyze(`Authentication-Results: mx.ourcompany.com; spf=fail smtp.mailfrom=evil.test; dkim=fail header.d=evil.test; dmarc=fail header.from=bank.test
From: security@bank.test
Return-Path: <bounce@evil.test>

body`);
  assert.equal(a.overallStatus.level, "fail");
  assert.equal(a.domainAlignment.dmarcAligned, false);
  assert.ok(a.domainAlignment.mismatches.length > 0);
});

test("alignment mismatch actually reaches overallStatus (dead branch regression)", () => {
  const a = analyze(`Authentication-Results: mx.test; spf=pass smtp.mailfrom=bounce@evil.test
From: security@bank.test
Return-Path: <bounce@evil.test>

body`);
  assert.ok(
    a.overallStatus.issues.some((i) => i.includes("not aligned")),
    "the old `!aligned` check on an object never fired",
  );
});

// ---------------------------------------------------------------------------
// Received chain
// ---------------------------------------------------------------------------

test("legitimate relays on non-.com TLDs are not flagged suspicious", () => {
  const a = analyze(`Received: from mx.provider.io (mx.provider.io [192.0.2.9]) by inbox.test; Mon, 1 Sep 2025 10:00:01 +0000
Received: from smtp.company.co.uk (smtp.company.co.uk [198.51.100.4]) by mx.provider.io; Mon, 1 Sep 2025 10:00:00 +0000
From: a@company.co.uk

body`);
  assert.equal(
    a.receivedChain.filter((h) => h.suspicious).length,
    0,
    "old heuristic flagged everything not ending in .com/.org/.net",
  );
  assert.equal(a.receivedChain[0].ip, "192.0.2.9");
});

test("hops are numbered so hop 1 is the origin", () => {
  const a = analyze(`Received: from b.test (b.test [192.0.2.2]) by inbox.test; Mon, 1 Sep 2025 10:00:01 +0000
Received: from a.test (a.test [192.0.2.1]) by b.test; Mon, 1 Sep 2025 10:00:00 +0000
From: x@a.test

body`);
  assert.equal(a.receivedChain.length, 2);
  assert.equal(a.receivedChain[1].number, 1);
  assert.equal(a.receivedChain[1].isOrigin, true);
  assert.equal(a.receivedChain[1].ip, "192.0.2.1");
});

// ---------------------------------------------------------------------------
// Scoring
// ---------------------------------------------------------------------------

const passingAuth = () =>
  analyze(`Authentication-Results: mx.test; spf=pass smtp.mailfrom=bounce@example.com; dkim=pass header.d=example.com; dmarc=pass header.from=example.com
From: news@example.com
Return-Path: <bounce@example.com>

body`);

test("many shortener links cannot outweigh fully passing authentication", () => {
  const urls = [];
  for (let i = 0; i < 20; i++) {
    urls.push({
      value: `https://bit.ly/${i}`,
      risks: [{ type: "url-shortener", level: "medium" }],
    });
  }
  const s = calculateScore(
    passingAuth(),
    { urls, domains: [], ips: [], emails: [], attachments: [] },
    null,
  );
  assert.equal(
    s.tier,
    "Low Risk",
    `20 shortener links with SPF+DKIM+DMARC all passing scored ${s.score}`,
  );
});

test("the auth breakdown key matches what the renderer reads", () => {
  const s = calculateScore(
    passingAuth(),
    { urls: [], domains: [], ips: [], emails: [], attachments: [] },
    null,
  );
  assert.ok("auth" in s.breakdown, "renderer reads breakdown.auth");
});

test("a spoofed sender still scores High Risk", () => {
  const a = analyze(`Authentication-Results: mx.ourcompany.com; spf=fail smtp.mailfrom=evil.test; dkim=fail header.d=evil.test; dmarc=fail header.from=bank.test
From: security@bank.test
Return-Path: <bounce@evil.test>

body`);
  const s = calculateScore(
    a,
    {
      urls: [
        { value: "http://192.0.2.5/login", risks: [{ type: "ip-url", level: "high" }] },
      ],
      domains: [],
      ips: [],
      emails: [],
      attachments: [],
    },
    null,
  );
  assert.equal(s.tier, "High Risk", `scored ${s.score}`);
});

test("every scored point produces a reason", () => {
  const s = calculateScore(
    passingAuth(),
    {
      urls: [
        { value: "https://bit.ly/x", risks: [{ type: "url-shortener", level: "medium" }] },
      ],
      domains: [],
      ips: [],
      emails: [],
      attachments: [],
    },
    null,
  );
  if (s.score > 0) {
    assert.ok(s.reasons.length > 0);
    assert.ok(
      !s.reasons.includes("Minor risk indicators present"),
      "the generic placeholder means a score with no explanation",
    );
  }
});

// ---------------------------------------------------------------------------

console.log(`\n${passed} passed, ${failures.length} failed`);
for (const f of failures) console.error(`  FAIL  ${f.name}\n        ${f.message}`);
process.exit(failures.length ? 1 : 0);
