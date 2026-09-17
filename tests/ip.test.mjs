// IP validation and extraction tests.
// Run: node tests/ip.test.mjs
//
// The anchor case is 15.21.360.10 — a value the old dotted-quad pattern
// accepted, displayed as "Last relay", and offered to AbuseIPDB, which
// rejected it as not an IP address pattern.

import assert from "node:assert/strict";
import {
  isValidIPv4,
  isValidIPv6,
  isValidIP,
  isPrivateIP,
  isRoutableIP,
  findIPs,
} from "../scripts/ip-utils.js";
import { parseHeaders } from "../scripts/parse-headers.js";
import { parseAuth } from "../scripts/parse-auth.js";
import { extractIOCs } from "../scripts/extract-iocs.js";

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

await test("the reported value is rejected", () => {
  assert.equal(isValidIPv4("15.21.360.10"), false, "360 exceeds 255");
  assert.equal(isValidIP("15.21.360.10"), false);
});

await test("octet range is enforced at both edges", () => {
  assert.equal(isValidIPv4("0.0.0.0"), true);
  assert.equal(isValidIPv4("255.255.255.255"), true);
  assert.equal(isValidIPv4("256.1.1.1"), false);
  assert.equal(isValidIPv4("1.1.1.256"), false);
  assert.equal(isValidIPv4("999.999.999.999"), false);
});

await test("malformed shapes are rejected", () => {
  for (const bad of [
    "1.2.3",
    "1.2.3.4.5",
    "1.2.3.",
    ".1.2.3",
    "1..3.4",
    "a.b.c.d",
    "1.2.3.-4",
    "1.2.3.4a",
    "",
    null,
    undefined,
    12345,
  ]) {
    assert.equal(isValidIPv4(bad), false, `should reject ${JSON.stringify(bad)}`);
  }
});

await test("zero-padded octets are rejected as ambiguous", () => {
  // Some resolvers read 010 as octal; it is a known obfuscation trick.
  assert.equal(isValidIPv4("192.168.001.1"), false);
  assert.equal(isValidIPv4("010.1.1.1"), false);
  assert.equal(isValidIPv4("0.1.1.1"), true, "a single zero is fine");
});

await test("valid IPv6 forms are accepted", () => {
  assert.equal(isValidIPv6("2001:0db8:85a3:0000:0000:8a2e:0370:7334"), true);
  assert.equal(isValidIPv6("2001:db8::1"), true);
  assert.equal(isValidIPv6("::1"), true);
  assert.equal(isValidIPv6("::ffff:192.0.2.1"), true);
  assert.equal(isValidIPv6("fe80::1"), true);
});

await test("invalid IPv6 forms are rejected", () => {
  assert.equal(isValidIPv6("2001:db8::1::2"), false, "two :: runs");
  assert.equal(isValidIPv6("gggg::1"), false);
  assert.equal(isValidIPv6("::ffff:15.21.360.10"), false, "bad v4 tail");
  assert.equal(isValidIPv6("1.2.3.4"), false, "not v6");
});

await test("private and reserved ranges are identified", () => {
  for (const ip of [
    "10.0.0.1",
    "192.168.1.1",
    "172.16.0.1",
    "172.31.255.255",
    "127.0.0.1",
    "169.254.1.1",
    "100.64.0.1",
    "224.0.0.1",
    "::1",
  ]) {
    assert.equal(isPrivateIP(ip), true, `${ip} should be private/reserved`);
    assert.equal(isRoutableIP(ip), false);
  }
  assert.equal(isPrivateIP("172.32.0.1"), false, "just outside the /12");
  assert.equal(isPrivateIP("8.8.8.8"), false);
  assert.equal(isRoutableIP("45.62.170.115"), true);
});

await test("an invalid address is never private and never routable", () => {
  assert.equal(isPrivateIP("15.21.360.10"), false);
  assert.equal(isRoutableIP("15.21.360.10"), false);
});

await test("findIPs returns only genuine addresses", () => {
  const text =
    "queue id 15.21.360.10, version 1.2.3.4.5, real 45.62.170.115 and 8.8.8.8";
  const found = findIPs(text);
  assert.ok(!found.includes("15.21.360.10"), "invalid octet must not survive");
  assert.ok(found.includes("45.62.170.115"));
  assert.ok(found.includes("8.8.8.8"));
  assert.ok(
    !found.some((ip) => "1.2.3.4.5".startsWith(ip) && ip === "1.2.3.4"),
    "must not slice a five-part version string into an address",
  );
});

// --- end to end through the real parsers -----------------------------------

const emlWithBadIP = `Received: from relay.test (relay.test [15.21.360.10]) by inbox.test; Mon, 1 Sep 2025 10:00:01 +0000
Received: from origin.test (origin.test [45.62.170.115]) by relay.test; Mon, 1 Sep 2025 10:00:00 +0000
From: a@example.com

body`;

await test("an invalid bracketed IP never reaches the received chain", () => {
  const auth = parseAuth(parseHeaders(emlWithBadIP));
  const ips = auth.receivedChain.map((h) => h.ip);
  assert.ok(!ips.includes("15.21.360.10"), `chain still has it: ${ips}`);
  assert.ok(ips.includes("45.62.170.115"), "the valid one must survive");
});

await test("an invalid IP never becomes an IOC", () => {
  const headers = parseHeaders(emlWithBadIP);
  const iocs = extractIOCs(headers, null);
  const values = iocs.ips.map((i) => i.value);
  assert.ok(!values.includes("15.21.360.10"), `IOCs still have it: ${values}`);
  assert.ok(values.includes("45.62.170.115"));
});

await test("a hop whose only candidate is invalid reports no IP rather than a wrong one", () => {
  const auth = parseAuth(
    parseHeaders(`Received: from weird.test (weird.test [15.21.360.10]) by inbox.test; Mon, 1 Sep 2025 10:00:00 +0000
From: a@example.com

body`),
  );
  assert.equal(auth.receivedChain[0].ip, null);
});

await test("private IOC addresses are marked so lookups can be withheld", () => {
  const iocs = extractIOCs(
    parseHeaders(`Received: from internal.test (internal.test [192.168.1.50]) by inbox.test; Mon, 1 Sep 2025 10:00:00 +0000
From: a@example.com

body`),
    null,
  );
  const ip = iocs.ips.find((i) => i.value === "192.168.1.50");
  assert.ok(ip, "the address should still be listed");
  assert.equal(ip.private, true);
});

await test("IPv6 in a Received header is captured", () => {
  const auth = parseAuth(
    parseHeaders(`Received: from v6.test (v6.test [IPv6:2001:db8::1]) by inbox.test; Mon, 1 Sep 2025 10:00:00 +0000
From: a@example.com

body`),
  );
  assert.equal(auth.receivedChain[0].ip, "2001:db8::1");
});

// --- by-clause attribution ----------------------------------------------------

await test("the receiving server's IP in the by-clause is never the sender's", async () => {
  const { receivedFromIP } = await import("../scripts/ip-utils.js");
  assert.equal(
    receivedFromIP("from unknown.test by mx.test (mx.test [198.51.100.8]); Mon, 1 Sep 2025 10:00:00 +0000"),
    null,
    "the only IP belongs to the receiver",
  );
  assert.equal(
    receivedFromIP("from a.test (a.test [203.0.113.5]) by mx.test (mx.test [198.51.100.8]); date"),
    "203.0.113.5",
  );
});

await test("Microsoft's bare parenthesised IPs are read from the from-clause", async () => {
  const { receivedFromIP } = await import("../scripts/ip-utils.js");
  assert.equal(
    receivedFromIP("from relay.test (40.107.22.61) by DM6PR12MB.mail.protection.outlook.com (10.167.8.14) with Microsoft SMTP Server; date"),
    "40.107.22.61",
  );
});

// --- sender IP resolution ------------------------------------------------
// The originating hop frequently records a private address (NAT, internal
// submission relay). Keep it, but walk outward to the first public address so
// the sender's real IP is what gets shown and looked up.

const chainOf = (...received) =>
  parseAuth(
    parseHeaders(
      received.map((r) => `Received: ${r}`).join("\n") +
        "\nFrom: a@example.com\n\nbody",
    ),
  );

await test("a private originating hop walks outward to the first public IP", () => {
  // Header order is newest first, so the last line is the origin.
  const a = chainOf(
    "from mx.test (mx.test [45.62.170.115]) by inbox.test; Mon, 1 Sep 2025 10:00:03 +0000",
    "from gw.test (gw.test [203.0.113.7]) by mx.test; Mon, 1 Sep 2025 10:00:02 +0000",
    "from pc.local (pc.local [192.168.1.50]) by gw.test; Mon, 1 Sep 2025 10:00:01 +0000",
  );
  assert.equal(a.senderIp.originIp, "192.168.1.50", "literal origin kept");
  assert.equal(a.senderIp.privateIp, "192.168.1.50", "reported as internal");
  assert.equal(a.senderIp.publicIp, "203.0.113.7", "first public going outward");
});

await test("several private hops in a row are skipped and counted", () => {
  const a = chainOf(
    "from mx.test (mx.test [45.62.170.115]) by inbox.test; Mon, 1 Sep 2025 10:00:04 +0000",
    "from edge.test (edge.test [203.0.113.7]) by mx.test; Mon, 1 Sep 2025 10:00:03 +0000",
    "from relay.local (relay.local [10.0.0.5]) by edge.test; Mon, 1 Sep 2025 10:00:02 +0000",
    "from pc.local (pc.local [192.168.1.50]) by relay.local; Mon, 1 Sep 2025 10:00:01 +0000",
  );
  assert.equal(a.senderIp.privateIp, "192.168.1.50");
  assert.equal(a.senderIp.publicIp, "203.0.113.7");
  assert.equal(a.senderIp.privateHopsSkipped, 1, "10.0.0.5 was skipped");
});

await test("a public originating hop is used as-is", () => {
  const a = chainOf(
    "from mx.test (mx.test [45.62.170.115]) by inbox.test; Mon, 1 Sep 2025 10:00:02 +0000",
    "from sender.test (sender.test [203.0.113.7]) by mx.test; Mon, 1 Sep 2025 10:00:01 +0000",
  );
  assert.equal(a.senderIp.publicIp, "203.0.113.7");
  assert.equal(a.senderIp.privateIp, null, "nothing internal to report");
  assert.equal(a.senderIp.privateHopsSkipped, 0);
});

await test("an all-private chain reports no public IP but keeps the origin", () => {
  const a = chainOf(
    "from relay.local (relay.local [10.0.0.5]) by inbox.local; Mon, 1 Sep 2025 10:00:02 +0000",
    "from pc.local (pc.local [192.168.1.50]) by relay.local; Mon, 1 Sep 2025 10:00:01 +0000",
  );
  assert.equal(a.senderIp.publicIp, null);
  assert.equal(a.senderIp.originIp, "192.168.1.50");
  assert.equal(a.senderIp.privateIp, "192.168.1.50");
});

await test("invalid addresses are skipped while walking outward", () => {
  const a = chainOf(
    "from mx.test (mx.test [45.62.170.115]) by inbox.test; Mon, 1 Sep 2025 10:00:03 +0000",
    "from gw.test (gw.test [203.0.113.7]) by mx.test; Mon, 1 Sep 2025 10:00:02 +0000",
    "from weird.test (weird.test [15.21.360.10]) by gw.test; Mon, 1 Sep 2025 10:00:01 +0000",
  );
  // The bogus hop has no usable IP, so the origin is the next valid one out.
  assert.equal(a.senderIp.publicIp, "203.0.113.7");
  assert.equal(a.senderIp.originIp, "203.0.113.7");
});

await test("an empty chain resolves to nothing rather than throwing", () => {
  const a = parseAuth(parseHeaders("From: a@example.com\n\nbody"));
  assert.equal(a.senderIp.publicIp, null);
  assert.equal(a.senderIp.originIp, null);
});

// --- renderer smoke test ---------------------------------------------------
// renderIOCs only writes to container.innerHTML, so it runs without a DOM.
// A previous edit referenced a const before its declaration, which threw at
// render time and wiped the entire IOC panel while every parser test still
// passed. This catches that class of mistake.

await test("renderIOCs builds every section without throwing", async () => {
  const { renderIOCs } = await import("../scripts/render.js");
  const container = { innerHTML: "" };
  const iocs = {
    urls: [
      { value: "http://45.62.170.115/login", risks: [], riskFlags: [{ type: "high", label: "IP URL" }] },
    ],
    domains: [{ value: "evil.test", riskFlags: [] }],
    ips: [
      { value: "45.62.170.115", riskFlags: [], private: false },
      { value: "192.168.1.50", riskFlags: [{ type: "low", label: "Private/Reserved" }], private: true },
    ],
    emails: [{ value: "a@evil.test", riskFlags: [] }],
    attachments: [
      { value: "x.exe", riskFlags: [], sha256: "a".repeat(64), md5: "b".repeat(32), size: 10, contentType: "application/octet-stream" },
    ],
    mismatchedLinks: [{ text: "bank.test", href: "http://evil.test" }],
  };
  renderIOCs(container, iocs, { virustotal: "k", abuseipdb: "k" });
  assert.ok(container.innerHTML.length > 0, "should render markup");
  assert.ok(container.innerHTML.includes("45.62.170.115"));
  assert.ok(container.innerHTML.includes("a".repeat(64)), "file hash shown");
});

await test("a private IP row offers no reputation lookup buttons", async () => {
  const { renderIOCs } = await import("../scripts/render.js");
  const container = { innerHTML: "" };
  renderIOCs(
    container,
    { urls: [], domains: [], ips: [{ value: "192.168.1.50", riskFlags: [], private: true }], emails: [], attachments: [], mismatchedLinks: [] },
    { virustotal: "k", abuseipdb: "k" },
  );
  assert.ok(container.innerHTML.includes("192.168.1.50"), "still listed");
  assert.ok(
    !container.innerHTML.includes("lookupAbuseIPDB"),
    "no AbuseIPDB button for a private address",
  );
});

console.log(`\n${passed} passed, ${failures.length} failed`);
for (const f of failures) console.error(`  FAIL  ${f.name}\n        ${f.message}`);
process.exit(failures.length ? 1 : 0);
