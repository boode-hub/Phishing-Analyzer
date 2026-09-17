// Header order tests.
// Run: node tests/headers.test.mjs

import assert from "node:assert/strict";
import { parseHeaders } from "../scripts/parse-headers.js";
import { renderHeaders } from "../scripts/render.js";

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

const RAW = `Received: from b.test (b.test [198.51.100.2]) by inbox.test;
 Mon, 1 Sep 2025 10:00:02 +0000
Authentication-Results: mx.test; spf=pass smtp.mailfrom=a.test
Received: from a.test (a.test [203.0.113.1]) by b.test; Mon, 1 Sep 2025 10:00:01 +0000
X-Custom-Header: first
From: Alice <alice@a.test>
DKIM-Signature: v=1; d=a.test; s=s1;
	bh=abc; b=def
Subject: Hello
X-Custom-Header: second

Body: this line is in the body, not a header`;

test("headers are kept in their original order, repeats in place", () => {
  const names = parseHeaders(RAW).ordered.map((h) => h.name);
  assert.deepEqual(names, [
    "Received",
    "Authentication-Results",
    "Received",
    "X-Custom-Header",
    "From",
    "DKIM-Signature",
    "Subject",
    "X-Custom-Header",
  ]);
});

test("folded values are unfolded and name case is preserved", () => {
  const o = parseHeaders(RAW).ordered;
  assert.equal(o[0].value, "from b.test (b.test [198.51.100.2]) by inbox.test; Mon, 1 Sep 2025 10:00:02 +0000");
  assert.equal(o[5].name, "DKIM-Signature");
  assert.match(o[5].value, /s=s1; bh=abc; b=def$/);
});

test("repeated headers keep their individual values in order", () => {
  const custom = parseHeaders(RAW).ordered.filter((h) => h.name === "X-Custom-Header");
  assert.deepEqual(custom.map((h) => h.value), ["first", "second"]);
});

test("body lines that contain a colon are not headers", () => {
  assert.ok(!parseHeaders(RAW).ordered.some((h) => h.name === "Body"));
});

test("the original-order view renders rows in email order with hop labels", () => {
  const container = { innerHTML: "", querySelectorAll: () => [] };
  renderHeaders(container, parseHeaders(RAW));
  const html = container.innerHTML;
  assert.match(html, /Original order/);
  assert.match(html, /Key headers first/);

  const ordered = html.split('headers-ordered')[1];
  const names = [...ordered.matchAll(/<td class="header-name">([^<]+)/g)].map((m) => m[1]);
  assert.deepEqual(names.slice(0, 4), ["Received", "Authentication-Results", "Received", "X-Custom-Header"]);

  // The first Received is the last hop; the lowest one is where it started.
  assert.match(ordered, /hop 2 · last/);
  assert.match(ordered, /hop 1 · origin/);
  assert.ok(ordered.indexOf("hop 2") < ordered.indexOf("hop 1"));
});

test("header values are escaped in the original-order view", () => {
  const container = { innerHTML: "", querySelectorAll: () => [] };
  renderHeaders(container, parseHeaders(`Subject: <img src=x onerror=alert(1)>\nFrom: a@b.test\n\nbody`));
  assert.ok(!container.innerHTML.includes("<img src=x"), "raw markup must not reach the page");
});

console.log(`\n${passed} passed, ${failures.length} failed`);
for (const f of failures) console.error(`  FAIL  ${f.name}\n        ${f.message}`);
process.exit(failures.length ? 1 : 0);
