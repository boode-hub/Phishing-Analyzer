// URL decoder tests.
// Run: node tests/url-decode.test.mjs
//
// Expected values come from independent sources — node:url for punycode,
// Buffer for base64, and Proofpoint's published decoder examples — not from
// this module's own output.

import assert from "node:assert/strict";
import { domainToUnicode } from "node:url";
import {
  percentDecode,
  unwrapRedirect,
  base64Decode,
  hexDecode,
  htmlEntityDecode,
  escapeDecode,
  punycodeDecode,
  decodeAll,
  detectEncodings,
  URL_DECODERS,
} from "../scripts/url-decode.js";

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

// --- percent ---------------------------------------------------------------

test("single-layer percent decoding", () => {
  const r = percentDecode("https://evil.test/login%3Fnext%3D%2Fhome");
  assert.equal(r.output, "https://evil.test/login?next=/home");
  assert.equal(r.note, null);
});

test("multi-layer percent encoding is fully unwound and flagged", () => {
  const once = encodeURIComponent("https://evil.test/a b");
  const thrice = encodeURIComponent(encodeURIComponent(once));
  const r = percentDecode(thrice);
  assert.equal(r.output, "https://evil.test/a b");
  assert.match(r.note, /3 layers/);
});

test("malformed percent sequences do not throw", () => {
  const r = percentDecode("https://x.test/%E0%A4%A%41");
  assert.ok(r, "should still decode what it can");
});

test("a plain URL has nothing to percent-decode", () => {
  assert.equal(percentDecode("https://example.com/path"), null);
});

// --- unwrapping ------------------------------------------------------------

test("Microsoft Safe Links", () => {
  const r = unwrapRedirect(
    "https://nam02.safelinks.protection.outlook.com/?url=https%3A%2F%2Fevil.test%2Flogin%3Fid%3D7&data=05%7C01&sdata=abc&reserved=0",
  );
  assert.equal(r.output, "https://evil.test/login?id=7");
  assert.match(r.note, /Safe Links/);
});

test("Proofpoint v2 (published example)", () => {
  const r = unwrapRedirect(
    "https://urldefense.proofpoint.com/v2/url?u=https-3A__media.mnn.com_assets_images_2016_06_jupiter-2Dnasa.jpg.638x0-5Fq80-5Fcrop-2Dsmart.jpg&d=DwMBaQ&c=0&r=0&m=0&s=0&e=",
  );
  assert.equal(
    r.output,
    "https://media.mnn.com/assets/images/2016/06/jupiter-nasa.jpg.638x0_q80_crop-smart.jpg",
  );
});

test("Proofpoint v3 restores the characters it replaced with *", () => {
  const r = unwrapRedirect(
    "https://urldefense.com/v3/__https://google.com:443/search?q=a*test&gs=ps__;Kw!-612Flbf0JlQ3kNuA_7IaTXrqc2h9i8eLAx8aW-eKOzDq-xQo7cN9dbhk2yF8BI4a$",
  );
  assert.equal(r.output, "https://google.com:443/search?q=a+test&gs=ps");
  assert.match(r.note, /Proofpoint URL Defense v3/);
});

test("Proofpoint v3 run-length markers (**X) expand to multiple characters", () => {
  // "**A" = a run of 2. Both removed characters are "+" — base64url of "++" is "Kys".
  const r = unwrapRedirect("https://urldefense.com/v3/__https://x.test/a**Ab__;Kys!abc$");
  assert.equal(r.output, "https://x.test/a++b");
});

test("Google redirect", () => {
  const r = unwrapRedirect("https://www.google.com/url?q=https://evil.test/x&sa=D");
  assert.equal(r.output, "https://evil.test/x");
});

test("nested wrappers are unwrapped all the way down", () => {
  const inner = "https://www.google.com/url?q=" + encodeURIComponent("https://evil.test/final");
  const outer =
    "https://eur01.safelinks.protection.outlook.com/?url=" + encodeURIComponent(inner) + "&data=x";
  const r = unwrapRedirect(outer);
  assert.equal(r.output, "https://evil.test/final");
  assert.match(r.note, /Safe Links → Google redirect/);
});

test("generic open-redirect parameters are followed", () => {
  const r = unwrapRedirect("https://tracker.test/click?id=5&redirect=https%3A%2F%2Fevil.test%2Fpay");
  assert.equal(r.output, "https://evil.test/pay");
  assert.match(r.note, /redirect/);
});

test("Mimecast says honestly that the destination cannot be recovered", () => {
  const r = unwrapRedirect("https://protect-eu.mimecast.com/s/AbCdEfGhIjK?domain=evil.test");
  assert.ok(r);
  assert.match(r.note, /cannot be recovered/);
});

test("an ordinary URL is not treated as a wrapper", () => {
  assert.equal(unwrapRedirect("https://example.com/about?page=2"), null);
});

// --- base64 / hex ----------------------------------------------------------

test("base64 victim email in the fragment is found", () => {
  const token = Buffer.from("victim@company.com").toString("base64").replace(/=+$/, "");
  const r = base64Decode(`https://evil.test/login#${token}`);
  assert.ok(r, "should find the token");
  assert.match(r.output, /victim@company\.com/);
  assert.match(r.note, /email address/);
});

test("base64 hidden behind percent-encoding is still found", () => {
  const token = Buffer.from("victim@company.com").toString("base64").replace(/=+$/, "");
  const wrapped =
    "https://nam02.safelinks.protection.outlook.com/?url=" +
    encodeURIComponent(`https://evil.test/login#${token}`);
  const r = base64Decode(wrapped);
  assert.ok(r, "the token sits behind %23 and inside url=");
  assert.match(r.output, /victim@company\.com/);
  assert.ok(detectEncodings(wrapped).includes("base64"), "so the button is highlighted");
});

test("base64url (with - and _) decodes", () => {
  const token = Buffer.from("https://evil.test/?x=ÿÿ>").toString("base64url");
  const r = base64Decode(`https://redir.test/go/${token}`);
  assert.match(r.output, /https:\/\/evil\.test/);
});

test("ordinary path words are not reported as base64", () => {
  assert.equal(base64Decode("https://example.com/products/category/shoes"), null);
  assert.equal(
    base64Decode("https://example.com/a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6"),
    null,
    "a hex tracking id is not base64 text",
  );
});

test("hex-encoded text is found; a hash is not", () => {
  const hex = Buffer.from("admin@bank.test").toString("hex");
  assert.match(hexDecode(`https://x.test/?e=${hex}`).output, /admin@bank\.test/);
  assert.equal(hexDecode("https://x.test/f/" + "a".repeat(64)), null);
});

// --- entities / escapes ----------------------------------------------------

test("HTML entities", () => {
  const r = htmlEntityDecode("https://evil.test/a?x=1&amp;y=2&#x2F;z&#47;");
  assert.equal(r.output, "https://evil.test/a?x=1&y=2/z/");
});

test("JavaScript escapes", () => {
  const r = escapeDecode("https:\\x2f\\x2fevil\\u002etest");
  assert.equal(r.output, "https://evil.test");
});

// --- punycode --------------------------------------------------------------

test("punycode matches node's domainToUnicode", () => {
  for (const host of ["xn--pypal-4ve.com", "xn--80ak6aa92e.com", "xn--mnchen-3ya.de", "xn--bcher-kva.example"]) {
    const r = punycodeDecode(`https://${host}/login`);
    assert.ok(r, `should decode ${host}`);
    assert.equal(r.output, `https://${domainToUnicode(host)}/login`, host);
  }
});

test("punycode note names the lookalike characters", () => {
  const r = punycodeDecode("https://xn--pypal-4ve.com/");
  assert.match(r.note, /U\+0430/, "Cyrillic small a");
});

test("an ASCII host has no punycode", () => {
  assert.equal(punycodeDecode("https://paypal.com/"), null);
});

// --- all / detection -------------------------------------------------------

test("decode all unwraps, decodes, and surfaces a hidden email", () => {
  const victim = Buffer.from("ceo@target.test").toString("base64").replace(/=+$/, "");
  const url =
    "https://nam02.safelinks.protection.outlook.com/?url=" +
    encodeURIComponent(`https://xn--pypal-4ve.com/verify#${victim}`) +
    "&data=x";
  const r = decodeAll(url);
  assert.match(r.output, /^https:\/\/xn--pypal-4ve\.com\/verify#/);
  assert.match(r.output, /ceo@target\.test/);
  assert.match(r.output, /U\+0430/);
  assert.match(r.note, /Safe Links/);
});

test("detectEncodings lists only decoders that apply", () => {
  assert.deepEqual(detectEncodings("https://example.com/"), []);
  const found = detectEncodings(
    "https://nam02.safelinks.protection.outlook.com/?url=https%3A%2F%2Fevil.test",
  );
  assert.ok(found.includes("unwrap"));
  assert.ok(found.includes("percent"));
});

test("no decoder throws on hostile input", () => {
  const nasty = [
    "",
    "not a url",
    "https://",
    "https://x.test/%",
    "https://urldefense.com/v3/__broken",
    "https://xn--.com/",
    "https://xn--zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz.com/",
    "javascript:alert(1)",
    "%".repeat(500),
  ];
  for (const input of nasty) {
    for (const d of URL_DECODERS) {
      assert.doesNotThrow(() => d.run(input), `${d.id} threw on ${JSON.stringify(input)}`);
    }
  }
});

console.log(`\n${passed} passed, ${failures.length} failed`);
for (const f of failures) console.error(`  FAIL  ${f.name}\n        ${f.message}`);
process.exit(failures.length ? 1 : 0);
