// Theme accent tests.
// Run: node tests/theme.test.mjs

import assert from "node:assert/strict";
import { accentPalette, applyAccent, normalizeHex, DEFAULT_ACCENT } from "../scripts/theme.js";

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

// Minimal stand-in for documentElement.style.
function fakeRoot() {
  const props = new Map();
  return { props, style: { setProperty: (k, v) => props.set(k, v), removeProperty: (k) => props.delete(k) } };
}

test("hex input is validated and normalised", () => {
  assert.equal(normalizeHex("#FF0000"), "#ff0000");
  assert.equal(normalizeHex("00aaff"), "#00aaff");
  for (const bad of ["", "#fff", "red", "#12345g", null, "javascript:alert(1)"]) assert.equal(normalizeHex(bad), null);
});

test("palette derives every accent token from one colour", () => {
  const p = accentPalette("#3366ff");
  assert.equal(p["--accent"], "#3366ff");
  assert.equal(p["--green"], "#3366ff");
  assert.equal(p["--accent-bg"], "rgba(51, 102, 255, 0.08)");
  assert.equal(p["--accent-contrast"], "#ffffff");
  assert.equal(accentPalette("#ffee00")["--accent-contrast"], "#0d1117");
  // Only accent/green tokens — base colours are never touched.
  assert.ok(Object.keys(p).every((k) => /^--(accent|green|border-hover)/.test(k)), Object.keys(p).join());
});

test("a custom colour is applied, reset clears back to the stylesheet", () => {
  const root = fakeRoot();
  assert.equal(applyAccent("#ff00aa", root), "#ff00aa");
  assert.equal(root.props.get("--accent"), "#ff00aa");
  assert.equal(applyAccent(DEFAULT_ACCENT, root), DEFAULT_ACCENT);
  assert.equal(root.props.size, 0);
  applyAccent("#ff00aa", root);
  applyAccent("garbage", root);
  assert.equal(root.props.size, 0, "invalid input falls back to defaults");
});

console.log(`\n${passed} passed, ${failures.length} failed`);
for (const f of failures) console.error(`  FAIL  ${f.name}\n        ${f.message}`);
process.exit(failures.length ? 1 : 0);
