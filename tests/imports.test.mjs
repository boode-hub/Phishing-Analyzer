// Static check: a module that calls another module's exported function must
// import it (or define its own). A missing import only fails at click time —
// main.js once called sha256() without importing it, so every VirusTotal URL
// lookup threw "sha256 is not defined".
// Run: node tests/imports.test.mjs

import { readFileSync, readdirSync } from "node:fs";

const dir = new URL("../scripts/", import.meta.url);
const files = readdirSync(dir).filter((f) => f.endsWith(".js"));
const src = Object.fromEntries(files.map((f) => [f, readFileSync(new URL(f, dir), "utf8")]));

const exported = new Map(); // name -> file
for (const [f, s] of Object.entries(src)) {
  for (const m of s.matchAll(/export\s+(?:async\s+)?(?:function|const|let)\s+([A-Za-z_$][\w$]*)/g)) exported.set(m[1], f);
}

const failures = [];
for (const [f, s] of Object.entries(src)) {
  const code = s.replace(/\/\/[^\n]*|\/\*[\s\S]*?\*\//g, "");
  const imported = new Set(
    [...code.matchAll(/import\s*\{([^}]*)\}/g)].flatMap((m) => m[1].split(",").map((x) => x.trim().split(/\s+as\s+/).pop())),
  );
  for (const [name, owner] of exported) {
    if (owner === f || imported.has(name)) continue;
    const called = new RegExp("(?<![\\w$.])" + name + "\\s*\\(").test(code);
    const defined = new RegExp("(?:function|const|let|var)\\s+" + name + "\\b").test(code);
    if (called && !defined) failures.push(`${f} calls ${name}() from ${owner} without importing it`);
  }
}

console.log(`\n${files.length} modules checked, ${failures.length} failed`);
for (const x of failures) console.error(`  FAIL  ${x}`);
process.exit(failures.length ? 1 : 0);
