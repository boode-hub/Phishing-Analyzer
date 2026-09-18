// Local server behaviour, exercised against a real instance.
//
// Every case here is something a web page the analyst merely visits could send
// to http://127.0.0.1:<port>, so each one was a real exposure: a null byte in
// the path used to kill the process outright.
// Run: node tests/server.test.mjs

import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";

const serverPath = fileURLToPath(new URL("../server.js", import.meta.url));

// Windows reserves whole dynamic port ranges (Hyper-V, WinNAT), so a fixed port
// fails with EACCES on some machines. Try a few until one binds.
async function startServer(ports) {
  for (const port of ports) {
    const child = spawn(process.execPath, [serverPath], {
      env: { ...process.env, PORT: String(port) },
      stdio: ["ignore", "pipe", "pipe"],
    });
    const ok = await new Promise((resolve) => {
      const timer = setTimeout(() => resolve(false), 10000);
      child.stdout.on("data", (chunk) => {
        if (String(chunk).includes("Server running")) {
          clearTimeout(timer);
          resolve(true);
        }
      });
      child.on("exit", () => {
        clearTimeout(timer);
        resolve(false);
      });
    });
    if (ok) return { child, port };
    child.kill();
  }
  throw new Error("no free port for the test server");
}

const { child: server, port: PORT } = await startServer([3457, 3458, 4173, 5183, 7321]);
const BASE = `http://127.0.0.1:${PORT}`;
const ready = Promise.resolve();

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

const get = (path, init) => fetch(BASE + path, init);

try {
  await ready;

  await test("the app is served", async () => {
    const res = await get("/");
    assert.equal(res.status, 200);
    assert.match(await res.text(), /Phishing Email Analyzer/);
  });

  await test("a null byte in the path is refused, and the server survives it", async () => {
    // fs.readFile throws on a null byte; uncaught, that killed the process.
    assert.equal((await get("/index.html%00.png")).status, 400);
    assert.equal((await get("/")).status, 200, "server died");
  });

  await test("control characters are refused", async () => {
    assert.equal((await get("/index%0a.html")).status, 400);
  });

  await test("path traversal cannot escape the project directory", async () => {
    for (const path of ["/../../../etc/passwd", "/%2e%2e%2f%2e%2e%2fserver.js", "/..%5c..%5cserver.js"]) {
      const res = await get(path);
      assert.ok([403, 404].includes(res.status), `${path} -> ${res.status}`);
    }
  });

  await test("dot-directories such as .git are never served", async () => {
    assert.equal((await get("/.git/config")).status, 403);
    assert.equal((await get("/.env")).status, 403);
  });

  await test("only known file types are served", async () => {
    assert.equal((await get("/notes.log")).status, 403);
    assert.equal((await get("/scripts/main.js")).status, 200);
  });

  await test("responses carry the basic protective headers", async () => {
    const res = await get("/");
    assert.equal(res.headers.get("x-content-type-options"), "nosniff");
    assert.equal(res.headers.get("x-frame-options"), "DENY");
    assert.equal(res.headers.get("referrer-policy"), "no-referrer");
  });

  await test("local lookups accept only a bare domain or IP", async () => {
    for (const q of ["example.com; whoami", "http://example.com/", "|cat /etc/passwd", "a".repeat(300) + ".com"]) {
      const res = await get(`/lookup/dns?q=${encodeURIComponent(q)}`);
      assert.equal(res.status, 400, q);
    }
  });

  await test("another origin cannot use the relay or the local lookups", async () => {
    for (const path of ["/lookup/dns?q=example.com", "/lookup/whois?q=example.com", "/proxy/abuseipdb/check?ipAddress=1.1.1.1"]) {
      const res = await get(path, { headers: { Origin: "https://evil.test" } });
      assert.equal(res.status, 403, path);
    }
  });

  await test("no endpoint hands out CORS permission", async () => {
    const res = await get("/lookup/dns?q=example.com");
    assert.equal(res.headers.get("access-control-allow-origin"), null);
    const options = await get("/proxy/vt/api/v3/ip_addresses/1.1.1.1", { method: "OPTIONS" });
    assert.equal(options.headers.get("access-control-allow-origin"), null);
  });

  await test("the relay only ever talks to its two vendors", async () => {
    // The target host is fixed in code; the path cannot move it elsewhere.
    const res = await get("/proxy/vt/../../../evil.test/");
    assert.ok([403, 404].includes(res.status), `-> ${res.status}`);
    assert.equal((await get("/")).status, 200, "server died");
  });
} finally {
  server.kill();
}

console.log(`\n${passed} passed, ${failures.length} failed`);
for (const f of failures) console.error(`  FAIL  ${f.name}\n        ${f.message}`);
process.exit(failures.length ? 1 : 0);
