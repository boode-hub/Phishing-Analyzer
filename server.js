// Simple HTTP server for Phishing Email Analyzer
// Run: node server.js
// Then open: http://localhost:8080
//
// This server also acts as a proxy for VirusTotal and AbuseIPDB APIs
// to bypass CORS restrictions when running locally.

const http = require("http");
const { validTarget, dnsRecords, reverseDns, whoisLookup } = require("./lookup-local");
const fs = require("fs");
const path = require("path");
const https = require("https");

// Overridable because Windows reserves dynamic port ranges (Hyper-V, WinNAT)
// that can include 8080, making it unbindable with EACCES. PORT=3000 node server.js
const PORT = Number(process.env.PORT) || 8080;

const MIME_TYPES = {
  ".html": "text/html",
  ".js": "text/javascript",
  ".css": "text/css",
  ".json": "application/json",
  ".eml": "message/rfc822",
  ".txt": "text/plain",
  ".svg": "image/svg+xml",
  ".png": "image/png",
  ".woff2": "font/woff2",
  ".ico": "image/x-icon",
};

// Proxy a request to an external API and return the response
function proxyRequest(targetUrl, options, res) {
  // WHATWG URL rather than the deprecated url.parse(), which Node flags as
  // having security implications.
  const parsed = new URL(targetUrl);
  const requestOptions = {
    hostname: parsed.hostname,
    port: parsed.port || 443,
    path: parsed.pathname + parsed.search,
    method: options.method || "GET",
    headers: options.headers || {},
  };

  const proxyReq = https.request(requestOptions, (proxyRes) => {
    // Copy status code
    res.writeHead(proxyRes.statusCode, {
      "Content-Type": proxyRes.headers["content-type"] || "application/json",
    });
    proxyRes.pipe(res);
  });

  proxyReq.on("error", (err) => {
    console.error("[Proxy Error]", err.message);
    res.writeHead(502, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ error: "Proxy error: " + err.message }));
  });

  if (options.body) {
    proxyReq.write(options.body);
  }

  proxyReq.end();
}

// Only these extensions are served. Anything else — .git, source control
// metadata, editor backups, a stray .env — is refused rather than published on
// a port every page in the browser can reach.
const SERVABLE = new Set(Object.keys(MIME_TYPES));

const server = http.createServer((req, res) => {
  try {
    handleRequest(req, res);
  } catch (err) {
    // A single bad request must never take the tool down.
    console.error("[Request error]", err.message);
    if (!res.headersSent) res.writeHead(500, { "Content-Type": "text/plain" });
    res.end("Server error");
  }
});

// The page is served from this same origin, so a request carrying any other
// Origin is not the app.
const LOCAL_ORIGIN = /^https?:\/\/(localhost|127\.0\.0\.1|\[::1\])(:\d+)?$/i;

function sameOrigin(req) {
  const origin = req.headers.origin;
  return !origin || LOCAL_ORIGIN.test(origin);
}

function handleRequest(req, res) {
  // Only the app may use the relay and the local lookups.
  if (!sameOrigin(req) && /^\/(proxy|lookup)\//.test(req.url)) {
    res.writeHead(403, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ error: "This endpoint serves the local app only." }));
    return;
  }

  // CORS preflight
  if (req.method === "OPTIONS") {
    // Same-origin requests need no preflight; answering one at all would only
    // help a cross-origin caller.
    res.writeHead(204, { Allow: "GET, POST" });
    res.end();
    return;
  }

  // ===== LOCAL LOOKUPS: DNS and WHOIS/RDAP =====
  //
  // Done by this machine with this machine's resolver, so no third-party API
  // and no key is involved. The target is validated as a bare domain or IP
  // before it reaches a resolver or a WHOIS server.
  if (req.url.startsWith("/lookup/dns") || req.url.startsWith("/lookup/whois")) {
    const query = new URL(req.url, "http://localhost").searchParams;
    const target = validTarget(query.get("q"));
    const json = (status, body) => {
      res.writeHead(status, { "Content-Type": "application/json" });
      res.end(JSON.stringify(body));
    };
    if (!target) {
      json(400, { error: "Ask for a single domain name or IP address." });
      return;
    }
    const wantsDns = req.url.startsWith("/lookup/dns");
    console.log("[Local]", wantsDns ? "DNS" : "WHOIS", "->", target.value);
    const work = wantsDns
      ? target.kind === "ip"
        ? reverseDns(target.value)
        : dnsRecords(target.value)
      : whoisLookup(target.kind, target.value);
    work.then(
      (data) => json(200, data),
      (err) => json(502, { error: String(err.message || err) }),
    );
    return;
  }

  // ===== PROXY: VirusTotal =====
  if (req.url.startsWith("/proxy/vt/")) {
    const vtPath = req.url.replace("/proxy/vt", "");
    const vtUrl = `https://www.virustotal.com${vtPath}`;

    const headers = {
      Accept: "application/json",
    };

    // Forward the API key from the client
    const apiKey = req.headers["x-apikey"];
    if (apiKey) {
      headers["x-apikey"] = apiKey;
    }

    console.log("[Proxy] VT ->", vtUrl);
    proxyRequest(vtUrl, { method: "GET", headers }, res);
    return;
  }

  // ===== PROXY: VirusTotal URL Submit =====
  if (req.url === "/proxy/vt-submit" && req.method === "POST") {
    let body = "";
    req.on("data", (chunk) => (body += chunk));
    req.on("end", () => {
      const headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        Accept: "application/json",
      };
      const apiKey = req.headers["x-apikey"];
      if (apiKey) {
        headers["x-apikey"] = apiKey;
      }

      console.log("[Proxy] VT Submit -> URL submission");
      proxyRequest(
        "https://www.virustotal.com/api/v3/urls",
        { method: "POST", headers, body },
        res,
      );
    });
    return;
  }

  // ===== PROXY: VirusTotal Analyse (Rescan) =====
  // Spelled "analyse": VirusTotal API v3 uses the British spelling.
  if (req.url.startsWith("/proxy/vt-analyse/") && req.method === "POST") {
    const vtPath = req.url.replace("/proxy/vt-analyse", "");
    const vtUrl = `https://www.virustotal.com${vtPath}`;

    let body = "";
    req.on("data", (chunk) => (body += chunk));
    req.on("end", () => {
      const headers = {
        Accept: "application/json",
      };
      const apiKey = req.headers["x-apikey"];
      if (apiKey) {
        headers["x-apikey"] = apiKey;
      }

      // Only set Content-Type if there's a body
      if (body) {
        headers["Content-Type"] = "application/x-www-form-urlencoded";
      }

      console.log("[Proxy] VT Analyse ->", vtUrl);
      proxyRequest(vtUrl, { method: "POST", headers, body: body || undefined }, res);
    });
    return;
  }

  // ===== PROXY: AbuseIPDB =====
  if (req.url.startsWith("/proxy/abuseipdb")) {
    const query = req.url.replace("/proxy/abuseipdb", "");
    const abuseUrl = `https://api.abuseipdb.com/api/v2${query}`;

    const headers = {
      Accept: "application/json",
    };

    // Forward the API key from the client
    const apiKey = req.headers["key"];
    if (apiKey) {
      headers["Key"] = apiKey;
    }

    console.log("[Proxy] AbuseIPDB ->", abuseUrl);
    proxyRequest(abuseUrl, { method: "GET", headers }, res);
    return;
  }

  // ===== STATIC FILES =====
  // Resolve inside the project directory and refuse anything that escapes it.
  // "." + req.url served any file on disk to "GET /../../etc/passwd", and the
  // query string was left on the path so "/index.html?v=2" was a 404.
  const ROOT = __dirname;
  let requestPath;
  try {
    requestPath = decodeURIComponent(req.url.split("?")[0].split("#")[0]);
  } catch {
    res.writeHead(400, { "Content-Type": "text/html" });
    res.end("<h1>400 Bad Request</h1>", "utf-8");
    return;
  }

  // A null byte truncates the name inside the filesystem layer, and fs throws
  // on it. Control characters have no business in a path either.
  if (/[\u0000-\u001f]/.test(requestPath)) {
    res.writeHead(400, { "Content-Type": "text/html" });
    res.end("<h1>400 Bad Request</h1>", "utf-8");
    return;
  }

  // Nothing hidden: no .git, no dot-files, at any depth.
  if (requestPath.split(/[\\/]/).some((part) => part.startsWith("."))) {
    res.writeHead(403, { "Content-Type": "text/html" });
    res.end("<h1>403 Forbidden</h1>", "utf-8");
    return;
  }
  const filePath = path.join(
    ROOT,
    requestPath === "/" ? "index.html" : requestPath,
  );

  if (filePath !== ROOT && !filePath.startsWith(ROOT + path.sep)) {
    res.writeHead(403, { "Content-Type": "text/html" });
    res.end("<h1>403 Forbidden</h1>", "utf-8");
    return;
  }

  const extname = String(path.extname(filePath)).toLowerCase();
  if (!SERVABLE.has(extname)) {
    res.writeHead(403, { "Content-Type": "text/html" });
    res.end("<h1>403 Forbidden</h1>", "utf-8");
    return;
  }
  const contentType = MIME_TYPES[extname];

  fs.readFile(filePath, (error, content) => {
    if (error) {
      if (error.code === "ENOENT" || error.code === "EISDIR") {
        res.writeHead(404, { "Content-Type": "text/html" });
        res.end("<h1>404 Not Found</h1>", "utf-8");
      } else {
        res.writeHead(500);
        res.end("Server Error: " + error.code + " ..\n");
      }
    } else {
      res.writeHead(200, {
        "Content-Type": contentType,
        // The app is never meant to be framed, and nothing here should be
        // sniffed into a different type than it declares.
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "Referrer-Policy": "no-referrer",
      });
      res.end(content, "utf-8");
    }
  });
}

server.on("error", (err) => {
  if (err.code === "EACCES" || err.code === "EADDRINUSE") {
    console.error(
      `Port ${PORT} is unavailable (${err.code}). Pick another, e.g.:\n  PORT=3000 node server.js`,
    );
    process.exit(1);
  }
  throw err;
});

// Loopback only. Binding every interface published the analyzer — and its API
// relay — to everyone on the same network.
server.listen(PORT, "127.0.0.1", () => {
  console.log(`Server running at http://localhost:${PORT}/`);
  console.log("Press Ctrl+C to stop");
});
