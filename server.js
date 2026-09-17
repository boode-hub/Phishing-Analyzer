// Simple HTTP server for Phishing Email Analyzer
// Run: node server.js
// Then open: http://localhost:8080
//
// This server also acts as a proxy for VirusTotal and AbuseIPDB APIs
// to bypass CORS restrictions when running locally.

const http = require("http");
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
      "Access-Control-Allow-Origin": "*",
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

const server = http.createServer((req, res) => {
  // CORS preflight
  if (req.method === "OPTIONS") {
    res.writeHead(204, {
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type, x-apikey, Key",
    });
    res.end();
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
  const contentType = MIME_TYPES[extname] || "application/octet-stream";

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
      res.writeHead(200, { "Content-Type": contentType });
      res.end(content, "utf-8");
    }
  });
});

server.on("error", (err) => {
  if (err.code === "EACCES" || err.code === "EADDRINUSE") {
    console.error(
      `Port ${PORT} is unavailable (${err.code}). Pick another, e.g.:\n  PORT=3000 node server.js`,
    );
    process.exit(1);
  }
  throw err;
});

server.listen(PORT, () => {
  console.log(`Server running at http://localhost:${PORT}/`);
  console.log("Press Ctrl+C to stop");
});
