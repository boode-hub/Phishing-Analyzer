// Cloudflare Worker - CORS Proxy for Phishing Email Analyzer
// Deploy this to Cloudflare Workers (free tier) to enable API calls from GitHub Pages
//
// Setup:
// 1. Go to https://workers.cloudflare.com/ and create a free account
// 2. Create a new Worker
// 3. Paste this code
// 4. Save and deploy
// 5. Copy the worker URL (e.g., https://your-worker.your-subdomain.workers.dev)
// 6. In the Phishing Analyzer app settings, paste the worker URL in the "CORS Proxy URL" field
//
// This worker forwards all headers (including API keys) to the target API,
// but ONLY to the two reputation services below. Without that allow-list it is
// an open proxy: anyone who learns the worker URL can route arbitrary traffic
// through your Cloudflare account, with their own headers attached.

// Only these hosts may be reached through the worker.
const ALLOWED_HOSTS = new Set([
  "www.virustotal.com",
  "virustotal.com",
  "api.abuseipdb.com",
]);

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    // CORS headers
    const corsHeaders = {
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type, x-apikey, Key, Accept",
    };

    // Handle preflight
    if (request.method === "OPTIONS") {
      return new Response(null, { headers: corsHeaders });
    }

    // Get target URL from query parameter
    const targetUrl = url.searchParams.get("url");
    if (!targetUrl) {
      return new Response(
        JSON.stringify({ error: "Missing 'url' query parameter" }),
        {
          status: 400,
          headers: { ...corsHeaders, "Content-Type": "application/json" },
        },
      );
    }

    // Refuse anything that is not one of the two reputation APIs.
    let target;
    try {
      target = new URL(targetUrl);
    } catch {
      return new Response(JSON.stringify({ error: "Malformed 'url' parameter" }), {
        status: 400,
        headers: { ...corsHeaders, "Content-Type": "application/json" },
      });
    }
    if (target.protocol !== "https:" || !ALLOWED_HOSTS.has(target.hostname)) {
      return new Response(
        JSON.stringify({
          error: "This relay only forwards to VirusTotal and AbuseIPDB over HTTPS",
        }),
        { status: 403, headers: { ...corsHeaders, "Content-Type": "application/json" } },
      );
    }

    // Build headers to forward
    const forwardHeaders = new Headers();
    for (const [key, value] of request.headers) {
      // Skip host and origin headers
      if (key.toLowerCase() !== "host" && key.toLowerCase() !== "origin") {
        forwardHeaders.set(key, value);
      }
    }

    // Create request to target
    const targetRequest = new Request(targetUrl, {
      method: request.method,
      headers: forwardHeaders,
      body:
        request.method !== "GET" && request.method !== "HEAD"
          ? request.body
          : null,
    });

    try {
      const response = await fetch(targetRequest);

      // Build response with CORS headers
      const responseHeaders = new Headers(response.headers);
      for (const [key, value] of Object.entries(corsHeaders)) {
        responseHeaders.set(key, value);
      }

      return new Response(response.body, {
        status: response.status,
        statusText: response.statusText,
        headers: responseHeaders,
      });
    } catch (error) {
      return new Response(
        JSON.stringify({ error: "Proxy error: " + error.message }),
        {
          status: 502,
          headers: { ...corsHeaders, "Content-Type": "application/json" },
        },
      );
    }
  },
};
