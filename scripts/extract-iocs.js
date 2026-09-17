// IOC Extraction Module
// Extract URLs, domains, IPs, emails, and attachments
// with risk flagging

import {
  isValidIP,
  isValidIPv4,
  isPrivateIP,
  findIPs,
  receivedFromIP,
} from "./ip-utils.js";
import { unwrapRedirect } from "./url-decode.js";

// Known URL shorteners
const URL_SHORTENERS = [
  "bit.ly",
  "tinyurl.com",
  "t.co",
  "goo.gl",
  "ow.ly",
  "is.gd",
  "buff.ly",
  "adf.ly",
  "j.mp",
  "tr.im",
  "tiny.cc",
  "lnkd.in",
  "db.tt",
  "qr.ae",
  "cur.lv",
  "ity.im",
  "q.gs",
  "po.st",
  "su.pr",
  "fire.to",
  "bit.do",
  "mcaf.ee",
  "link.tl",
  "go.usa.gov",
  "go2.me",
  "shorl.com",
];

// Risky file extensions
const RISKY_EXTENSIONS = [
  ".exe",
  ".scr",
  ".js",
  ".hta",
  ".vbs",
  ".bat",
  ".cmd",
  ".pif",
  ".msi",
  ".com",
  ".dll",
  ".ps1",
  ".sh",
  ".bash",
  ".jar",
  ".app",
  ".dmg",
];

// Double extension patterns
const DOUBLE_EXT_PATTERNS = [
  /\.pdf\.exe/i,
  /\.doc\.exe/i,
  /\.xls\.exe/i,
  /\.zip\.exe/i,
  /\.pdf\.scr/i,
  /\.doc\.scr/i,
  /\.xls\.scr/i,
  /\.jpg\.exe/i,
  /\.png\.exe/i,
  /\.gif\.exe/i,
  /\.txt\.exe/i,
];

// Punycode pattern
const PUNYCODE_PATTERN = /xn--/i;

/**
 * Extract IOCs from headers and body
 * @param {Object} headers - Parsed headers
 * @param {Object} body - Parsed body (may be null)
 * @returns {Object} Extracted IOCs
 */
export function extractIOCs(headers, body) {
  const iocs = {
    urls: [],
    domains: [],
    ips: [],
    emails: [],
    attachments: [],
    mismatchedLinks: [],
  };

  // Extract from headers
  extractFromHeaders(headers, iocs);

  // Extract from body
  if (body) {
    extractFromBody(body, iocs);
  }

  addUnwrappedDestinations(iocs);
  collectDomains(iocs, headers);

  // Deduplicate and flag
  deduplicateAndFlag(iocs);

  return iocs;
}

/**
 * Extract IOCs from headers
 */
function extractFromHeaders(headers, iocs) {
  // Extract emails from From, Reply-To, To
  if (headers.from && headers.from.email) {
    iocs.emails.push({ value: headers.from.email, source: "From" });
  }
  if (headers.replyTo && headers.replyTo.email) {
    iocs.emails.push({ value: headers.replyTo.email, source: "Reply-To" });
  }
  if (headers.returnPath && headers.returnPath.email) {
    iocs.emails.push({
      value: headers.returnPath.email,
      source: "Return-Path",
    });
  }

  // Extract from headers - collect all IPs with sources before dedup
  // X-Originating-IP is checked first so we can flag it properly
  const ipSourceMap = new Map(); // ip -> Set of sources

  function trackIp(value, source) {
    if (!ipSourceMap.has(value)) {
      ipSourceMap.set(value, new Set());
    }
    ipSourceMap.get(value).add(source);
  }

  // Extract from X-Originating-IP. findIPs validates each candidate, so a
  // dotted-quad lookalike never becomes an IOC.
  if (headers.xOriginatingIp) {
    for (const ip of findIPs(headers.xOriginatingIp)) {
      trackIp(ip, "X-Originating-IP");
    }
  }

  // Extract the sending host's IP from each Received header.
  for (const received of headers.received || []) {
    const ip = receivedFromIP(received);
    if (ip) trackIp(ip, "Received");
  }

  // Now push unique IPs with combined source info
  for (const [ip, sources] of ipSourceMap) {
    const primarySource = sources.has("X-Originating-IP")
      ? "X-Originating-IP"
      : "Received";
    iocs.ips.push({ value: ip, source: primarySource, allSources: [...sources] });
  }

  // Extract Message-ID domain
  if (headers.messageId) {
    const domainMatch = headers.messageId.match(/@([^>]+)/);
    if (domainMatch) {
      iocs.domains.push({
        value: domainMatch[1].toLowerCase(),
        source: "Message-ID",
      });
    }
  }
}

/**
 * Extract IOCs from body
 */
function extractFromBody(body, iocs) {
  const text = body.text || body.raw || "";

  // Extract URLs
  const urlPattern = /https?:\/\/[^\s<>"')\]]+/gi;
  let match;
  while ((match = urlPattern.exec(text)) !== null) {
    iocs.urls.push({ value: match[0], source: "Body" });
  }

  // Also check HTML links
  if (body.links) {
    for (const link of body.links) {
      const existing = iocs.urls.find((u) => u.value === link.href);
      if (existing) {
        // The same URL can appear as plain text and as an anchor; keep the
        // mismatch finding from whichever occurrence has one. For an HTML-only
        // message the text scan runs over raw markup and reaches a pixel's URL
        // first, so the more specific resource label wins.
        existing.isMismatch = existing.isMismatch || link.isMismatch;
        if (link.resource) existing.source = "Remote resource (loads on open)";
      } else {
        iocs.urls.push({
          value: link.href,
          source: link.resource ? "Remote resource (loads on open)" : "Body",
          text: link.text,
          isMismatch: link.isMismatch,
        });
      }

      // Collect mismatched links separately
      if (link.isMismatch) {
        iocs.mismatchedLinks.push({
          text: link.text,
          href: link.href,
        });
      }
    }
  }

  // Extract email addresses
  const emailPattern = /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g;
  while ((match = emailPattern.exec(text)) !== null) {
    iocs.emails.push({ value: match[0].toLowerCase(), source: "Body" });
  }

  // Extract IPs from body
  for (const ip of findIPs(text)) {
    iocs.ips.push({ value: ip, source: "Body" });
  }

  // Extract attachments
  if (body.attachments) {
    for (const att of body.attachments) {
      iocs.attachments.push({
        value: att.filename,
        contentType: att.contentType,
        size: att.size,
        source: att.inline ? "Inline" : "Attachment",
        inline: att.inline,
        contentId: att.contentId,
        // Raw bytes, so the hash is computed over the real file rather than a
        // lossy string round-trip. Hashes are filled in by main.js.
        bytes: att.bytes,
      });
    }
  }
}


/**
 * A link rewritten by Safe Links or Proofpoint shows only the gateway's host,
 * so every risk check ran against the gateway and the real destination — the
 * punycode lookalike, the raw IP — was never examined. Add the unwrapped
 * destination as an IOC of its own so it is flagged, scored, and looked up.
 */
function addUnwrappedDestinations(iocs) {
  for (const url of [...iocs.urls]) {
    const r = unwrapRedirect(url.value);
    if (!r || r.output === url.value || !/^https?:\/\//i.test(r.output)) continue;
    if (iocs.urls.some((u) => u.value === r.output)) continue;
    iocs.urls.push({
      value: r.output,
      source: r.note ? r.note.replace(/^Unwrapped: /, "Unwrapped via ") : "Unwrapped",
      // The mismatch belongs to the anchor that displayed the misleading text;
      // copying it here would score the same deception twice.
      isMismatch: false,
      unwrappedFrom: url.value,
    });
  }
}

/**
 * Domains from every URL (including unwrapped destinations) and from the
 * sender addresses. Previously only the Message-ID domain was listed.
 */
function collectDomains(iocs, headers) {
  const add = (domain, source) => {
    if (!domain) return;
    const d = domain.toLowerCase().replace(/\.$/, "");
    if (isValidIP(d.replace(/^\[|\]$/g, "")) || !d.includes(".")) return;
    iocs.domains.push({ value: d, source });
  };

  for (const [header, label] of [
    ["from", "From"],
    ["replyTo", "Reply-To"],
    ["returnPath", "Return-Path"],
  ]) {
    add(headers?.[header]?.email?.split("@")[1], label);
  }

  for (const url of iocs.urls) {
    try {
      add(new URL(url.value).hostname, url.unwrappedFrom ? "Unwrapped URL" : "URL");
    } catch {
      /* not a parseable URL */
    }
  }
}

/**
 * Deduplicate and add risk flags
 */
function deduplicateAndFlag(iocs) {
  // Deduplicate URLs
  const seenUrls = new Set();
  iocs.urls = iocs.urls.filter((url) => {
    if (seenUrls.has(url.value)) return false;
    seenUrls.add(url.value);

    // Add risk flags
    url.riskFlags = [];
    url.risks = [];
    const parsed = parseUrl(url.value);

    if (parsed) {
      // Check for URL shortener
      if (URL_SHORTENERS.some((s) => parsed.hostname.includes(s))) {
        url.riskFlags.push({ type: "medium", label: "URL Shortener" });
        url.risks.push({
          type: "url-shortener",
          level: "medium",
          message: "URL uses a URL shortener service",
        });
      }

      // Check for punycode
      if (PUNYCODE_PATTERN.test(parsed.hostname)) {
        url.riskFlags.push({ type: "high", label: "Punycode" });
        url.risks.push({
          type: "punycode",
          level: "high",
          message: "Domain contains punycode (possible homograph attack)",
        });
      }

      // Check for IP address in URL
      if (
        isValidIPv4(parsed.hostname) ||
        (parsed.hostname.startsWith("[") && isValidIP(parsed.hostname.slice(1, -1)))
      ) {
        url.riskFlags.push({ type: "high", label: "IP URL" });
        url.risks.push({
          type: "ip-url",
          level: "high",
          message: "URL uses raw IP address instead of domain",
        });
      }

      // Check for mismatched anchor text
      if (url.isMismatch) {
        url.riskFlags.push({ type: "high", label: "Mismatch" });
        url.risks.push({
          type: "mismatch",
          level: "high",
          message: "Link text doesn't match actual URL",
        });
      }
    }

    // Add defanged version
    url.defanged = defang(url.value);

    return true;
  });

  // Deduplicate domains
  const seenDomains = new Set();
  iocs.domains = iocs.domains.filter((domain) => {
    if (seenDomains.has(domain.value)) return false;
    seenDomains.add(domain.value);

    // Add risk flags
    domain.riskFlags = [];
    domain.risks = [];

    if (PUNYCODE_PATTERN.test(domain.value)) {
      domain.riskFlags.push({ type: "high", label: "Punycode" });
      domain.risks.push({
        type: "punycode",
        level: "high",
        message: "Domain contains punycode",
      });
    }

    // Add defanged version
    domain.defanged = defang(domain.value);

    return true;
  });

  // Deduplicate IPs - body IPs may overlap with header IPs
  const seenIps = new Set();
  iocs.ips = iocs.ips.filter((ip) => {
    if (seenIps.has(ip.value)) return false;
    seenIps.add(ip.value);
    return true;
  }).map((ip) => {
    ip.riskFlags = [];
    ip.risks = [];

    // Flag originating IPs as higher risk (can be spoofed)
    if (ip.source === "X-Originating-IP") {
      ip.riskFlags.push({ type: "medium", label: "Originating IP" });
      ip.risks.push({
        type: "originating-ip",
        level: "medium",
        message: "X-Originating-IP header (may be spoofed)",
      });
    }

    // Reputation services have nothing to say about a private or reserved
    // address, so mark it and let the renderer omit the lookup buttons.
    ip.private = isPrivateIP(ip.value);
    if (ip.private) {
      ip.riskFlags.push({ type: "low", label: "Private/Reserved" });
    }

    // Add defanged version
    ip.defanged = defang(ip.value);

    return ip;
  });

  // Deduplicate emails
  const seenEmails = new Set();
  iocs.emails = iocs.emails.filter((email) => {
    if (seenEmails.has(email.value)) return false;
    seenEmails.add(email.value);
    email.riskFlags = [];
    email.risks = [];

    // Check for disposable email domains
    const domain = email.value.split("@")[1];
    if (isDisposableDomain(domain)) {
      email.riskFlags.push({ type: "medium", label: "Disposable" });
      email.risks.push({
        type: "disposable",
        level: "medium",
        message: "Uses disposable email domain",
      });
    }

    return true;
  });

  // Flag risky attachments
  iocs.attachments = iocs.attachments.map((att) => {
    att.riskFlags = [];
    att.risks = [];
    att.risky = false;

    // Check for double extension
    if (DOUBLE_EXT_PATTERNS.some((p) => p.test(att.value))) {
      att.riskFlags.push({ type: "high", label: "Double Extension" });
      att.risks.push({
        type: "double-extension",
        level: "high",
        message: "Suspicious double file extension",
      });
      att.risky = true;
    }

    // Check for risky extension
    const ext = getExtension(att.value);
    if (RISKY_EXTENSIONS.includes(ext)) {
      att.riskFlags.push({ type: "high", label: `Risky: ${ext}` });
      att.risks.push({
        type: "risky-extension",
        level: "high",
        message: `Risky file extension: ${ext}`,
      });
      att.risky = true;
    }

    return att;
  });
}

/**
 * Defang a value for safe sharing
 */
function defang(value) {
  return value.replace(/http/gi, "hxxp").replace(/\./g, "[.]");
}

/**
 * Parse URL to get components
 */
function parseUrl(url) {
  try {
    return new URL(url);
  } catch (e) {
    return null;
  }
}

/**
 * Get file extension
 */
function getExtension(filename) {
  const match = filename.match(/\.([^.]+)$/);
  return match ? "." + match[1].toLowerCase() : "";
}

/**
 * Check for disposable email domains
 */
function isDisposableDomain(domain) {
  const disposableDomains = [
    "tempmail.com",
    "10minutemail.com",
    "guerrillamail.com",
    "mailinator.com",
    "throwaway.email",
    "temp-mail.org",
    "fakeinbox.com",
    "trashmail.com",
    "yopmail.com",
    "sharklasers.com",
    "guerrillamail.info",
    "grr.la",
  ];
  return disposableDomains.some((d) => domain && domain.includes(d));
}
