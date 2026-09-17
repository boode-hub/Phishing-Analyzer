// Header Parsing Module
// RFC 5322 compliant header extraction and unfolding

/**
 * Parse email headers from raw input
 * @param {string} rawInput - Raw email headers or full email
 * @returns {Object} Parsed headers object
 */
export function parseHeaders(rawInput) {
  // Split headers from body (if present)
  const headerEnd = findHeaderBodyBoundary(rawInput);
  const headerSection = rawInput.substring(0, headerEnd);
  const bodySection = rawInput.substring(headerEnd);

  // Unfold and parse headers
  const unfolded = unfoldHeaders(headerSection);
  const headers = parseHeaderLines(unfolded);
  const ordered = orderedHeaders(unfolded);

  // Extract specific headers (keys are lowercased with hyphens preserved)
  //
  // Headers that legitimately repeat (every relay prepends its own
  // Authentication-Results / Received-SPF, and a message may carry several
  // DKIM-Signature headers) are always exposed as arrays, ordered topmost
  // first. Single-value headers take the topmost occurrence: a second From or
  // Subject is a forgery attempt, and the topmost is what the MUA displays.
  const result = {
    raw: headerSection,
    all: headers,
    // Every header exactly as it appeared, top to bottom, name case preserved.
    // `all` is keyed by name, which groups repeats (all Received headers
    // together) and loses the order the servers wrote them in.
    ordered,
    from: extractAddress(first(headers.from)),
    replyTo: extractAddress(first(headers["reply-to"])),
    returnPath: extractAddress(first(headers["return-path"])),
    to: extractAddress(first(headers.to)),
    subject: decodeEncodedWords(first(headers.subject) || ""),
    date: first(headers.date),
    messageId: first(headers["message-id"]),
    received: asArray(headers.received),
    authenticationResults: asArray(headers["authentication-results"]),
    receivedSpf: asArray(headers["received-spf"]),
    dkimSignature: asArray(headers["dkim-signature"]),
    contentType: first(headers["content-type"]),
    xMailer: first(headers["x-mailer"]),
    xOriginatingIp: first(headers["x-originating-ip"]),
    xHeaders: extractXHeaders(headers),
    // Headers a sender should only send once. More than one is itself a signal.
    duplicated: ["from", "subject", "reply-to", "return-path", "date", "to"]
      .filter((k) => Array.isArray(headers[k]) && headers[k].length > 1)
      .map((k) => ({ header: k, count: headers[k].length })),
  };

  // Extract domains
  result.domains = extractDomains(result);

  return result;
}

/**
 * A repeated header arrives from parseHeaderLines as an array; a single one as
 * a string. These two normalize both shapes so callers never have to check.
 */
function asArray(v) {
  if (v == null) return [];
  return Array.isArray(v) ? v : [v];
}

function first(v) {
  return Array.isArray(v) ? v[0] : v;
}

/**
 * Find the boundary between headers and body
 */
function findHeaderBodyBoundary(input) {
  // RFC 5322: headers end with a blank line (CRLF CRLF or LF LF)
  const crlfIndex = input.indexOf("\r\n\r\n");
  const lfIndex = input.indexOf("\n\n");

  if (crlfIndex !== -1 && (lfIndex === -1 || crlfIndex < lfIndex)) {
    return crlfIndex;
  }
  if (lfIndex !== -1) {
    return lfIndex;
  }

  // Fallback: look for the first blank line that follows a header-like line
  const lines = input.split(/\r?\n/);
  for (let i = 1; i < lines.length; i++) {
    const prevLine = lines[i - 1];
    const currLine = lines[i];
    // Blank line after a header line (contains colon) = end of headers
    if (
      currLine.trim() === "" &&
      prevLine.includes(":") &&
      !prevLine.startsWith(" ")
    ) {
      // Calculate the offset accounting for \r\n vs \n
      let offset = 0;
      const isCRLF = input.includes("\r\n");
      const lineEnding = isCRLF ? "\r\n" : "\n";
      for (let j = 0; j < i; j++) {
        offset += lines[j].length + lineEnding.length;
      }
      return offset;
    }
  }

  return input.length;
}

/**
 * Unfold multi-line headers (RFC 5322)
 * Continuation lines start with whitespace
 */
function unfoldHeaders(headerSection) {
  return headerSection.replace(/\r?\n[ \t]+/g, " ");
}

/**
 * Headers in their original order. A field name is printable ASCII with no
 * spaces or colon (RFC 5322 §2.2), which keeps stray lines out of the list.
 */
function orderedHeaders(unfolded) {
  const list = [];
  for (const line of unfolded.split(/\r?\n/)) {
    const colon = line.indexOf(":");
    if (colon <= 0) continue;
    const name = line.slice(0, colon);
    if (!/^[\x21-\x39\x3b-\x7e]+$/.test(name)) continue;
    list.push({ name, value: line.slice(colon + 1).trim() });
  }
  return list;
}

/**
 * Parse header lines into key-value pairs
 */
function parseHeaderLines(unfolded) {
  const headers = {};
  const lines = unfolded.split(/\r?\n/);

  for (const line of lines) {
    const colonIndex = line.indexOf(":");
    if (colonIndex === -1) continue;

    const key = line.substring(0, colonIndex).trim().toLowerCase();
    const value = line.substring(colonIndex + 1).trim();

    // Handle duplicate headers (like Received)
    if (headers[key]) {
      if (Array.isArray(headers[key])) {
        headers[key].push(value);
      } else {
        headers[key] = [headers[key], value];
      }
    } else {
      headers[key] = value;
    }
  }

  return headers;
}

/**
 * Extract email address from header value
 * Handles: "Name <email>", plain email, comments, multiple addresses
 */
function extractAddress(headerValue) {
  if (!headerValue) return null;

  // Remove RFC 2047 encoded-words comments that may contain parenthesized text
  let cleaned = headerValue.replace(/\([^()]*\)/g, "").trim();

  // Handle "Name <email@domain>" format
  const angleMatch = cleaned.match(/<([^>]+)>/);
  if (angleMatch) {
    const name = cleaned.replace(/<[^>]+>/, "").replace(/"/g, "").trim();
    const email = angleMatch[1].trim().toLowerCase();
    // Validate it looks like an email
    if (/^[^\s<>]+@[^\s<>]+\.[^\s<>]+$/.test(email)) {
      return {
        raw: headerValue,
        email,
        name: name || null,
      };
    }
  }

  // Handle plain email@domain format (no angle brackets)
  const plainMatch = cleaned.match(/([^\s<>;,]+@[^\s<>;,]+\.[^\s<>;,]+)/);
  if (plainMatch) {
    return {
      raw: headerValue,
      email: plainMatch[1].toLowerCase(),
      name: null,
    };
  }

  // Last resort: try to find any email-like pattern
  const fallbackMatch = headerValue.match(
    /([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/,
  );
  if (fallbackMatch) {
    return {
      raw: headerValue,
      email: fallbackMatch[1].toLowerCase(),
      name: null,
    };
  }

  return { raw: headerValue, email: null, name: null };
}

/**
 * Decode RFC 2047 encoded-words
 * Format: =?charset?encoding?encoded_text?=
 */
function decodeEncodedWords(text) {
  if (!text) return "";

  // Pattern: =?charset?encoding?text?=
  const pattern = /=\?([^?]+)\?([BQbq])\?([^?]*)\?=/g;

  return text.replace(pattern, (match, charset, encoding, encodedText) => {
    try {
      if (encoding.toUpperCase() === "B") {
        // Base64
        const decoded = atob(encodedText);
        return decodeString(decoded, charset);
      } else if (encoding.toUpperCase() === "Q") {
        // Quoted-printable
        const decoded = encodedText
          .replace(/_/g, " ")
          .replace(/=([0-9A-Fa-f]{2})/g, (m, hex) =>
            String.fromCharCode(parseInt(hex, 16)),
          );
        return decodeString(decoded, charset);
      }
    } catch (e) {
      // Return original if decode fails
    }
    return match;
  });
}

/**
 * Decode string with charset
 */
function decodeString(str, charset) {
  try {
    // Try to decode as the specified charset
    const decoder = new TextDecoder(charset, { fatal: false });
    return decoder.decode(new Uint8Array([...str].map((c) => c.charCodeAt(0))));
  } catch (e) {
    return str;
  }
}

/**
 * Extract X-* headers
 */
function extractXHeaders(headers) {
  const xHeaders = {};
  for (const [key, value] of Object.entries(headers)) {
    if (key.startsWith("x-")) {
      xHeaders[key] = value;
    }
  }
  return xHeaders;
}

/**
 * Extract domains from various header sources
 */
function extractDomains(headerData) {
  const domains = [];

  // From address
  if (headerData.from && headerData.from.email) {
    const domain = headerData.from.email.split("@")[1];
    if (domain) {
      domains.push({ source: "From", domain, email: headerData.from.email });
    }
  }

  // Reply-To
  if (headerData.replyTo && headerData.replyTo.email) {
    const domain = headerData.replyTo.email.split("@")[1];
    if (domain) {
      domains.push({
        source: "Reply-To",
        domain,
        email: headerData.replyTo.email,
      });
    }
  }

  // Return-Path
  if (headerData.returnPath && headerData.returnPath.email) {
    const domain = headerData.returnPath.email.split("@")[1];
    if (domain) {
      domains.push({
        source: "Return-Path",
        domain,
        email: headerData.returnPath.email,
      });
    }
  }

  // DKIM domain — a message may carry several signatures, each with its own d=
  for (const sig of headerData.dkimSignature || []) {
    const dkimMatch = String(sig).match(/[;\s]d=\s*([^;\s]+)/) ||
      String(sig).match(/^\s*d=\s*([^;\s]+)/);
    if (dkimMatch) {
      domains.push({ source: "DKIM", domain: dkimMatch[1].toLowerCase() });
    }
  }

  return domains;
}
