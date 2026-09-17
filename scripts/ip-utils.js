// IP Address Utilities
//
// Every IP in this app is scraped out of free-form header text, where a
// dotted-quad-shaped run of digits is very often not an address at all —
// message ids, Postfix queue ids, version strings and timestamps all produce
// convincing-looking matches. A pattern like \d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}
// happily accepts "15.21.360.10", which then reached the UI and was offered to
// AbuseIPDB, which rejected it.
//
// Extraction patterns find candidates; nothing becomes an IP without passing
// through here first.

/** Strictly validate a dotted-quad IPv4 address. */
export function isValidIPv4(value) {
  if (typeof value !== "string") return false;
  const parts = value.split(".");
  if (parts.length !== 4) return false;

  for (const part of parts) {
    if (!/^\d{1,3}$/.test(part)) return false;
    // "010" is ambiguous — some resolvers read it as octal, which is a known
    // obfuscation trick. Treat a padded octet as not a plain address.
    if (part.length > 1 && part[0] === "0") return false;
    if (Number(part) > 255) return false;
  }
  return true;
}

/**
 * Validate an IPv6 address, including the compressed "::" form and the
 * IPv4-mapped tail (::ffff:192.0.2.1).
 */
export function isValidIPv6(value) {
  if (typeof value !== "string" || !value.includes(":")) return false;

  let text = value;

  // A trailing dotted-quad is allowed and counts as two 16-bit groups.
  let tailGroups = 0;
  const lastColon = text.lastIndexOf(":");
  const tail = text.slice(lastColon + 1);
  if (tail.includes(".")) {
    if (!isValidIPv4(tail)) return false;
    text = text.slice(0, lastColon + 1) + "0";
    tailGroups = 1;
  }

  const doubleColons = text.split("::").length - 1;
  if (doubleColons > 1) return false;

  const [head, rest] = doubleColons === 1 ? text.split("::") : [text, null];
  const headGroups = head ? head.split(":") : [];
  const restGroups = rest ? rest.split(":") : [];
  const groups = [...headGroups, ...restGroups].filter((g) => g !== "");

  for (const g of groups) {
    if (!/^[0-9a-f]{1,4}$/i.test(g)) return false;
  }

  const total = groups.length + tailGroups;
  return doubleColons === 1 ? total <= 7 : total === 8;
}

/** True for any address this app is willing to treat as real. */
export function isValidIP(value) {
  return isValidIPv4(value) || isValidIPv6(value);
}

/**
 * Private, loopback, link-local, multicast and other reserved ranges — an
 * address here cannot be the true public origin of a message, and is not worth
 * sending to a reputation service.
 */
export function isPrivateIP(value) {
  if (!isValidIP(value)) return false;

  if (isValidIPv6(value)) {
    const v = value.toLowerCase();
    if (v === "::1" || v === "::") return true;
    if (/^f[cd]/.test(v)) return true; // unique local
    if (/^fe[89ab]/.test(v)) return true; // link local
    // IPv4-mapped: judge by the embedded address.
    const tail = v.slice(v.lastIndexOf(":") + 1);
    if (tail.includes(".")) return isPrivateIP(tail);
    return false;
  }

  const [a, b] = value.split(".").map(Number);
  if (a === 10 || a === 127 || a === 0) return true;
  if (a === 172 && b >= 16 && b <= 31) return true;
  if (a === 192 && b === 168) return true;
  if (a === 169 && b === 254) return true; // link local
  if (a === 100 && b >= 64 && b <= 127) return true; // carrier-grade NAT
  if (a >= 224) return true; // multicast and reserved
  return false;
}

/** True for an address worth submitting to VirusTotal or AbuseIPDB. */
export function isRoutableIP(value) {
  return isValidIP(value) && !isPrivateIP(value);
}

/**
 * The address of the host that SENT a hop, from one Received header.
 *
 * "Received: from A (A [1.2.3.4]) by B (B [5.6.7.8]); date" — only the from
 * clause describes the sender; the by clause is the server that received it.
 * Searching the whole header let B's address be reported as the sender's
 * whenever A's clause carried no address of its own. Microsoft writes the
 * address bare in parentheses rather than brackets, so both forms are read.
 */
export function receivedFromIP(header) {
  const fromClause =
    String(header).match(/\bfrom\b([\s\S]*?)(?=\bby\b|\bwith\b|;|$)/i)?.[1] || "";
  const bracketed = [...fromClause.matchAll(/\[([^\]]+)\]/g)]
    .map((m) => m[1].replace(/^IPv6:/i, "").trim())
    .find(isValidIP);
  return bracketed || findIPs(fromClause)[0] || null;
}

/**
 * Pull every genuine IP out of arbitrary text, in order of appearance.
 * Candidates that fail validation are discarded rather than reported.
 */
export function findIPs(text) {
  if (!text) return [];
  const found = [];
  const seen = new Set();

  const push = (candidate) => {
    if (isValidIP(candidate) && !seen.has(candidate)) {
      seen.add(candidate);
      found.push(candidate);
    }
  };

  // IPv4 candidates. The surrounding boundaries stop "1.2.3.4.5" and version
  // strings from yielding a spurious four-octet slice.
  const v4 = /(?<![\d.])(\d{1,3}(?:\.\d{1,3}){3})(?![\d.])/g;
  let m;
  while ((m = v4.exec(text)) !== null) push(m[1]);

  // IPv6 candidates, including the "IPv6:" prefix MTAs write in brackets.
  const v6 = /(?:IPv6:)?\b([0-9a-f]{0,4}(?::[0-9a-f]{0,4}){2,7}(?:\.\d{1,3}){0,3})/gi;
  while ((m = v6.exec(text)) !== null) push(m[1]);

  return found;
}
