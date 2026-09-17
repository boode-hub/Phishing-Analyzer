// URL Decoders
//
// Phishing links are routinely wrapped or encoded to get past filters and to
// hide the real destination from a human glancing at them: rewritten by a mail
// security gateway (Safe Links, Proofpoint), percent-encoded in layers, carrying
// the victim's address as base64, or using a punycode lookalike domain.
//
// Each decoder returns { output, note } when it applies to the input, or null
// when there is nothing for it to do. None of them fetch anything — decoding is
// purely local, like the rest of the app.

const MAX_LAYERS = 5;

// ===== Percent-encoding =====

export function percentDecode(input) {
  let current = input;
  let layers = 0;
  while (layers < MAX_LAYERS && /%[0-9a-f]{2}/i.test(current)) {
    let next;
    try {
      next = decodeURIComponent(current);
    } catch {
      // Malformed UTF-8 sequence: decode byte by byte rather than give up.
      next = current.replace(/%([0-9a-f]{2})/gi, (m, h) =>
        String.fromCharCode(parseInt(h, 16)),
      );
    }
    if (next === current) break;
    current = next;
    layers++;
  }
  if (!layers) return null;
  return {
    output: current,
    note:
      layers > 1
        ? `${layers} layers of encoding — multi-encoding is a filter-evasion technique`
        : null,
  };
}

// ===== Security gateway / redirect unwrapping =====

/**
 * Recover the real destination from a link rewritten by a mail security
 * gateway or wrapped in a redirector. Unwraps repeatedly, since a Safe Links
 * URL can wrap a Google redirect that wraps the actual target.
 */
export function unwrapRedirect(input) {
  const chain = [];
  let current = input;

  for (let i = 0; i < MAX_LAYERS; i++) {
    const step = unwrapOnce(current);
    if (!step) break;
    chain.push(step.via);
    // Checked before the no-change test: a partial result (Mimecast) leaves
    // the URL as-is, and the explanation is the whole point.
    if (step.partial) {
      return {
        output: step.url,
        note: `${chain.join(" → ")}. ${step.partial}`,
      };
    }
    if (step.url === current) break;
    current = step.url;
  }

  if (!chain.length) return null;
  return { output: current, note: `Unwrapped: ${chain.join(" → ")}` };
}

function unwrapOnce(url) {
  let u;
  try {
    u = new URL(url);
  } catch {
    return null;
  }
  const host = u.hostname.toLowerCase();
  const param = (...names) => {
    for (const n of names) {
      const v = u.searchParams.get(n);
      if (v) return v;
    }
    return null;
  };

  if (host.endsWith("safelinks.protection.outlook.com")) {
    const target = param("url");
    if (target) return { url: target, via: "Microsoft Defender Safe Links" };
  }

  if (host === "urldefense.com" && u.pathname.startsWith("/v3/__")) {
    const decoded = decodeProofpointV3(url);
    if (decoded) return { url: decoded, via: "Proofpoint URL Defense v3" };
  }

  if (host.endsWith("urldefense.proofpoint.com")) {
    const raw = param("u");
    if (raw && u.pathname.startsWith("/v2/")) {
      const translated = raw.replace(/-/g, "%").replace(/_/g, "/");
      return {
        url: safeDecodeURIComponent(translated),
        via: "Proofpoint URL Defense v2",
      };
    }
    if (raw && u.pathname.startsWith("/v1/")) {
      return {
        url: safeDecodeURIComponent(raw),
        via: "Proofpoint URL Defense v1",
      };
    }
  }

  if (/(^|\.)google\.[a-z.]+$/.test(host) && u.pathname === "/url") {
    const target = param("q", "url");
    if (target) return { url: target, via: "Google redirect" };
  }

  if (/^l[m]?\.facebook\.com$/.test(host) && u.pathname === "/l.php") {
    const target = param("u");
    if (target) return { url: target, via: "Facebook link shim" };
  }

  if (host === "linkprotect.cudasvc.com") {
    const target = param("a");
    if (target) return { url: target, via: "Barracuda Link Protection" };
  }

  if (host === "secure-web.cisco.com") {
    const last = u.pathname.split("/").pop();
    const target = safeDecodeURIComponent(last);
    if (/^https?:\/\//i.test(target)) {
      return { url: target, via: "Cisco Secure Email" };
    }
  }

  if (/(^|\.)mimecast\.com$/.test(host) && /\/s\//.test(u.pathname)) {
    // Mimecast stores the destination server-side; the link carries only a
    // token. Say so rather than pretend there is nothing to decode.
    return {
      url,
      via: "Mimecast URL Protect",
      partial:
        "The destination is held on Mimecast's servers and cannot be recovered from the link itself.",
    };
  }

  // Generic open redirect: any parameter that is itself a URL.
  for (const [key, value] of u.searchParams) {
    const candidate = value.trim();
    if (/^(https?:\/\/|www\.)/i.test(candidate) && candidate !== url) {
      return {
        url: candidate,
        via: `redirect parameter "${key}" on ${host}`,
      };
    }
  }

  return null;
}

/**
 * Proofpoint URL Defense v3. Characters Proofpoint considered unsafe are
 * replaced by "*" in the visible URL, and the originals are stored in order as
 * base64url after "__;". "**X" marks a run of several, X encoding the length.
 */
function decodeProofpointV3(url) {
  const m = url.match(/v3\/__(.+?)__;(.*?)!/);
  if (!m) return null;

  const encodedUrl = safeDecodeURIComponent(m[1]);
  let removed = "";
  if (m[2]) {
    const bytes = base64ToBytes(m[2]);
    if (!bytes) return null;
    removed = new TextDecoder("utf-8").decode(bytes);
  }
  const chars = [...removed];

  const runValues =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
  let marker = 0;
  return encodedUrl.replace(/\*\*(.)|\*/g, (token, runKey) => {
    if (runKey !== undefined) {
      const length = runValues.indexOf(runKey) + 2;
      const run = chars.slice(marker, marker + length).join("");
      marker += length;
      return run;
    }
    return chars[marker++] ?? "*";
  });
}

// ===== Base64 / Base64URL =====

/**
 * Find base64 or base64url tokens anywhere in the URL and decode the ones that
 * produce readable text. Phishing kits commonly carry the victim's email
 * address this way, e.g. "#dmljdGltQGNvbXBhbnkuY29t".
 */
export function base64Decode(input) {
  // Percent-decode first: a token behind "%23" or inside a wrapped url= value
  // is otherwise glued to encoding characters and never recognised.
  const text = percentDecode(input)?.output ?? input;
  const tokens = text
    .split(/[/?&=#;,:.]+/)
    .filter((t) => t.length >= 8 && /^[A-Za-z0-9+/_-]+={0,2}$/.test(t))
    // A plain word or a pure number is not worth trying.
    .filter((t) => /\d/.test(t) || /[A-Z].*[a-z]|[a-z].*[A-Z]/.test(t));

  const found = [];
  for (const token of new Set(tokens)) {
    const bytes = base64ToBytes(token);
    if (!bytes) continue;
    const text = readableText(bytes);
    if (text) found.push(`${token}  →  ${text}`);
  }
  if (!found.length) return null;
  return {
    output: found.join("\n"),
    note: found.some((f) => /@/.test(f.split("→")[1]))
      ? "An email address was hidden in the link — typically the targeted recipient"
      : null,
  };
}

function base64ToBytes(token) {
  let b = token.replace(/-/g, "+").replace(/_/g, "/").replace(/=+$/, "");
  if (b.length % 4 === 1) return null;
  while (b.length % 4) b += "=";
  try {
    return Uint8Array.from(atob(b), (c) => c.charCodeAt(0));
  } catch {
    return null;
  }
}

/** UTF-8 text that is overwhelmingly printable, or null. */
function readableText(bytes) {
  let text;
  try {
    text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    return null;
  }
  if (text.length < 4) return null;
  const printable = [...text].filter((ch) => {
    const c = ch.codePointAt(0);
    return c >= 0x20 && c !== 0x7f && !(c >= 0x80 && c < 0xa0);
  }).length;
  if (printable / [...text].length < 0.95) return null;
  if (!/[a-z]{3}/i.test(text)) return null;
  return text;
}

// ===== Hex =====

export function hexDecode(input) {
  const text = percentDecode(input)?.output ?? input;
  const runs = text.match(/(?:[0-9a-f]{2}){6,}/gi) || [];
  const found = [];
  for (const run of new Set(runs)) {
    const bytes = new Uint8Array(run.length / 2);
    for (let i = 0; i < bytes.length; i++) {
      bytes[i] = parseInt(run.substr(i * 2, 2), 16);
    }
    const text = readableText(bytes);
    if (text) found.push(`${run}  →  ${text}`);
  }
  return found.length ? { output: found.join("\n"), note: null } : null;
}

// ===== HTML entities =====

const NAMED_ENTITIES = {
  amp: "&",
  lt: "<",
  gt: ">",
  quot: '"',
  apos: "'",
  nbsp: " ",
  sol: "/",
  colon: ":",
  period: ".",
  commat: "@",
  quest: "?",
  equals: "=",
};

export function htmlEntityDecode(input) {
  if (!/&(#x?[0-9a-f]+|[a-z]+);/i.test(input)) return null;
  const output = input.replace(/&(#x[0-9a-f]+|#\d+|[a-z]+);/gi, (m, e) => {
    if (e[0] === "#") {
      const cp =
        e[1].toLowerCase() === "x"
          ? parseInt(e.slice(2), 16)
          : parseInt(e.slice(1), 10);
      return cp > 0 && cp <= 0x10ffff ? String.fromCodePoint(cp) : m;
    }
    return NAMED_ENTITIES[e.toLowerCase()] ?? m;
  });
  return output === input ? null : { output, note: null };
}

// ===== JavaScript-style escapes =====

export function escapeDecode(input) {
  if (!/\\u\{?[0-9a-f]{2,6}\}?|\\x[0-9a-f]{2}/i.test(input)) return null;
  const output = input
    .replace(/\\u\{([0-9a-f]{1,6})\}/gi, (m, h) => String.fromCodePoint(parseInt(h, 16)))
    .replace(/\\u([0-9a-f]{4})/gi, (m, h) => String.fromCharCode(parseInt(h, 16)))
    .replace(/\\x([0-9a-f]{2})/gi, (m, h) => String.fromCharCode(parseInt(h, 16)));
  return output === input ? null : { output, note: null };
}

// ===== Punycode (IDN homographs) =====

/**
 * Reveal the Unicode form of a punycode hostname. "xn--pypal-4ve.com" renders
 * as "pаypal.com" with a Cyrillic "а" — the lookalike the link is relying on.
 */
export function punycodeDecode(input) {
  let u;
  try {
    u = new URL(input);
  } catch {
    return null;
  }
  if (!/(^|\.)xn--/i.test(u.hostname)) return null;

  let unicodeHost;
  try {
    unicodeHost = u.hostname
      .split(".")
      .map((label) =>
        label.toLowerCase().startsWith("xn--") ? punycodeToUnicode(label.slice(4)) : label,
      )
      .join(".");
  } catch {
    return null;
  }

  const nonAscii = [...unicodeHost].filter((ch) => ch.codePointAt(0) > 0x7f);
  const codes = [...new Set(nonAscii)]
    .map((ch) => `${ch} U+${ch.codePointAt(0).toString(16).toUpperCase().padStart(4, "0")}`)
    .join(", ");

  return {
    output: input.replace(u.hostname, unicodeHost),
    note: `Displays as ${unicodeHost}${codes ? ` — non-ASCII characters: ${codes}` : ""}`,
  };
}

// RFC 3492 decoding. Browsers expose no toUnicode, so this is done by hand.
function punycodeToUnicode(input) {
  const base = 36, tMin = 1, tMax = 26, skew = 38, damp = 700;
  let n = 128, i = 0, bias = 72;
  const output = [];

  const basicEnd = input.lastIndexOf("-");
  for (let j = 0; j < Math.max(basicEnd, 0); j++) {
    output.push(input.charCodeAt(j));
  }

  const digitOf = (cp) => {
    if (cp >= 48 && cp <= 57) return cp - 22; // 0-9 -> 26-35
    if (cp >= 65 && cp <= 90) return cp - 65; // A-Z -> 0-25
    if (cp >= 97 && cp <= 122) return cp - 97; // a-z -> 0-25
    throw new Error("invalid punycode");
  };

  const adapt = (delta, numPoints, firstTime) => {
    delta = firstTime ? Math.floor(delta / damp) : delta >> 1;
    delta += Math.floor(delta / numPoints);
    let k = 0;
    while (delta > ((base - tMin) * tMax) >> 1) {
      delta = Math.floor(delta / (base - tMin));
      k += base;
    }
    return Math.floor(k + ((base - tMin + 1) * delta) / (delta + skew));
  };

  for (let idx = basicEnd > 0 ? basicEnd + 1 : 0; idx < input.length; ) {
    const oldI = i;
    let w = 1;
    for (let k = base; ; k += base) {
      if (idx >= input.length) throw new Error("invalid punycode");
      const digit = digitOf(input.charCodeAt(idx++));
      i += digit * w;
      const t = k <= bias ? tMin : k >= bias + tMax ? tMax : k - bias;
      if (digit < t) break;
      w *= base - t;
    }
    const length = output.length + 1;
    bias = adapt(i - oldI, length, oldI === 0);
    n += Math.floor(i / length);
    i %= length;
    output.splice(i++, 0, n);
  }
  return String.fromCodePoint(...output);
}

// ===== Everything, in sequence =====

/**
 * Apply every reversible layer until the URL stops changing, then report any
 * embedded base64/hex payloads and the punycode display form of the result.
 */
export function decodeAll(input) {
  const steps = [];
  let current = input;

  for (let pass = 0; pass < MAX_LAYERS; pass++) {
    let changed = false;
    for (const [name, fn] of [
      ["unwrap", unwrapRedirect],
      ["HTML entities", htmlEntityDecode],
      ["escapes", escapeDecode],
      ["URL %XX", percentDecode],
    ]) {
      const r = fn(current);
      if (r && r.output !== current) {
        steps.push(name === "unwrap" && r.note ? r.note.replace(/^Unwrapped: /, "unwrap: ") : name);
        current = r.output;
        changed = true;
      }
    }
    if (!changed) break;
  }

  const extras = [];
  const b64 = base64Decode(current);
  if (b64) extras.push(`Base64 inside:\n${b64.output}`);
  const hex = hexDecode(current);
  if (hex) extras.push(`Hex inside:\n${hex.output}`);
  const puny = punycodeDecode(current);
  if (puny) extras.push(puny.note);

  if (!steps.length && !extras.length) return null;
  return {
    output: [current, ...extras].join("\n\n"),
    note: steps.length ? `Applied: ${steps.join(" → ")}` : null,
  };
}

// ===== Registry =====

export const URL_DECODERS = [
  { id: "all", label: "Decode all", run: decodeAll },
  { id: "unwrap", label: "Unwrap Safe Links / redirect", run: unwrapRedirect },
  { id: "percent", label: "URL %XX", run: percentDecode },
  { id: "base64", label: "Base64", run: base64Decode },
  { id: "punycode", label: "Punycode", run: punycodeDecode },
  { id: "html", label: "HTML entities", run: htmlEntityDecode },
  { id: "hex", label: "Hex", run: hexDecode },
  { id: "escape", label: "\\u \\x escapes", run: escapeDecode },
];

/** Labels of the specific decoders that find something in this URL. */
export function detectEncodings(url) {
  return URL_DECODERS.filter((d) => d.id !== "all" && safeRun(d.run, url)).map(
    (d) => d.id,
  );
}

export function safeRun(fn, url) {
  try {
    return fn(url);
  } catch {
    return null;
  }
}

function safeDecodeURIComponent(s) {
  try {
    return decodeURIComponent(s);
  } catch {
    return s;
  }
}
