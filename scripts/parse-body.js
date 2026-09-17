// Body Parsing Module
// MIME body extraction, decoding, and link extraction

import { orgDomain } from "./parse-auth.js";
import { unwrapRedirect, htmlEntityDecode } from "./url-decode.js";

/**
 * Parse email body from raw input
 * @param {string} rawInput - Raw email (headers + body)
 * @returns {Object} Parsed body content
 */
export function parseBody(rawInput) {
  const headerEnd = findHeaderBodyBoundary(rawInput);
  const headerSection = rawInput.substring(0, headerEnd);
  const bodyContent = rawInput.substring(headerEnd);

  const root = parseMimePart(headerSection, bodyContent);

  const collected = {
    text: "",
    html: "",
    attachments: [],
    links: [],
  };
  walkParts(root, collected, true);

  // An HTML-only message still needs readable text, or language analysis gets
  // an empty string and silently reports nothing.
  const plain =
    collected.text.trim() ||
    (collected.html ? stripHtml(collected.html) : "");

  return {
    text: plain,
    html: collected.html.trim() || null,
    raw: plain || collected.html.trim(),
    contentType: root.contentTypeRaw,
    attachments: collected.attachments,
    links: collected.links,
  };
}

/**
 * Walk the MIME tree, gathering displayable text and every file-like part.
 *
 * "File-like" deliberately includes inline images and any part carrying a
 * Content-ID: a tracking pixel or an embedded logo is exactly the thing an
 * analyst wants a hash of, and the previous version only collected parts
 * explicitly marked `Content-Disposition: attachment`.
 */
function walkParts(part, out, isRoot) {
  if (part.children) {
    for (const child of part.children) walkParts(child, out, false);
    return;
  }

  if (isFilePart(part, isRoot)) {
    out.attachments.push({
      filename: part.filename || inferFilename(part),
      contentType: part.mime,
      size: part.bytes.length,
      bytes: part.bytes,
      contentId: part.contentId,
      inline: part.dispositionType === "inline" || !!part.contentId,
    });
    return;
  }

  const text = decodeText(part);
  if (part.mime === "text/html") {
    out.html += text;
    out.links.push(...extractLinksFromHtml(text));
  } else if (part.mime.startsWith("text/")) {
    out.text += text + "\n";
    out.links.push(...extractLinksFromText(text));
  }
}

function isFilePart(part, isRoot) {
  if (part.dispositionType === "attachment") return true;
  // An inline part with a filename or Content-ID is an embedded file.
  if (part.filename || part.contentId) return true;
  // Any non-text, non-root leaf is a file even without a disposition header.
  if (!isRoot && !part.mime.startsWith("text/")) return true;
  return false;
}

function inferFilename(part) {
  if (part.contentId) return `inline-${part.contentId}`;
  const ext = (part.mime.split("/")[1] || "bin").replace(/[^a-z0-9]/gi, "");
  return `unnamed-part.${ext}`;
}

/**
 * Find header/body boundary
 */
function findHeaderBodyBoundary(input) {
  const crlfIndex = input.indexOf("\r\n\r\n");
  const lfIndex = input.indexOf("\n\n");

  if (crlfIndex !== -1 && (lfIndex === -1 || crlfIndex < lfIndex)) {
    return crlfIndex + 4;
  }
  if (lfIndex !== -1) {
    return lfIndex + 2;
  }
  return input.length;
}

/**
 * Parse one MIME part into either a container (with children) or a decoded
 * leaf. Recursive, so a multipart/mixed wrapping a multipart/alternative — the
 * ordinary shape of a message with both a rich body and an attachment — is
 * traversed properly instead of being split on the outer boundary only.
 */
function parseMimePart(rawHeaders, rawBody) {
  const headers = parsePartHeaders(rawHeaders);
  const contentTypeRaw = headers["content-type"] || "text/plain";
  const mime = contentTypeRaw.split(";")[0].trim().toLowerCase();
  const disposition = headers["content-disposition"] || "";

  const part = {
    mime,
    contentTypeRaw,
    charset: getParam(contentTypeRaw, "charset") || "utf-8",
    encoding: (headers["content-transfer-encoding"] || "7bit")
      .trim()
      .toLowerCase(),
    dispositionType: disposition.split(";")[0].trim().toLowerCase() || null,
    filename:
      decodeHeaderWord(getParam(disposition, "filename")) ||
      decodeHeaderWord(getParam(contentTypeRaw, "name")) ||
      null,
    contentId: (headers["content-id"] || "").replace(/[<>]/g, "").trim() || null,
  };

  if (mime.startsWith("multipart/")) {
    const boundary = getParam(contentTypeRaw, "boundary");
    part.children = boundary ? splitMultipart(rawBody, boundary) : [];
    return part;
  }

  part.bytes = decodeToBytes(rawBody, part.encoding);
  return part;
}

/** Split a multipart body on its boundary and parse each piece. */
function splitMultipart(body, boundary) {
  const delimiter = "--" + boundary;
  const chunks = body.split(delimiter);
  const parts = [];

  // First chunk is the preamble; a chunk starting with "--" is the epilogue.
  for (let i = 1; i < chunks.length; i++) {
    const chunk = chunks[i];
    if (chunk.startsWith("--")) break;
    const stripped = chunk.replace(/^\r?\n/, "");
    const { head, body: partBody } = splitHeadBody(stripped);
    parts.push(parseMimePart(head, partBody));
  }
  return parts;
}

function splitHeadBody(s) {
  const crlf = s.indexOf("\r\n\r\n");
  const lf = s.indexOf("\n\n");
  if (crlf !== -1 && (lf === -1 || crlf < lf)) {
    return { head: s.slice(0, crlf), body: s.slice(crlf + 4) };
  }
  if (lf !== -1) return { head: s.slice(0, lf), body: s.slice(lf + 2) };
  return { head: s, body: "" };
}

/** Unfold and index one part's headers. */
function parsePartHeaders(raw) {
  const headers = {};
  const unfolded = String(raw).replace(/\r?\n[ \t]+/g, " ");
  for (const line of unfolded.split(/\r?\n/)) {
    const colon = line.indexOf(":");
    if (colon === -1) continue;
    headers[line.slice(0, colon).trim().toLowerCase()] = line
      .slice(colon + 1)
      .trim();
  }
  return headers;
}

/** Read a parameter out of a structured header value. */
function getParam(value, name) {
  if (!value) return null;
  const quoted = value.match(
    new RegExp(name + '\\s*=\\s*"([^"]*)"', "i"),
  );
  if (quoted) return quoted[1];
  const bare = value.match(
    new RegExp(name + "\\s*=\\s*([^;\\s]+)", "i"),
  );
  return bare ? bare[1] : null;
}

/** Filenames are frequently RFC 2047 encoded-words. */
function decodeHeaderWord(text) {
  if (!text) return text;
  return text.replace(
    /=\?([^?]+)\?([BQbq])\?([^?]*)\?=/g,
    (match, charset, enc, body) => {
      try {
        const binary =
          enc.toUpperCase() === "B"
            ? atob(body)
            : body
                .replace(/_/g, " ")
                .replace(/=([0-9A-Fa-f]{2})/g, (m, h) =>
                  String.fromCharCode(parseInt(h, 16)),
                );
        return new TextDecoder(charset, { fatal: false }).decode(
          latin1ToBytes(binary),
        );
      } catch {
        return match;
      }
    },
  );
}

/**
 * Decode a part body to raw bytes. Everything downstream — hashing especially —
 * needs bytes, not a JS string.
 */
function decodeToBytes(content, encoding) {
  switch (encoding) {
    case "base64": {
      const cleaned = content.replace(/[^A-Za-z0-9+/=]/g, "");
      try {
        return latin1ToBytes(atob(cleaned));
      } catch {
        return latin1ToBytes(content);
      }
    }
    case "quoted-printable": {
      const unfolded = content.replace(/=\r?\n/g, "");
      const bytes = [];
      for (let i = 0; i < unfolded.length; i++) {
        if (
          unfolded[i] === "=" &&
          /^[0-9A-Fa-f]{2}$/.test(unfolded.substr(i + 1, 2))
        ) {
          bytes.push(parseInt(unfolded.substr(i + 1, 2), 16));
          i += 2;
        } else {
          bytes.push(unfolded.charCodeAt(i) & 0xff);
        }
      }
      return new Uint8Array(bytes);
    }
    default:
      return latin1ToBytes(content);
  }
}

function latin1ToBytes(s) {
  const out = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i) & 0xff;
  return out;
}

/** Decode a text part's bytes using its declared charset. */
function decodeText(part) {
  let text;
  try {
    text = new TextDecoder(part.charset, { fatal: false }).decode(part.bytes);
  } catch {
    text = new TextDecoder("utf-8", { fatal: false }).decode(part.bytes);
  }
  return part.mime === "text/html" ? text : text;
}

/**
 * Strip HTML tags and decode entities
 */
function stripHtml(html) {
  return html
    .replace(/<script[^>]*>[\s\S]*?<\/script>/gi, "")
    .replace(/<style[^>]*>[\s\S]*?<\/style>/gi, "")
    .replace(/<[^>]+>/g, " ")
    .replace(/&nbsp;/gi, " ")
    .replace(/&#(\d+);/g, (m, num) => String.fromCharCode(num))
    .replace(/&#x([0-9a-f]+);/gi, (m, hex) =>
      String.fromCharCode(parseInt(hex, 16)),
    )
    .replace(/&amp;/gi, "&")
    .replace(/&lt;/gi, "<")
    .replace(/&gt;/gi, ">")
    .replace(/&quot;/gi, '"')
    .replace(/&#39;/gi, "'")
    .replace(/\s+/g, " ")
    .trim();
}

/**
 * Extract links from HTML: anchors, plus remote resources the message loads on
 * open (tracking pixels, remote images, scripts, frames). Those resources are
 * IOCs in their own right and often carry the recipient's identity.
 */
function extractLinksFromHtml(html) {
  const links = [];

  // [\s\S]*? so anchors wrapping other markup (<a><span>…</span></a>) are
  // still captured; the old [^<]* silently skipped them.
  const linkPattern = /<a\b[^>]*?\bhref\s*=\s*["']([^"']+)["'][^>]*>([\s\S]*?)<\/a>/gi;
  let match;
  while ((match = linkPattern.exec(html)) !== null) {
    const href = decodeEntities(match[1].trim());
    const text = stripHtml(match[2]).trim();
    links.push({
      href,
      text: text || href,
      isMismatch: isDeceptiveLink(text, href),
    });
  }

  const resourcePattern =
    /<(?:img|script|iframe|embed|source|input|body|table|td)\b[^>]*?\b(?:src|background)\s*=\s*["'](https?:\/\/[^"']+)["']/gi;
  while ((match = resourcePattern.exec(html)) !== null) {
    links.push({
      href: decodeEntities(match[1].trim()),
      text: "",
      isMismatch: false,
      resource: true,
    });
  }

  return links;
}

/**
 * A link is deceptive only when its visible text itself looks like a link and
 * points somewhere else. "View invoice" is ordinary link text; flagging it made
 * every newsletter look like phishing. The destination is compared after
 * unwrapping, so a gateway rewrite (Safe Links) is not itself a mismatch but a
 * rewrite hiding a different domain is.
 */
function isDeceptiveLink(text, href) {
  if (!text || /^(mailto|tel|#)/i.test(href)) return false;
  const shown = hostOf(text);
  if (!shown) return false;
  const unwrapped = unwrapRedirect(href);
  const real = hostOf(unwrapped ? unwrapped.output : href);
  if (!real) return false;
  return orgDomain(shown) !== orgDomain(real);
}

function hostOf(value) {
  const t = String(value).trim();
  let candidate = null;
  if (/^https?:\/\//i.test(t)) candidate = t;
  else if (/^(www\.)?[a-z0-9-]+(\.[a-z0-9-]+)+(\/\S*)?$/i.test(t)) candidate = `http://${t}`;
  if (!candidate) return null;
  try {
    return new URL(candidate).hostname.toLowerCase().replace(/^www\./, "");
  } catch {
    return null;
  }
}

function decodeEntities(s) {
  return htmlEntityDecode(s)?.output ?? s;
}

/**
 * Extract links from plain text
 */
function extractLinksFromText(text) {
  const links = [];
  const urlPattern = /https?:\/\/[^\s<>"]+/gi;
  let match;

  while ((match = urlPattern.exec(text)) !== null) {
    links.push({
      href: match[0],
      text: match[0],
      isMismatch: false,
    });
  }

  return links;
}
