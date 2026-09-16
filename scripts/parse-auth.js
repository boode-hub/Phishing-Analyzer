// Authentication Parsing Module
// SPF/DKIM/DMARC parsing and DMARC-style domain alignment

import { isValidIP, isPrivateIP, isRoutableIP, findIPs } from "./ip-utils.js";
//
// Design notes, because the accuracy of this file is the accuracy of the tool:
//
// 1. Authentication-Results headers are PREPENDED by each relay, so index 0 is
//    the one your own receiving MTA wrote. Only that one is trustworthy —
//    anything below it was supplied by an upstream host and can be forged
//    outright by the sender. We evaluate the topmost and treat the rest as
//    informational, flagging disagreements.
// 2. Results are read per-clause, not by scanning the whole header. A bare
//    /spf=(\w+)/ over the full string will happily pick up "spf=pass" out of a
//    DKIM clause's comment text.
// 3. Received-SPF's result is the FIRST TOKEN of the value (RFC 7208 §9.1),
//    not "result=pass". The latter is a Microsoft-ism we also accept.
// 4. Alignment follows DMARC (RFC 7489 §3.1): SPF aligns Return-Path against
//    From, DKIM aligns d= against From, and relaxed mode compares
//    organizational domains. Reply-To is NOT part of DMARC and is reported
//    separately as a weak heuristic.

// Every result value SPF and DKIM/DMARC can legitimately produce.
const SPF_RESULTS = new Set([
  "pass",
  "fail",
  "softfail",
  "neutral",
  "none",
  "temperror",
  "permerror",
]);

// ponytail: compact public-suffix list, not the real PSL. Covers the
// multi-part suffixes that show up in mail; anything else falls back to the
// last two labels. Swap in the published PSL if false alignment results on
// exotic ccTLDs ever show up.
const MULTI_PART_SUFFIXES = new Set([
  "co.uk", "org.uk", "ac.uk", "gov.uk", "net.uk", "sch.uk", "me.uk", "ltd.uk",
  "com.au", "net.au", "org.au", "edu.au", "gov.au", "id.au",
  "co.nz", "net.nz", "org.nz", "govt.nz", "ac.nz",
  "co.za", "org.za", "net.za", "gov.za", "ac.za",
  "co.jp", "ne.jp", "or.jp", "ac.jp", "go.jp", "ad.jp",
  "com.br", "net.br", "org.br", "gov.br", "edu.br",
  "com.cn", "net.cn", "org.cn", "gov.cn", "edu.cn", "ac.cn",
  "co.in", "net.in", "org.in", "gen.in", "firm.in", "ind.in", "gov.in",
  "com.mx", "com.ar", "com.co", "com.pe", "com.ve", "com.ec", "com.uy",
  "com.sg", "com.hk", "com.tw", "com.my", "com.ph", "com.vn", "com.bd",
  "com.tr", "com.pl", "com.ua", "com.ru", "org.ru", "net.ru",
  "co.kr", "or.kr", "ne.kr", "go.kr",
  "co.il", "org.il", "net.il", "ac.il", "gov.il",
  "co.th", "in.th", "ac.th", "go.th",
  "co.id", "or.id", "ac.id", "go.id", "web.id",
  "com.sa", "com.eg", "com.ng", "com.pk", "com.kw", "com.qa",
  "co.ke", "co.tz", "co.ug",
  "com.es", "com.pt", "com.gr", "com.ro", "com.hr", "com.cy",
]);

/**
 * Parse authentication results from headers
 * @param {Object} headers - Parsed headers object
 * @returns {Object} Authentication analysis
 */
export function parseAuth(headers) {
  const arRaw = asArray(headers.authenticationResults);
  const spfRaw = asArray(headers.receivedSpf);
  const dkimSigs = asArray(headers.dkimSignature);

  const arAll = arRaw.map(parseAuthResults).filter(Boolean);
  const authoritative = arAll[0] || null;
  const lower = arAll.slice(1);

  const receivedSpf = spfRaw.map(parseReceivedSpf).filter(Boolean);
  const signatures = dkimSigs.map(parseDkimSignature).filter(Boolean);

  const spf = resolveSPF(authoritative, receivedSpf);
  const dkim = resolveDKIM(authoritative, signatures);
  const dmarc = resolveDMARC(authoritative);

  const domainAlignment = checkDomainAlignment(headers, signatures, spf, dkim);
  const receivedChain = parseReceivedChain(headers.received);
  const senderIp = resolveSenderIp(receivedChain);

  const trust = assessHeaderTrust(authoritative, lower, arAll, headers);

  const overallStatus = determineOverallStatus({
    spf,
    dkim,
    dmarc,
    domainAlignment,
    trust,
  });

  return {
    mechanisms: {
      spf: { status: spf.status, details: spf.details, source: spf.source },
      dkim: { status: dkim.status, details: dkim.details, source: dkim.source },
      dmarc: {
        status: dmarc.status,
        details: dmarc.details,
        source: dmarc.source,
      },
    },
    spf,
    dkim,
    dmarc,
    signatures,
    domainAlignment,
    receivedChain,
    senderIp,
    trust,
    overallStatus,
  };
}

// ===== Authentication-Results (RFC 8601) =====

/**
 * Parse one Authentication-Results header into its authserv-id and a map of
 * method -> [{ result, props }]. A method can appear more than once (two DKIM
 * signatures, for instance), so each maps to a list.
 */
function parseAuthResults(raw) {
  if (!raw || typeof raw !== "string") return null;

  const segments = splitClauses(raw);
  const idSegment = (segments.shift() || "").trim();
  // authserv-id is the first token; an optional version number may follow.
  const authservId = idSegment.split(/\s+/)[0] || null;

  const methods = {};
  for (const segment of segments) {
    // Comments may contain anything at all, including "spf=pass" prose from
    // the upstream MTA. Strip them before reading properties.
    const clean = stripComments(segment).trim();
    if (!clean) continue;

    const m = clean.match(/^([a-z][a-z0-9-]*)\s*=\s*([a-z]+)/i);
    if (!m) continue;

    const method = m[1].toLowerCase();
    const result = m[2].toLowerCase();

    const props = {};
    const propRe = /\b([a-z]+)\.([a-z0-9-]+)\s*=\s*("[^"]*"|[^\s;]+)/gi;
    let p;
    while ((p = propRe.exec(clean)) !== null) {
      const key = `${p[1].toLowerCase()}.${p[2].toLowerCase()}`;
      props[key] = p[3].replace(/^"|"$/g, "");
    }

    (methods[method] = methods[method] || []).push({
      result,
      props,
      raw: segment.trim(),
    });
  }

  return { authservId, methods, raw };
}

/**
 * Split an Authentication-Results value on top-level semicolons. Semicolons
 * inside comments or quoted strings do not separate clauses.
 */
function splitClauses(s) {
  const out = [];
  let cur = "";
  let depth = 0;
  let inQuote = false;

  for (let i = 0; i < s.length; i++) {
    const c = s[i];
    if (inQuote) {
      cur += c;
      if (c === '"' && s[i - 1] !== "\\") inQuote = false;
      continue;
    }
    if (c === '"') {
      inQuote = true;
      cur += c;
      continue;
    }
    if (c === "(") {
      depth++;
      cur += c;
      continue;
    }
    if (c === ")") {
      if (depth > 0) depth--;
      cur += c;
      continue;
    }
    if (c === ";" && depth === 0) {
      out.push(cur);
      cur = "";
      continue;
    }
    cur += c;
  }
  out.push(cur);
  return out;
}

/** Remove (possibly nested) RFC 5322 comments. */
function stripComments(s) {
  let out = "";
  let depth = 0;
  for (let i = 0; i < s.length; i++) {
    const c = s[i];
    if (c === "(") depth++;
    else if (c === ")") {
      if (depth > 0) depth--;
    } else if (depth === 0) out += c;
  }
  return out;
}

// ===== Received-SPF (RFC 7208 §9.1) =====

/**
 * Received-SPF: <result> (optional comment) key=value; key=value
 * The result is the first token. Some MTAs (notably Microsoft) instead write
 * "result=pass" among the key/value pairs, so we accept that too.
 */
function parseReceivedSpf(raw) {
  if (!raw || typeof raw !== "string") return null;

  let result = null;
  const leading = raw.match(/^\s*([A-Za-z]+)/);
  if (leading && SPF_RESULTS.has(leading[1].toLowerCase())) {
    result = leading[1].toLowerCase();
  } else {
    const alt = stripComments(raw).match(/\bresult\s*=\s*"?([A-Za-z]+)"?/i);
    if (alt && SPF_RESULTS.has(alt[1].toLowerCase())) {
      result = alt[1].toLowerCase();
    }
  }
  if (!result) return null;

  const clean = stripComments(raw);
  return {
    result,
    clientIp: matchValue(clean, /client-ip\s*=\s*"?([^\s;"]+)/i),
    envelopeFrom: matchValue(clean, /envelope-from\s*=\s*"?([^\s;"]+)/i),
    helo: matchValue(clean, /helo\s*=\s*"?([^\s;"]+)/i),
    raw,
  };
}

// ===== DKIM-Signature =====

function parseDkimSignature(raw) {
  if (!raw || typeof raw !== "string") return null;
  const tags = {};
  for (const part of raw.split(";")) {
    const eq = part.indexOf("=");
    if (eq === -1) continue;
    const k = part.slice(0, eq).trim().toLowerCase();
    if (!k) continue;
    tags[k] = part.slice(eq + 1).trim();
  }
  if (!tags.d) return null;
  return {
    domain: tags.d.toLowerCase(),
    selector: tags.s || null,
    algorithm: tags.a || null,
    identity: tags.i || null,
    raw,
  };
}

// ===== Mechanism resolution =====

function resolveSPF(authoritative, receivedSpf) {
  const clause = authoritative?.methods?.spf?.[0];
  if (clause) {
    // RFC 8601 records the checked identity as smtp.mailfrom (or smtp.helo
    // when the MAIL FROM was empty, e.g. bounces).
    const identity =
      clause.props["smtp.mailfrom"] || clause.props["smtp.helo"] || null;
    return {
      status: normalizeAuthStatus(clause.result),
      rawResult: clause.result,
      identity,
      domain: identity ? domainPart(identity) : null,
      source: `Authentication-Results (${authoritative.authservId || "unknown"})`,
      details: identity ? `${clause.result} — ${identity}` : clause.result,
    };
  }

  if (receivedSpf.length) {
    const r = receivedSpf[0];
    const identity = r.envelopeFrom || r.helo || null;
    const bits = [r.clientIp && `client-ip=${r.clientIp}`, identity]
      .filter(Boolean)
      .join(", ");
    return {
      status: normalizeAuthStatus(r.result),
      rawResult: r.result,
      identity,
      domain: identity ? domainPart(identity) : null,
      clientIp: r.clientIp,
      source: "Received-SPF",
      details: bits ? `${r.result} — ${bits}` : r.result,
    };
  }

  return {
    status: "unknown",
    rawResult: null,
    identity: null,
    domain: null,
    source: null,
    details: "No SPF result published by the receiving server",
  };
}

function resolveDKIM(authoritative, signatures) {
  const clauses = authoritative?.methods?.dkim || [];

  if (clauses.length) {
    // With several signatures, a single pass is what DKIM requires — report
    // the passing one, since that is what DMARC will evaluate.
    const passing = clauses.find((c) => normalizeAuthStatus(c.result) === "pass");
    const chosen = passing || clauses[0];
    const domain =
      chosen.props["header.d"] ||
      chosen.props["header.i"]?.replace(/^@/, "") ||
      signatures[0]?.domain ||
      null;
    return {
      status: normalizeAuthStatus(chosen.result),
      rawResult: chosen.result,
      domain: domain ? domain.toLowerCase() : null,
      domains: clauses
        .map((c) => c.props["header.d"])
        .filter(Boolean)
        .map((d) => d.toLowerCase()),
      signatureCount: signatures.length,
      source: `Authentication-Results (${authoritative.authservId || "unknown"})`,
      details: domain ? `${chosen.result} — d=${domain}` : chosen.result,
    };
  }

  if (signatures.length) {
    // A signature is present but nothing verified it. That is not a pass and
    // not a failure — it is simply unverified.
    return {
      status: "unverified",
      rawResult: null,
      domain: signatures[0].domain,
      domains: signatures.map((s) => s.domain),
      signatureCount: signatures.length,
      source: "DKIM-Signature header",
      details: `Signature present (d=${signatures[0].domain}) but no verification result`,
    };
  }

  return {
    status: "none",
    rawResult: null,
    domain: null,
    domains: [],
    signatureCount: 0,
    source: null,
    details: "Message carries no DKIM signature",
  };
}

function resolveDMARC(authoritative) {
  const clause = authoritative?.methods?.dmarc?.[0];
  if (!clause) {
    return {
      status: "unknown",
      rawResult: null,
      policy: null,
      source: null,
      details: "No DMARC result published by the receiving server",
    };
  }
  const policy = clause.props["header.p"] || null;
  const from = clause.props["header.from"] || null;
  const bits = [from && `header.from=${from}`, policy && `p=${policy}`]
    .filter(Boolean)
    .join(", ");
  return {
    status: normalizeAuthStatus(clause.result),
    rawResult: clause.result,
    policy,
    fromDomain: from,
    source: `Authentication-Results (${authoritative.authservId || "unknown"})`,
    details: bits ? `${clause.result} — ${bits}` : clause.result,
  };
}

/**
 * Normalize a result token. Unlike the previous version this keeps neutral,
 * temperror and permerror distinct: a temporary DNS error is not a pass, and a
 * broken SPF record is not the same as a forged sender.
 */
function normalizeAuthStatus(status) {
  if (!status) return "unknown";
  const s = String(status).toLowerCase();
  const known = [
    "pass",
    "fail",
    "softfail",
    "neutral",
    "none",
    "temperror",
    "permerror",
    "policy",
  ];
  return known.includes(s) ? s : "unknown";
}

// ===== Domain alignment (DMARC RFC 7489 §3.1) =====

/**
 * Reduce a hostname to its organizational domain (eTLD+1).
 */
export function orgDomain(domain) {
  if (!domain) return null;
  const parts = String(domain)
    .toLowerCase()
    .replace(/\.$/, "")
    .split(".")
    .filter(Boolean);
  if (parts.length <= 2) return parts.join(".") || null;
  const lastTwo = parts.slice(-2).join(".");
  if (MULTI_PART_SUFFIXES.has(lastTwo)) return parts.slice(-3).join(".");
  return lastTwo;
}

function checkDomainAlignment(headers, signatures, spf, dkim) {
  const fromDomain = domainPart(headers.from?.email);
  const fromOrg = orgDomain(fromDomain);

  // SPF aligns the envelope sender. Prefer the identity the receiving server
  // actually checked; fall back to Return-Path when it did not say.
  const envelopeDomain =
    spf.domain || domainPart(headers.returnPath?.email) || null;
  const replyToDomain = domainPart(headers.replyTo?.email);

  const entries = [];

  if (envelopeDomain) {
    entries.push(
      buildAlignment(
        "Return-Path",
        envelopeDomain,
        fromDomain,
        fromOrg,
        true,
        spf.status === "pass",
        "SPF alignment: the envelope sender DMARC checks against From",
      ),
    );
  }

  // The signing domains DMARC evaluates come from the receiving server's
  // verification result (header.d) when it published one; the raw
  // DKIM-Signature headers are the fallback for messages nobody verified.
  const dkimDomains = dkim?.domains?.length
    ? dkim.domains
    : signatures.map((s) => s.domain);
  const uniqueDkimDomains = [...new Set(dkimDomains.filter(Boolean))];

  for (const domain of uniqueDkimDomains) {
    const selector = signatures.find((s) => s.domain === domain)?.selector;
    entries.push(
      buildAlignment(
        uniqueDkimDomains.length > 1 ? `DKIM (${selector || domain})` : "DKIM",
        domain,
        fromDomain,
        fromOrg,
        true,
        dkim?.status === "pass",
        "DKIM alignment: the signing domain DMARC checks against From",
      ),
    );
  }

  // Reply-To is deliberately NOT a DMARC input. Legitimate mail routinely
  // replies to a different domain (no-reply@ -> support@, ticketing systems,
  // mailing lists), so a mismatch here is a weak hint, never an auth failure.
  if (replyToDomain) {
    entries.push(
      buildAlignment(
        "Reply-To",
        replyToDomain,
        fromDomain,
        fromOrg,
        false,
        false,
        "Not used by DMARC — informational only",
      ),
    );
  }

  // Kept for the renderer's simple source -> domain table.
  const domains = {};
  const aligned = {};
  if (fromDomain) {
    domains.From = fromDomain;
    aligned.From = true;
  }
  for (const e of entries) {
    domains[e.source] = e.domain;
    aligned[e.source] = e.aligned;
  }

  const dmarcEntries = entries.filter((e) => e.dmarcRelevant);
  const mismatches = dmarcEntries
    .filter((e) => !e.aligned)
    .map(
      (e) =>
        `${e.source} domain (${e.domain}) is not aligned with From domain (${fromDomain})`,
    );

  // DMARC passes on (SPF passed AND aligned) OR (DKIM passed AND aligned) —
  // either one suffices, but alignment alone is not enough: a mechanism that
  // aligned while failing to verify proves nothing.
  const dmarcAligned = dmarcEntries.length
    ? dmarcEntries.some((e) => e.aligned && e.mechanismPassed)
    : null;

  const replyToEntry = entries.find((e) => e.source === "Reply-To");

  return {
    fromDomain,
    fromOrgDomain: fromOrg,
    entries,
    domains,
    aligned,
    mismatches,
    dmarcAligned,
    replyToMismatch: replyToEntry ? !replyToEntry.aligned : false,
    replyToDomain,
    mismatchWarning: mismatches.length
      ? `Domain alignment failure: ${mismatches.join("; ")}`
      : null,
  };
}

function buildAlignment(
  source,
  domain,
  fromDomain,
  fromOrg,
  dmarcRelevant,
  mechanismPassed,
  note,
) {
  const org = orgDomain(domain);
  const strict = !!fromDomain && domain.toLowerCase() === fromDomain.toLowerCase();
  // Relaxed alignment is symmetric: mail.example.com and example.com share an
  // organizational domain regardless of which one appears in From.
  const relaxed = !!fromOrg && !!org && org === fromOrg;
  return {
    source,
    domain,
    orgDomain: org,
    strict,
    relaxed,
    aligned: strict || relaxed,
    mode: strict ? "strict" : relaxed ? "relaxed" : "none",
    dmarcRelevant,
    mechanismPassed: !!mechanismPassed,
    note,
  };
}

// ===== Header trust =====

/**
 * Only the topmost Authentication-Results is written by our own MTA. Report
 * what we relied on, and warn when a lower (sender-supplied) header disagrees
 * with it — that is a deliberate spoofing pattern, not an accident.
 */
function assessHeaderTrust(authoritative, lower, all, headers) {
  const warnings = [];

  if (all.length > 1) {
    for (const method of ["spf", "dkim", "dmarc"]) {
      const top = authoritative?.methods?.[method]?.[0]?.result;
      if (!top) continue;
      for (const other of lower) {
        const claim = other.methods?.[method]?.[0]?.result;
        if (!claim) continue;
        if (
          normalizeAuthStatus(claim) === "pass" &&
          normalizeAuthStatus(top) !== "pass"
        ) {
          warnings.push(
            `A lower Authentication-Results header claims ${method.toUpperCase()}=${claim} while the receiving server recorded ${method.toUpperCase()}=${top}. Lower headers can be forged by the sender.`,
          );
        }
      }
    }
  }

  for (const dup of headers.duplicated || []) {
    warnings.push(
      `${dup.count} ${formatHeaderName(dup.header)} headers present — a message should carry only one.`,
    );
  }

  return {
    authservId: authoritative?.authservId || null,
    authResultsCount: all.length,
    usedTopmost: all.length > 0,
    warnings,
  };
}

function formatHeaderName(k) {
  return k
    .split("-")
    .map((w) => w.charAt(0).toUpperCase() + w.slice(1))
    .join("-");
}

// ===== Received chain =====

/**
 * Parse Received headers into an ordered chain.
 *
 * Received headers are prepended, so array index 0 is the LAST hop (your own
 * server) and the final element is where the message originated. Hop 1 in the
 * output is the origin, so the chain reads in the direction the mail travelled.
 */
function parseReceivedChain(receivedHeaders) {
  const headers = asArray(receivedHeaders);
  const total = headers.length;

  const hops = headers.map((header, index) => {
    const clean = String(header);
    const hop = {
      number: total - index,
      isOrigin: index === total - 1,
      raw: clean,
      from: null,
      by: null,
      date: null,
      ip: null,
      privateIp: false,
      suspicious: false,
      warnings: [],
    };

    // Prefer a bracketed address (what the receiving server actually saw),
    // then any valid address in the from-clause, then anywhere in the header.
    // Each candidate is validated: a Received header is full of dotted-quad
    // lookalikes — queue ids, versions, timestamps — and the old pattern
    // accepted anything shaped like four numbers, including "15.21.360.10".
    const bracketed = [...clean.matchAll(/\[([^\]]+)\]/g)]
      .map((m) => m[1].replace(/^IPv6:/i, "").trim())
      .find(isValidIP);

    if (bracketed) {
      hop.ip = bracketed;
    } else {
      const fromClause = clean.match(/\bfrom\b([^;]*)/i)?.[1] || "";
      hop.ip = findIPs(fromClause)[0] || findIPs(clean)[0] || null;
    }

    const fromMatch = clean.match(/\bfrom\s+([^\s;()\[\]]+)/i);
    if (fromMatch) hop.from = fromMatch[1];

    const byMatch = clean.match(/\bby\s+([^\s;()\[\]]+)/i);
    if (byMatch) hop.by = byMatch[1];

    // The timestamp is the last semicolon-separated field.
    const semi = clean.lastIndexOf(";");
    if (semi !== -1) {
      const candidate = clean.slice(semi + 1).trim();
      const parsed = Date.parse(candidate);
      hop.date = candidate || null;
      hop.timestamp = Number.isNaN(parsed) ? null : parsed;
    }

    hop.privateIp = isPrivateIP(hop.ip);
    return hop;
  });

  // The previous heuristic flagged any hop whose hostname did not end in
  // .com/.org/.net, which marked every legitimate .io, .co.uk and .dev relay as
  // suspicious. These two checks are things that are actually wrong.
  for (let i = 0; i < hops.length; i++) {
    const hop = hops[i];

    if (hop.isOrigin && hop.privateIp && hops.length > 1) {
      hop.warnings.push(
        "Message originated from a private/reserved IP address",
      );
    }

    // Time must not run backwards as the message moves toward us.
    const next = hops[i - 1]; // the hop that received it after this one
    if (next && hop.timestamp && next.timestamp) {
      if (next.timestamp < hop.timestamp - 60000) {
        hop.warnings.push("Timestamp is later than the hop that follows it");
      }
    }

    hop.suspicious = hop.warnings.length > 0;
  }

  return hops;
}


/**
 * Work out the sender's public IP from the Received chain.
 *
 * Received headers are prepended, so the last entry is where the message
 * originated — and that hop very often records a private address: the sender's
 * workstation behind NAT, or an internal submission relay. A private address
 * identifies nobody and cannot be looked up, so keep it for the internal trail
 * but keep walking outward (toward the receiving end) until a routable address
 * appears. That is where the message actually left the sender's network, and
 * the address worth checking against reputation data.
 */
export function resolveSenderIp(chain) {
  const result = {
    publicIp: null,
    publicHop: null,
    privateIp: null,
    originIp: null,
    privateHopsSkipped: 0,
  };
  if (!Array.isArray(chain)) return result;

  // Walk from the origin (end of the array) toward the receiving server.
  for (let i = chain.length - 1; i >= 0; i--) {
    const hop = chain[i];
    if (!isValidIP(hop.ip)) continue;

    if (result.originIp === null) {
      result.originIp = hop.ip;
      if (isPrivateIP(hop.ip)) result.privateIp = hop.ip;
    } else if (isPrivateIP(hop.ip)) {
      result.privateHopsSkipped++;
    }

    if (isRoutableIP(hop.ip)) {
      result.publicIp = hop.ip;
      result.publicHop = hop;
      break;
    }
  }

  return result;
}

// ===== Overall status =====

function determineOverallStatus(auth) {
  const issues = [];
  let failures = 0;
  let softIssues = 0;

  const spf = auth.spf.status;
  if (spf === "fail") {
    issues.push("SPF check failed — sending server is not authorized");
    failures++;
  } else if (spf === "softfail") {
    issues.push("SPF soft-failed — sending server is not authorized");
    softIssues++;
  } else if (spf === "permerror") {
    issues.push("SPF record is malformed (permerror)");
    softIssues++;
  } else if (spf === "temperror") {
    issues.push("SPF could not be evaluated (temporary DNS error)");
  } else if (spf === "none") {
    issues.push("Sending domain publishes no SPF record");
    softIssues++;
  }

  const dkim = auth.dkim.status;
  if (dkim === "fail") {
    issues.push("DKIM signature failed verification");
    failures++;
  } else if (dkim === "none") {
    issues.push("Message is not DKIM signed");
    softIssues++;
  } else if (dkim === "permerror") {
    issues.push("DKIM signature is malformed (permerror)");
    softIssues++;
  }

  const dmarc = auth.dmarc.status;
  if (dmarc === "fail") {
    issues.push("DMARC evaluation failed");
    failures++;
  } else if (dmarc === "none") {
    issues.push("Sending domain publishes no DMARC policy");
    softIssues++;
  }

  // This is the check that never ran before: `aligned` is an object, and an
  // object is always truthy, so `!auth.domainAlignment.aligned` was dead.
  if (auth.domainAlignment.dmarcAligned === false) {
    issues.push(...auth.domainAlignment.mismatches);
    failures++;
  }

  if (auth.domainAlignment.replyToMismatch) {
    issues.push(
      `Reply-To points at a different domain (${auth.domainAlignment.replyToDomain})`,
    );
    softIssues++;
  }

  for (const w of auth.trust.warnings) {
    issues.push(w);
    softIssues++;
  }

  if (failures >= 2) return { level: "fail", issues, failures, softIssues };
  if (failures === 1 || softIssues >= 2)
    return { level: "suspicious", issues, failures, softIssues };
  if (issues.length) return { level: "suspicious", issues, failures, softIssues };
  return { level: "pass", issues: [], failures: 0, softIssues: 0 };
}

// ===== helpers =====

function asArray(v) {
  if (v == null) return [];
  return Array.isArray(v) ? v : [v];
}

function domainPart(address) {
  if (!address) return null;
  const at = String(address).lastIndexOf("@");
  if (at === -1) return null;
  const d = address
    .slice(at + 1)
    .replace(/[>\s;,]+$/, "")
    .toLowerCase();
  return d || null;
}

function matchValue(s, re) {
  const m = s.match(re);
  return m ? m[1] : null;
}
