// Comparison model
//
// Phishing arrives as a campaign: ten messages that look unrelated until you
// put them next to each other and notice they all left the same IP, or carry
// the same attachment, or were all signed by a domain registered last week.
// This module turns a set of analyses into one table — messages as columns,
// properties as rows — and works out which values are shared, which is the part
// an analyst cannot see by opening the messages one at a time.
//
// Pure data: no DOM, so it is testable on its own.

import { orgDomain } from "./parse-auth.js";
import { defangUrl, defangDomain, defangIp, defangEmail } from "./report.js";

const dash = "—";
const text = (value) => (value == null || value === "" ? dash : String(value));

/** Every row of the comparison, in the order an analyst reads them. */
const FIELDS = [
  {
    key: "verdict",
    label: "Verdict",
    get: (a) => (a.score ? `${a.score.tier} · ${a.score.score}/100` : dash),
    tone: (a) =>
      a.score?.tier === "High Risk" ? "bad" : a.score?.tier === "Suspicious" ? "warn" : "good",
  },
  { key: "topReason", label: "Main reason", get: (a) => (a.score?.reasons || [])[0] || dash },
  {
    key: "spf",
    label: "SPF",
    get: (a) => (a.auth?.mechanisms?.spf?.status || "unknown").toUpperCase(),
    tone: (a) => statusTone(a.auth?.mechanisms?.spf?.status),
  },
  {
    key: "dkim",
    label: "DKIM",
    get: (a) => (a.auth?.mechanisms?.dkim?.status || "unknown").toUpperCase(),
    tone: (a) => statusTone(a.auth?.mechanisms?.dkim?.status),
  },
  {
    key: "dmarc",
    label: "DMARC",
    get: (a) => (a.auth?.mechanisms?.dmarc?.status || "unknown").toUpperCase(),
    tone: (a) => statusTone(a.auth?.mechanisms?.dmarc?.status),
  },
  {
    key: "alignment",
    label: "DMARC alignment",
    get: (a) =>
      a.auth?.domainAlignment?.dmarcAligned === true
        ? "Aligned"
        : a.auth?.domainAlignment?.dmarcAligned === false
          ? "Not aligned"
          : "No data",
    tone: (a) =>
      a.auth?.domainAlignment?.dmarcAligned === true
        ? "good"
        : a.auth?.domainAlignment?.dmarcAligned === false
          ? "bad"
          : "muted",
  },
  {
    key: "identity",
    label: "Identity findings",
    get: (a) => {
      const f = a.identity?.findings || [];
      return f.length ? f.map((x) => x.title).join("; ") : "None";
    },
    tone: (a) => ((a.identity?.findings || []).some((f) => f.severity === "high") ? "bad" : "muted"),
  },
  { key: "from", label: "From", get: (a) => text(a.headers?.from?.email), correlate: "from" },
  { key: "fromDomain", label: "From domain", get: (a) => text(domainOf(a.headers?.from?.email)), correlate: "domain" },
  { key: "displayName", label: "Display name", get: (a) => text(a.headers?.from?.name), correlate: "displayName" },
  { key: "replyTo", label: "Reply-To", get: (a) => text(a.headers?.replyTo?.email), correlate: "replyTo" },
  { key: "returnPath", label: "Return-Path", get: (a) => text(a.headers?.returnPath?.email) },
  { key: "subject", label: "Subject", get: (a) => text(a.headers?.subject), correlate: "subject" },
  { key: "date", label: "Date", get: (a) => text(a.headers?.date) },
  {
    key: "senderIp",
    label: "Sender IP",
    get: (a) => text(a.auth?.senderIp?.publicIp),
    correlate: "ip",
  },
  { key: "originHost", label: "Origin host", get: (a) => text(a.auth?.senderIp?.publicHop?.from) },
  {
    key: "messageIdDomain",
    label: "Message-ID domain",
    get: (a) => text(String(a.headers?.messageId || "").match(/@([^>\s]+)/)?.[1]),
    correlate: "messageIdDomain",
  },
  { key: "mailer", label: "X-Mailer", get: (a) => text(a.headers?.xMailer), correlate: "mailer" },
  {
    key: "urlCount",
    label: "Links",
    get: (a) => String((a.iocs?.urls || []).length),
  },
  {
    key: "urlDomains",
    label: "Link domains",
    get: (a) => {
      const domains = [...new Set((a.iocs?.urls || []).map((u) => hostOf(u.value)).filter(Boolean))];
      return domains.length ? domains.slice(0, 6).join(", ") + (domains.length > 6 ? ` +${domains.length - 6}` : "") : dash;
    },
  },
  {
    key: "deceptive",
    label: "Deceptive links",
    get: (a) => String((a.iocs?.mismatchedLinks || []).length),
    tone: (a) => ((a.iocs?.mismatchedLinks || []).length ? "bad" : "muted"),
  },
  {
    key: "attachments",
    label: "Attachments",
    get: (a) => {
      const files = a.iocs?.attachments || [];
      return files.length ? files.map((f) => f.value).join(", ") : "None";
    },
    tone: (a) => ((a.iocs?.attachments || []).some((f) => f.risky) ? "bad" : "muted"),
  },
  {
    key: "hashes",
    label: "File SHA-256",
    get: (a) => {
      const hashes = (a.iocs?.attachments || []).map((f) => f.sha256).filter(Boolean);
      return hashes.length ? hashes.join(", ") : dash;
    },
    correlate: "hash",
  },
  {
    key: "language",
    label: "Language flags",
    get: (a) => {
      const cats = Object.entries(a.languageAnalysis?.categories || {}).filter(([, c]) => c.matchCount);
      return cats.length ? cats.map(([, c]) => `${c.label}: ${c.matchCount}`).join("; ") : "None";
    },
    tone: (a) => ((a.languageAnalysis?.categories?.bec?.matchCount || 0) >= 2 ? "bad" : "muted"),
  },
  {
    key: "anomalies",
    label: "Header anomalies",
    get: (a) => {
      const list = a.auth?.anomalies || [];
      return list.length ? list.map((x) => x.message).join(" ") : "None";
    },
    tone: (a) => ((a.auth?.anomalies || []).length ? "warn" : "muted"),
  },
  {
    key: "trust",
    label: "Trust warnings",
    get: (a) => {
      const list = a.auth?.trust?.warnings || [];
      return list.length ? String(list.length) : "None";
    },
    tone: (a) => ((a.auth?.trust?.warnings || []).length ? "bad" : "muted"),
  },
  { key: "arc", label: "ARC", get: (a) => (a.auth?.arc?.present ? `${a.auth.arc.sets} set(s)` : "None") },
];

function statusTone(status) {
  if (status === "pass") return "good";
  if (status === "fail") return "bad";
  if (["softfail", "permerror", "unverified"].includes(status)) return "warn";
  return "muted";
}

function domainOf(email) {
  if (!email || !email.includes("@")) return null;
  return email.split("@").pop().toLowerCase();
}

function hostOf(url) {
  try {
    return new URL(url).hostname.toLowerCase().replace(/^www\./, "");
  } catch {
    return null;
  }
}

/** Subjects differ only by a name or a number within one campaign. */
function subjectKey(subject) {
  return String(subject || "")
    .toLowerCase()
    .replace(/^\s*(re|fw|fwd)\s*:\s*/i, "")
    .replace(/\d+/g, "#")
    .replace(/\s+/g, " ")
    .trim();
}

/**
 * Everything worth correlating, per message: the values that tie two messages
 * to the same sender, the same infrastructure or the same payload.
 */
export function indicatorsOf(analysis) {
  const out = [];
  const add = (type, value, label) => {
    if (value) out.push({ type, value: String(value).toLowerCase(), label: label || type });
  };

  add("from", analysis.headers?.from?.email, "Sender address");
  add("domain", domainOf(analysis.headers?.from?.email), "Sender domain");
  const org = orgDomain(domainOf(analysis.headers?.from?.email));
  if (org && org !== domainOf(analysis.headers?.from?.email)) add("domain", org, "Sender domain");
  add("replyTo", analysis.headers?.replyTo?.email, "Reply-To");
  add("displayName", analysis.headers?.from?.name, "Display name");
  add("ip", analysis.auth?.senderIp?.publicIp, "Sender IP");
  add("subject", subjectKey(analysis.headers?.subject), "Subject pattern");
  add("messageIdDomain", String(analysis.headers?.messageId || "").match(/@([^>\s]+)/)?.[1], "Message-ID domain");
  add("mailer", analysis.headers?.xMailer, "X-Mailer");

  for (const url of analysis.iocs?.urls || []) {
    add("urlDomain", hostOf(url.value), "Link domain");
    add("url", url.value, "Link");
  }
  for (const file of analysis.iocs?.attachments || []) {
    add("hash", file.sha256, "File hash");
    add("filename", file.value, "File name");
  }
  return out;
}

/**
 * Values that appear in more than one message, strongest first. This is the
 * campaign view: one shared sender IP or file hash ties messages together even
 * when every other detail was changed.
 */
export function sharedIndicators(items) {
  const weight = {
    hash: 100, ip: 90, url: 80, urlDomain: 70, from: 65, replyTo: 60,
    domain: 55, messageIdDomain: 40, displayName: 35, subject: 30, mailer: 20, filename: 25,
  };
  const map = new Map();

  items.forEach((item, index) => {
    const seen = new Set();
    for (const ind of indicatorsOf(item.analysis)) {
      const key = `${ind.type}:${ind.value}`;
      if (seen.has(key)) continue;
      seen.add(key);
      if (!map.has(key)) map.set(key, { ...ind, messages: [] });
      map.get(key).messages.push(index);
    }
  });

  return [...map.values()]
    .filter((entry) => entry.messages.length > 1)
    .map((entry) => ({ ...entry, weight: weight[entry.type] || 10 }))
    .sort((a, b) => b.messages.length - a.messages.length || b.weight - a.weight)
    .map((entry) => ({
      type: entry.type,
      label: entry.label,
      value: entry.value,
      defanged: defangValue(entry.type, entry.value),
      messages: entry.messages,
    }));
}

function defangValue(type, value) {
  if (type === "url") return defangUrl(value);
  if (type === "ip") return defangIp(value);
  if (type === "from" || type === "replyTo") return defangEmail(value);
  if (["domain", "urlDomain", "messageIdDomain"].includes(type)) return defangDomain(value);
  return value;
}

/**
 * The full table: one row per property, one cell per message, with the cells
 * that hold a value another message also has marked as shared.
 *
 * @param {Array<{name: string, analysis: Object}>} items
 */
export function buildComparison(items) {
  const shared = sharedIndicators(items);
  // Which exact strings are shared, so a cell can be marked without re-deriving.
  const sharedValues = new Set(shared.map((s) => `${s.type}:${s.value}`));

  const rows = FIELDS.map((field) => ({
    key: field.key,
    label: field.label,
    cells: items.map((item) => {
      const value = field.get(item.analysis);
      const correlateKey = field.correlate
        ? `${field.correlate}:${String(field.correlate === "subject" ? subjectKey(value) : value).toLowerCase()}`
        : null;
      return {
        value,
        tone: field.tone ? field.tone(item.analysis) : "",
        shared: !!correlateKey && sharedValues.has(correlateKey),
      };
    }),
    // A row where every message says the same thing is not worth staring at.
    identical: new Set(items.map((item) => field.get(item.analysis))).size === 1 && items.length > 1,
  }));

  return { rows, shared, count: items.length };
}

/** The comparison as CSV: first column the property, one column per message. */
export function comparisonCsv(items) {
  const { rows, shared } = buildComparison(items);
  const cell = (value) => {
    const s = String(value ?? "");
    const guarded = /^[=+\-@\t\r]/.test(s) ? `'${s}` : s;
    return /[",\r\n]/.test(guarded) ? `"${guarded.replace(/"/g, '""')}"` : guarded;
  };
  const lines = [["property", ...items.map((i) => i.name)].map(cell).join(",")];
  for (const row of rows) {
    lines.push([row.label, ...row.cells.map((c) => c.value)].map(cell).join(","));
  }
  lines.push("");
  lines.push(["shared indicator", "type", "seen in"].map(cell).join(","));
  for (const s of shared) {
    lines.push([s.defanged, s.label, s.messages.map((i) => items[i].name).join("; ")].map(cell).join(","));
  }
  return "﻿" + lines.join("\r\n") + "\r\n";
}

/** The comparison as JSON, for a ticket or a pipeline. */
export function comparisonJson(items, now = new Date()) {
  const { rows, shared } = buildComparison(items);
  return JSON.stringify(
    {
      tool: "Phishing Email Analyzer — comparison",
      generated: now.toISOString(),
      messages: items.map((item, index) => ({
        name: item.name,
        verdict: item.analysis.score?.tier || null,
        score: item.analysis.score?.score ?? null,
        properties: Object.fromEntries(rows.map((row) => [row.key, row.cells[index].value])),
      })),
      shared: shared.map((s) => ({
        type: s.type,
        label: s.label,
        indicator: s.defanged,
        seenIn: s.messages.map((i) => items[i].name),
      })),
    },
    null,
    2,
  );
}
