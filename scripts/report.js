// Report Generation
//
// Markdown for people (tickets, chat, email) and CSV for tooling (SIEM,
// blocklists, spreadsheets). Both are built entirely in the browser from an
// analysis that already exists — nothing is fetched or uploaded.
//
// Every indicator is defanged so a report pasted into a ticket or chat cannot
// turn into a clickable link. Hashes are left intact: they cannot be clicked,
// and an analyst needs to paste them into lookups exactly as they are.

// ===== Defanging =====

/** hxxps[://]evil[.]test/path — scheme and host neutralised, path readable. */
export function defangUrl(value) {
  const s = String(value ?? "");
  const m = s.match(/^([a-z][a-z0-9+.-]*):\/\/([^/?#]*)([\s\S]*)$/i);
  if (!m) return defangText(s);
  const scheme = m[1].toLowerCase().replace(/^http/, "hxxp").replace(/^ftp/, "fxp");
  // The path and query are defanged too. A wrapper like Safe Links carries the
  // real phishing domain in its query ("url=https%3A%2F%2Fevil.com…"), and
  // chat tools such as Slack and Teams auto-link bare domains even without a
  // scheme. Leaving it raw leaked exactly the indicator that matters most.
  return `${scheme}[://]${defangHost(m[2])}${defangText(m[3])}`;
}

export function defangDomain(value) {
  return String(value ?? "").replace(/\./g, "[.]");
}

export function defangIp(value) {
  const s = String(value ?? "");
  return s.includes(":") ? s.replace(/:/g, "[:]") : s.replace(/\./g, "[.]");
}

export function defangEmail(value) {
  const s = String(value ?? "");
  const at = s.lastIndexOf("@");
  if (at === -1) return defangText(s);
  return `${s.slice(0, at)}[@]${defangDomain(s.slice(at + 1))}`;
}

function defangHost(host) {
  // userinfo@host:port — defang the @ and the dots, keep the port readable.
  return host
    .replace(/@/g, "[@]")
    .replace(/\[([0-9a-f:.]+)\]/i, (m, ip) => `[${ip.replace(/:/g, "[:]")}]`)
    .replace(/\.(?![^[]*\])/g, "[.]");
}

/**
 * Defang any URL, email, IP or domain appearing inside free text such as a
 * subject line or a finding. Matched in a single pass so a URL's host is not
 * defanged twice.
 */
export function defangText(value) {
  return String(value ?? "").replace(
    /\b(?:https?|ftp):\/\/[^\s<>"'`)\]]+|[a-z0-9._%+-]+@[a-z0-9-]+(?:\.[a-z0-9-]+)*\.[a-z]{2,}|\b\d{1,3}(?:\.\d{1,3}){3}\b|\b(?:[a-z0-9-]+\.)+[a-z]{2,}\b/gi,
    (match) => {
      if (/^(?:https?|ftp):\/\//i.test(match)) return defangUrl(match);
      if (match.includes("@")) return defangEmail(match);
      if (isNotADomain(match)) return match;
      return defangDomain(match);
    },
  );
}

// File extensions that are not top-level domains. ".zip", ".mov" and ".one"
// ARE real TLDs used in phishing, so they are deliberately absent.
const FILE_EXTENSIONS = new Set(
  "exe pdf doc docx docm xls xlsx xlsm ppt pptx rar 7z gz tar cab js vbs vbe wsf hta html htm iso img lnk scr bat cmd ps1 dll jar msi txt csv png jpg jpeg gif svg eml msg ics json xml py sh".split(" "),
);

/**
 * Dotted tokens that look like domains but are not: authentication-result
 * property names ("header.from", "smtp.mailfrom") and filenames
 * ("Invoice.pdf.exe"). Defanging them only made the report harder to read.
 */
function isNotADomain(token) {
  if (/^(header|smtp|policy|body)\.[a-z-]+$/i.test(token)) return true;
  return FILE_EXTENSIONS.has(token.split(".").pop().toLowerCase());
}

// ===== Shared helpers =====

const TIER_ICON = { "High Risk": "🔴", Suspicious: "🟠", "Low Risk": "🟢" };

const STATUS = {
  pass: "✅ PASS",
  fail: "❌ FAIL",
  softfail: "⚠️ SOFTFAIL",
  permerror: "⚠️ PERMERROR",
  unverified: "⚠️ UNVERIFIED",
  temperror: "➖ TEMPERROR",
  neutral: "➖ NEUTRAL",
  none: "➖ NONE",
  unknown: "➖ UNKNOWN",
};

function flagsOf(item) {
  return (item?.riskFlags || []).map((f) => f.label).filter(Boolean);
}

function formatBytes(bytes) {
  if (!bytes) return "0 B";
  const units = ["B", "KB", "MB", "GB"];
  const i = Math.min(Math.floor(Math.log(bytes) / Math.log(1024)), units.length - 1);
  return `${(bytes / 1024 ** i).toFixed(i ? 1 : 0)} ${units[i]}`;
}

function formatTimestamp(date) {
  const iso = date.toISOString();
  return `${iso.slice(0, 10)} ${iso.slice(11, 16)} UTC`;
}

function plural(n, one, many = `${one}s`) {
  return `${n} ${n === 1 ? one : many}`;
}

/** Top-level URLs, each with the destinations unwrapped from it. */
function groupUrls(urls = []) {
  const children = new Map();
  for (const u of urls) {
    if (!u.unwrappedFrom) continue;
    if (!children.has(u.unwrappedFrom)) children.set(u.unwrappedFrom, []);
    children.get(u.unwrappedFrom).push(u);
  }
  const listed = new Set(urls.filter((u) => !u.unwrappedFrom).map((u) => u.value));
  return urls
    .filter((u) => !u.unwrappedFrom || !listed.has(u.unwrappedFrom))
    .map((u) => ({ url: u, destinations: children.get(u.value) || [] }));
}

/** Suggested download name, e.g. phishing-report_2026-09-17_account-suspended.md */
export function reportFilename(analysis, ext, now = new Date()) {
  const date = now.toISOString().slice(0, 10);
  const full = String(analysis?.headers?.subject || "")
    .normalize("NFKD")
    .replace(/[^\x00-\x7f]/g, "")
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "");
  let slug = full.slice(0, 40);
  // Cut at a word boundary rather than mid-word.
  if (full.length > 40 && slug.includes("-")) slug = slug.replace(/-[^-]*$/, "");
  return `phishing-report_${date}_${slug || "email"}.${ext}`;
}

// ===== Markdown =====

/**
 * Escape what Markdown would act on, and nothing more: every extra backslash
 * shows up literally when the report is pasted somewhere that does not render
 * Markdown. Brackets are left alone ("evil[.]com" must stay readable) except
 * where "](" would form a link — subject lines are attacker-controlled, and an
 * injected link must not become clickable in the analyst's ticket.
 */
function mdText(value) {
  return String(value ?? "")
    .replace(/([\\`*<>])/g, "\\$1")
    .replace(/~~/g, "\\~\\~")
    .replace(/(^|[^a-z0-9])_|_(?=[^a-z0-9]|$)/gi, (m) => m.replace("_", "\\_"))
    .replace(/\]\(/g, "]\\(")
    // "@name" becomes a mention in GitHub, Slack, Teams and Jira. Subjects are
    // attacker-controlled; a report must not ping people.
    .replace(/@(?=\w)/g, "\\@");
}

/**
 * Monospace display width. Emoji take two columns and the variation selector
 * none, so padding by string length misaligned every row with a status icon.
 */
function displayWidth(s) {
  let w = 0;
  for (const ch of String(s)) {
    const cp = ch.codePointAt(0);
    if (cp === 0xfe0f || (cp >= 0x300 && cp <= 0x36f)) continue;
    const wide =
      cp >= 0x1f000 ||
      (cp >= 0x2600 && cp <= 0x27bf) ||
      cp === 0x2b50 ||
      cp === 0x2b55;
    w += wide ? 2 : 1;
  }
  return w;
}

/** An inline code span that survives backticks. */
function mdCode(value) {
  const s = String(value ?? "").replace(/\r?\n/g, " ");
  if (!s) return "";
  const fence = s.includes("`") ? "``" : "`";
  const pad = fence.length > 1 ? " " : "";
  return `${fence}${pad}${s}${pad}${fence}`;
}

/**
 * A GitHub-flavoured table padded into aligned columns, so it reads as a clean
 * grid in plain text too — in a ticket that does not render Markdown.
 */
function mdTable(head, rows) {
  // A "|" inside a cell ends the cell, so it is escaped here — and only here.
  // Outside a table the backslash would be printed literally.
  const cell = (v) =>
    String(v ?? "")
      .replace(/\r?\n/g, " ")
      .replace(/\|/g, "\\|");
  const all = [head, ...rows].map((r) => r.map(cell));
  const widths = head.map((_, i) =>
    Math.max(3, ...all.map((r) => displayWidth(r[i] || ""))),
  );
  const line = (r) =>
    `| ${r.map((c, i) => c + " ".repeat(Math.max(0, widths[i] - displayWidth(c)))).join(" | ")} |`;
  return [
    line(all[0]),
    `| ${widths.map((w) => "-".repeat(w)).join(" | ")} |`,
    ...all.slice(1).map(line),
  ].join("\n");
}

function section(title) {
  return ["", `## ${title}`, ""];
}

/**
 * @param {Object} analysis - the app's current analysis
 * @param {Object} [options]
 * @param {Map<string,string>} [options.lookups] - "vt:<value>" / "abuse:<value>" summaries
 * @param {Date} [options.now]
 */
export function buildMarkdownReport(analysis, { lookups = new Map(), now = new Date() } = {}) {
  const h = analysis.headers || {};
  const auth = analysis.auth || {};
  const iocs = analysis.iocs || {};
  const score = analysis.score || {};
  const vt = (v) => lookups.get(`vt:${v}`) || "";
  const abuse = (v) => lookups.get(`abuse:${v}`) || "";
  const out = [];

  // --- Title ---------------------------------------------------------------
  const tier = score.tier || "Unknown";
  out.push("# Phishing Analysis Report", "");
  out.push(`> ${TIER_ICON[tier] || "⚪"} **${tier.toUpperCase()}** · Score **${score.score ?? 0}/100**  `);
  out.push(`> Generated ${formatTimestamp(now)} by Phishing Email Analyzer  `);
  out.push("> Indicators are defanged — re-fang before using them in tooling. Hashes are unmodified.");
  out.push("");

  const urls = iocs.urls || [];
  const counts = [
    plural(urls.length, "URL"),
    plural((iocs.domains || []).length, "domain"),
    plural((iocs.ips || []).length, "IP"),
    plural((iocs.emails || []).length, "email"),
    plural((iocs.attachments || []).length, "file"),
  ];
  if ((iocs.mismatchedLinks || []).length) {
    counts.push(plural(iocs.mismatchedLinks.length, "deceptive link"));
  }
  out.push(`**Indicators:** ${counts.join(" · ")}`);
  out.push("");
  out.push(
    "**Contents:** [Message](#message) · [Verdict](#verdict) · [Authentication](#authentication) · [Sender Path](#sender-path) · [Indicators of Compromise](#indicators-of-compromise)",
  );

  // --- Message -------------------------------------------------------------
  out.push(...section("Message"));
  const address = (a) =>
    a?.email ? `${a.name ? `${mdText(defangText(a.name))} ` : ""}${mdCode(defangEmail(a.email))}` : "—";
  const messageRows = [
    ["Subject", h.subject ? mdText(defangText(h.subject)) : "—"],
    ["From", address(h.from)],
    ["Reply-To", h.replyTo?.email ? address(h.replyTo) : "— (replies go to From)"],
    ["Return-Path", address(h.returnPath)],
    ["To", address(h.to)],
    ["Date", h.date ? mdText(h.date) : "—"],
    ["Message-ID", h.messageId ? mdCode(defangText(h.messageId)) : "—"],
  ];
  if (h.xMailer) messageRows.push(["Mailer", mdText(defangText(h.xMailer))]);
  out.push(mdTable(["Field", "Value"], messageRows));

  // --- Verdict -------------------------------------------------------------
  out.push(...section("Verdict"));
  for (const caveat of score.caveats || []) {
    out.push(`> ⚠️ ${mdText(defangText(caveat))}`, "");
  }
  const groups = score.reasonGroups || { auth: score.reasons || [], iocs: [], language: [] };
  const breakdown = score.breakdown || {};
  for (const [key, label] of [
    ["auth", "Authentication"],
    ["iocs", "Indicators"],
    ["language", "Language"],
  ]) {
    out.push(`**${label}** · ${breakdown[key] ?? 0}/100`, "");
    const reasons = groups[key] || [];
    if (reasons.length) {
      for (const r of reasons) out.push(`- ${mdText(defangText(r))}`);
    } else {
      out.push("- Nothing found");
    }
    out.push("");
  }
  out.pop();

  // --- Authentication ------------------------------------------------------
  out.push(...section("Authentication"));
  const mech = auth.mechanisms || {};
  out.push(
    mdTable(
      ["Check", "Result", "Details"],
      ["spf", "dkim", "dmarc"].map((k) => [
        k.toUpperCase(),
        STATUS[mech[k]?.status] || STATUS.unknown,
        mech[k]?.details ? mdText(defangText(mech[k].details)) : "—",
      ]),
    ),
  );

  const spfSources = auth.spf?.sources || [];
  if (spfSources.length) {
    out.push("", "**SPF by header**", "");
    out.push(
      mdTable(
        ["Header", "Result", "Evaluated IP", "Identity"],
        spfSources.map((s) => [
          s.header,
          STATUS[s.status] || STATUS.unknown,
          s.ip ? mdCode(defangIp(s.ip)) : "—",
          s.identity ? mdCode(defangText(s.identity)) : "—",
        ]),
      ),
    );
    if (spfSources.length === 2) {
      const agree = auth.spf.resultsAgree && auth.spf.ipsAgree !== false;
      out.push(
        "",
        agree
          ? "✅ Both SPF headers agree."
          : "⚠️ The SPF headers disagree. Authentication-Results, written by the receiving server, decides the result above.",
      );
    }
  }

  const align = auth.domainAlignment || {};
  const entries = align.entries || [];
  if (entries.length) {
    out.push("", "**Domain alignment**", "");
    out.push(
      mdTable(
        ["Check", "Comparison", "Result"],
        entries.map((e) => {
          const check = e.source.startsWith("DKIM")
            ? "DKIM"
            : e.source === "Return-Path"
              ? "SPF"
              : `${e.source} (informational)`;
          const comparison = `${e.source} ${mdCode(defangDomain(e.domain))} ${e.aligned ? "=" : "≠"} From ${mdCode(defangDomain(align.fromDomain || "none"))}`;
          let result;
          if (!e.dmarcRelevant) result = e.aligned ? "➖ Same domain" : "➖ Differs";
          else if (e.strict) result = "✅ Aligned (strict)";
          else if (e.relaxed) result = `✅ Aligned (relaxed, ${defangDomain(e.orgDomain)})`;
          else result = "❌ Not aligned";
          if (e.dmarcRelevant && e.aligned && !e.mechanismPassed) {
            result += ` — but ${check} did not pass`;
          }
          return [check, comparison, result];
        }),
      ),
    );
    if (align.dmarcAligned === true) {
      out.push("", "✅ At least one authenticated mechanism aligns with the From domain.");
    } else if (align.dmarcAligned === false) {
      out.push("", "❌ No authenticated mechanism aligns with the From domain.");
    }
  }

  const warnings = auth.trust?.warnings || [];
  if (warnings.length) {
    out.push("", "**Header trust**", "");
    for (const w of warnings) out.push(`- ⚠️ ${mdText(defangText(w))}`);
  }

  // --- Sender path -----------------------------------------------------------
  out.push(...section("Sender Path"));
  const chain = auth.receivedChain || [];
  const sender = auth.senderIp || {};
  const relay = chain.find((hop) => hop.ip);
  const pathRows = [];
  if (sender.publicIp) {
    pathRows.push([
      "**Originating IP** (public)",
      mdCode(defangIp(sender.publicIp)),
      sender.publicHop?.from ? mdCode(defangDomain(sender.publicHop.from)) : "—",
    ]);
  }
  if (sender.privateIp) {
    pathRows.push(["First hop (private)", mdCode(defangIp(sender.privateIp)), "—"]);
  }
  if (relay?.ip && relay.ip !== sender.publicIp && relay.ip !== sender.privateIp) {
    pathRows.push([
      "Last relay",
      mdCode(defangIp(relay.ip)),
      relay.from ? mdCode(defangDomain(relay.from)) : "—",
    ]);
  }
  out.push(pathRows.length ? mdTable(["Role", "IP", "Host"], pathRows) : "_No IP addresses recorded in the Received headers._");

  if (chain.length) {
    out.push("", "**Received chain** (hop 1 is where the message started)", "");
    out.push(
      mdTable(
        ["Hop", "From", "By", "IP", "Time"],
        [...chain]
          .sort((a, b) => a.number - b.number)
          .map((hop) => [
            String(hop.number),
            hop.from ? mdCode(defangDomain(hop.from)) : "—",
            hop.by ? mdCode(defangDomain(hop.by)) : "—",
            hop.ip ? mdCode(defangIp(hop.ip)) : "—",
            hop.date ? mdText(hop.date) : "—",
          ]),
      ),
    );
  }

  // --- IOCs --------------------------------------------------------------------
  out.push(...section("Indicators of Compromise"));

  out.push(`### URLs (${urls.length})`, "");
  const grouped = groupUrls(urls);
  if (!grouped.length) out.push("_None found._");
  grouped.forEach(({ url, destinations }, i) => {
    const flags = flagsOf(url);
    out.push(`${i + 1}. ${mdCode(defangUrl(url.value))}`);
    out.push(`   - **Source:** ${mdText(url.source || "—")}`);
    out.push(`   - **Flags:** ${flags.length ? mdText(flags.join(", ")) : "—"}`);
    for (const d of destinations) {
      const dFlags = flagsOf(d);
      out.push(
        `   - **Real destination:** ${mdCode(defangUrl(d.value))}${dFlags.length ? ` — ${mdText(dFlags.join(", "))}` : ""}`,
      );
      if (vt(d.value)) out.push(`     - **VirusTotal:** ${mdText(vt(d.value))}`);
    }
    if (vt(url.value)) out.push(`   - **VirusTotal:** ${mdText(vt(url.value))}`);
  });

  const lookupCols = (items, services) =>
    services.filter(([, get]) => items.some((it) => get(it.value)));

  const iocTable = (title, items, defang, extraCols = []) => {
    out.push("", `### ${title} (${items.length})`, "");
    if (!items.length) {
      out.push("_None found._");
      return;
    }
    const cols = lookupCols(items, extraCols);
    out.push(
      mdTable(
        [title.replace(/ Addresses$|s$/, "") || title, "Source", "Flags", ...cols.map(([n]) => n)],
        items.map((it) => [
          mdCode(defang(it.value)),
          mdText(it.source || "—"),
          flagsOf(it).length ? mdText(flagsOf(it).join(", ")) : "—",
          ...cols.map(([, get]) => (get(it.value) ? mdText(get(it.value)) : "—")),
        ]),
      ),
    );
  };

  iocTable("Domains", iocs.domains || [], defangDomain, [["VirusTotal", vt]]);
  iocTable("IP Addresses", iocs.ips || [], defangIp, [
    ["VirusTotal", vt],
    ["AbuseIPDB", abuse],
  ]);
  iocTable("Email Addresses", iocs.emails || [], defangEmail);

  const files = iocs.attachments || [];
  out.push("", `### Attachments (${files.length})`, "");
  if (!files.length) out.push("_None found._");
  files.forEach((f, i) => {
    if (i) out.push("");
    out.push(`#### ${mdText(f.value || "unnamed")}${f.inline ? " (inline)" : ""}`, "");
    const rows = [
      ["Type", mdText(f.contentType || "unknown")],
      ["Size", formatBytes(f.size)],
      ["Flags", flagsOf(f).length ? mdText(flagsOf(f).join(", ")) : "—"],
      ["SHA-256", f.sha256 ? mdCode(f.sha256) : "—"],
      ["MD5", f.md5 ? mdCode(f.md5) : "—"],
    ];
    if (vt(f.value)) rows.push(["VirusTotal", mdText(vt(f.value))]);
    out.push(mdTable(["Property", "Value"], rows));
  });

  const deceptive = iocs.mismatchedLinks || [];
  out.push("", `### Deceptive Links (${deceptive.length})`, "");
  if (!deceptive.length) {
    out.push("_None found._");
  } else {
    out.push("Links whose visible text shows one address while pointing to another.", "");
    out.push(
      mdTable(
        ["Displays", "Actually goes to"],
        deceptive.map((l) => [mdCode(defangText(l.text)), mdCode(defangUrl(l.href))]),
      ),
    );
  }

  out.push(
    "",
    "---",
    "",
    "_Defanging: `hxxp[://]` for schemes, `[.]` for dots, `[@]` for email addresses, `[:]` for IPv6. Generated locally — no data left the analyst's browser._",
    "",
  );
  return out.join("\n");
}

// ===== CSV =====

export const CSV_COLUMNS = [
  "type",
  "indicator",
  "source",
  "risk_flags",
  "details",
  "virustotal",
  "abuseipdb",
];

/**
 * One indicator per row, a fixed column set so imports do not break between
 * reports. RFC 4180 quoting, CRLF line endings, and a UTF-8 byte-order mark so
 * Excel reads non-ASCII (punycode reveals, subjects) correctly.
 */
export function buildCsvReport(analysis, { lookups = new Map(), includeRaw = false } = {}) {
  const iocs = analysis.iocs || {};
  const vt = (v) => lookups.get(`vt:${v}`) || "";
  const abuse = (v) => lookups.get(`abuse:${v}`) || "";
  const flags = (it) => flagsOf(it).join("; ");
  const rows = [];

  const add = (type, raw, defanged, source, riskFlags, details, lookupKey = raw) => {
    const row = [type, defanged, source || "", riskFlags || "", details || "", vt(lookupKey), abuse(lookupKey)];
    if (includeRaw) row.push(raw);
    rows.push(row);
  };

  for (const u of iocs.urls || []) {
    add(
      "url",
      u.value,
      defangUrl(u.value),
      u.source,
      flags(u),
      u.unwrappedFrom ? `unwrapped from ${defangUrl(u.unwrappedFrom)}` : "",
    );
  }
  for (const d of iocs.domains || []) add("domain", d.value, defangDomain(d.value), d.source, flags(d), "");
  for (const ip of iocs.ips || []) {
    add("ip", ip.value, defangIp(ip.value), ip.source, flags(ip), ip.private ? "private/reserved address" : "");
  }
  for (const e of iocs.emails || []) add("email", e.value, defangEmail(e.value), e.source, flags(e), "");
  for (const f of iocs.attachments || []) {
    const name = f.value || "unnamed";
    const meta = `${f.contentType || "unknown type"}; ${formatBytes(f.size)}${f.inline ? "; inline" : ""}`;
    add("filename", name, name, f.inline ? "Inline" : "Attachment", flags(f), meta);
    if (f.sha256) add("sha256", f.sha256, f.sha256, "Attachment", flags(f), `file: ${name}`, name);
    if (f.md5) add("md5", f.md5, f.md5, "Attachment", flags(f), `file: ${name}`, name);
  }
  for (const l of iocs.mismatchedLinks || []) {
    add("deceptive_link", l.href, defangUrl(l.href), "Body", "Mismatch", `displays: ${defangText(l.text)}`);
  }

  const header = includeRaw ? [...CSV_COLUMNS, "indicator_raw"] : CSV_COLUMNS;
  return "﻿" + [header, ...rows].map((r) => r.map(csvCell).join(",")).join("\r\n") + "\r\n";
}

function csvCell(value) {
  let s = value == null ? "" : String(value);
  // A cell starting with = + - @ is evaluated as a formula by spreadsheet
  // software. An IOC report is exactly the file an attacker would like to get
  // a formula into.
  if (/^[=+\-@\t\r]/.test(s)) s = `'${s}`;
  return /[",\r\n]/.test(s) || s !== s.trim() ? `"${s.replace(/"/g, '""')}"` : s;
}
