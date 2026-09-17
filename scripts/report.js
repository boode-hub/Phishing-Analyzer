// Report Generation
//
// An HTML report for people (tickets, email, print to PDF) and CSV for tooling (SIEM,
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

/** Suggested download name, e.g. phishing-report_2026-09-17_account-suspended.html */
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

// ===== HTML =====
//
// A single self-contained file in the app's own visual language. It must be
// safe to open and to forward:
//  - every value comes from an attacker-written email, so all of it is escaped;
//  - a Content-Security-Policy blocks all loading and script execution, so even
//    an escaping mistake cannot run code or fetch anything;
//  - no web fonts, images or scripts — opening the report makes no request;
//  - no clickable links to indicators, only in-page navigation.

const STATUS_LABEL = {
  pass: "Pass",
  fail: "Fail",
  softfail: "Softfail",
  permerror: "Permerror",
  unverified: "Unverified",
  temperror: "Temperror",
  neutral: "Neutral",
  none: "None",
  unknown: "Unknown",
};
const STATUS_TONE = {
  pass: "good",
  fail: "bad",
  softfail: "warn",
  permerror: "warn",
  unverified: "warn",
  temperror: "muted",
  neutral: "muted",
  none: "muted",
  unknown: "muted",
};

function esc(value) {
  return String(value ?? "").replace(
    /[&<>"']/g,
    (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c],
  );
}

const DASH = '<span class="dim">—</span>';

/** A whole number 0–100, for meter widths written into style attributes. */
function percent(value) {
  const n = Number(value);
  return Number.isFinite(n) ? Math.round(Math.max(0, Math.min(100, n))) : 0;
}

function statusPill(status) {
  const s = STATUS_LABEL[status] ? status : "unknown";
  return `<span class="pill ${STATUS_TONE[s]}">${STATUS_LABEL[s]}</span>`;
}

function flagPills(item) {
  const flags = item?.riskFlags || [];
  if (!flags.length) return DASH;
  return flags
    .map((f) => {
      const tone = f.type === "high" ? "bad" : f.type === "medium" ? "warn" : "muted";
      return `<span class="pill ${tone}">${esc(f.label)}</span>`;
    })
    .join(" ");
}

function code(value, extra = "") {
  return value ? `<code class="${extra}">${esc(value)}</code>` : DASH;
}

function htmlTable(head, rows) {
  return `<div class="table-wrap"><table><thead><tr>${head
    .map((c) => `<th>${esc(c)}</th>`)
    .join("")}</tr></thead><tbody>${rows
    .map(
      (r) =>
        `<tr>${r.map((cell, i) => `<td data-label="${esc(head[i])}">${cell}</td>`).join("")}</tr>`,
    )
    .join("")}</tbody></table></div>`;
}

function panel(id, title, body, count) {
  return `<section class="panel" id="${id}"><h2>${esc(title)}${count != null ? `<span class="badge">${count}</span>` : ""}</h2>${body}</section>`;
}

function sub(title, count, body) {
  return `<div class="sub"><h3>${esc(title)}<span class="badge">${count}</span></h3>${body}</div>`;
}

const EMPTY = '<p class="empty">None found.</p>';

// The app's Glitch Tomoe mark, inlined so the file needs nothing external.
const LOGO = `<svg class="logo" viewBox="-5 -5 110 110" aria-hidden="true"><defs><g id="lg-eye"><circle cx="50" cy="50" r="48" fill="#000"/><circle cx="50" cy="50" r="46.5" fill="none" stroke="#9fef00" stroke-width="2.5"/><g id="lg-t" fill="#9fef00"><path d="M50 12A38 38 0 0 1 81 28Q69 22 50 26Z"/><circle cx="50" cy="19" r="7"/></g><use href="#lg-t" transform="rotate(120 50 50)"/><use href="#lg-t" transform="rotate(240 50 50)"/><circle cx="50" cy="50" r="8" fill="#9fef00"/></g><clipPath id="lg-s1"><rect x="-10" y="22" width="120" height="7"/></clipPath><clipPath id="lg-s2"><rect x="-10" y="47" width="120" height="5"/></clipPath><clipPath id="lg-s3"><rect x="-10" y="70" width="120" height="6"/></clipPath></defs><use href="#lg-eye"/><g clip-path="url(#lg-s1)"><use href="#lg-eye" x="7"/></g><g clip-path="url(#lg-s2)"><use href="#lg-eye" x="-6"/></g><g clip-path="url(#lg-s3)"><use href="#lg-eye" x="5"/></g></svg>`;

/**
 * @param {Object} analysis - the app's current analysis
 * @param {Object} [options]
 * @param {Map<string,string>} [options.lookups] - "vt:<value>" / "abuse:<value>" summaries
 * @param {Date} [options.now]
 */
export function buildHtmlReport(analysis, { lookups = new Map(), local = new Map(), now = new Date() } = {}) {
  const hd = analysis.headers || {};
  const auth = analysis.auth || {};
  const iocs = analysis.iocs || {};
  const score = analysis.score || {};
  const vt = (v) => lookups.get(`vt:${v}`) || "";
  const abuse = (v) => lookups.get(`abuse:${v}`) || "";
  // Registration and DNS answers the analyst already pulled up, if any.
  const whois = (v) => local.get(`whois:${v}`) || "";
  const dnsOf = (v) => local.get(`dns:${v}`) || "";

  const urls = iocs.urls || [];
  const domains = iocs.domains || [];
  const ips = iocs.ips || [];
  const emails = iocs.emails || [];
  const files = iocs.attachments || [];
  const deceptive = iocs.mismatchedLinks || [];

  const tier = score.tier || "Unknown";
  const tone = tier === "High Risk" ? "bad" : tier === "Suspicious" ? "warn" : "good";
  const total = percent(score.score);

  const address = (a) =>
    a?.email
      ? `${a.name ? `<span class="name">${esc(defangText(a.name))}</span> ` : ""}${code(defangEmail(a.email))}`
      : DASH;

  // --- Hero ------------------------------------------------------------------
  const counts = [
    [urls.length, "URL"],
    [domains.length, "Domain"],
    [ips.length, "IP"],
    [emails.length, "Email"],
    [files.length, "File"],
  ];
  if (deceptive.length) counts.push([deceptive.length, "Deceptive link"]);

  const hero = `<section class="hero ${tone}">
    <div class="hero-verdict">
      <div class="eyebrow">Verdict</div>
      <div class="hero-tier">${esc(tier)}</div>
      <div class="hero-score"><strong>${total}</strong><span>/100</span></div>
      <div class="meter"><div class="meter-fill ${tone}" style="width:${total}%"></div></div>
    </div>
    <div class="hero-message">
      <div class="eyebrow">Subject</div>
      <div class="hero-subject">${hd.subject ? esc(defangText(hd.subject)) : '<span class="dim">(no subject)</span>'}</div>
      <div class="hero-from"><span class="eyebrow-inline">From</span> ${address(hd.from)}</div>
      <div class="counts">${counts
        .map(([n, label]) => `<span class="count${n ? "" : " zero"}"><strong>${n}</strong> ${label}${n === 1 ? "" : "s"}</span>`)
        .join("")}</div>
    </div>
  </section>`;

  const caveats = (score.caveats || [])
    .map((c) => `<div class="callout warn">${esc(defangText(c))}</div>`)
    .join("");

  // --- Message ----------------------------------------------------------------
  const kv = (rows) =>
    `<dl class="kv">${rows.map(([k, v]) => `<dt>${esc(k)}</dt><dd>${v}</dd>`).join("")}</dl>`;
  const messageRows = [
    ["Subject", hd.subject ? esc(defangText(hd.subject)) : DASH],
    ["From", address(hd.from)],
    ["Reply-To", hd.replyTo?.email ? address(hd.replyTo) : '<span class="dim">None — replies go to From</span>'],
    ["Return-Path", address(hd.returnPath)],
    ["To", address(hd.to)],
    ["Date", hd.date ? esc(hd.date) : DASH],
    ["Message-ID", hd.messageId ? code(defangText(hd.messageId)) : DASH],
  ];
  if (hd.xMailer) messageRows.push(["Mailer", esc(defangText(hd.xMailer))]);
  const message = panel("message", "Message", kv(messageRows));

  // --- Sender identity ---------------------------------------------------------
  const identityFindings = analysis.identity?.findings || [];
  const identityPanel = identityFindings.length
    ? panel(
        "identity",
        "Sender identity",
        `<p class="dim small lead">Who the message claims to be from. Authentication cannot answer this: a display name and a lookalike domain both pass every check.</p>${identityFindings
          .map(
            (f) =>
              `<div class="callout ${f.severity === "high" ? "bad" : "warn"}"><strong>${esc(defangText(f.title))}</strong><div>${esc(defangText(f.detail))}</div></div>`,
          )
          .join("")}`,
        identityFindings.length,
      )
    : "";

  // --- Verdict ------------------------------------------------------------------
  const groups = score.reasonGroups || { auth: score.reasons || [], iocs: [], language: [] };
  const breakdown = score.breakdown || {};
  const severity = (v) => (v >= 60 ? "bad" : v >= 30 ? "warn" : "good");
  const verdict = panel(
    "verdict",
    "Why it scored this way",
    `${caveats}<div class="score-grid">${[
      ["auth", "Authentication"],
      ["iocs", "Indicators"],
      ["language", "Language"],
    ]
      .map(([key, label]) => {
        const v = percent(breakdown[key]);
        const reasons = groups[key] || [];
        return `<div class="score-card">
          <div class="score-head"><span class="eyebrow">${label}</span><span class="score-num">${v}</span></div>
          <div class="meter small"><div class="meter-fill ${severity(v)}" style="width:${v}%"></div></div>
          <ul class="reasons">${reasons.length ? reasons.map((r) => `<li>${esc(defangText(r))}</li>`).join("") : '<li class="none">Nothing found</li>'}</ul>
        </div>`;
      })
      .join("")}</div>`,
  );

  // --- Authentication ------------------------------------------------------------
  const mech = auth.mechanisms || {};
  let authBody = `<div class="mech-grid">${["spf", "dkim", "dmarc"]
    .map(
      (k) => `<div class="mech ${STATUS_TONE[mech[k]?.status] || "muted"}">
        <div class="mech-head"><span class="mech-name">${k.toUpperCase()}</span>${statusPill(mech[k]?.status)}</div>
        <div class="mech-detail">${mech[k]?.details ? esc(defangText(mech[k].details)) : DASH}</div>
      </div>`,
    )
    .join("")}</div>`;

  const spfSources = auth.spf?.sources || [];
  if (spfSources.length) {
    authBody += `<h3>SPF by header</h3>${htmlTable(
      ["Header", "Result", "Evaluated IP", "Identity"],
      spfSources.map((s) => [
        esc(s.header),
        statusPill(s.status),
        s.ip ? code(defangIp(s.ip)) : DASH,
        s.identity ? code(defangText(s.identity)) : DASH,
      ]),
    )}`;
    if (spfSources.length === 2) {
      authBody +=
        auth.spf.resultsAgree && auth.spf.ipsAgree !== false
          ? '<div class="callout good">Both SPF headers agree.</div>'
          : '<div class="callout warn">The SPF headers disagree. Authentication-Results, written by the receiving server, decides the result.</div>';
    }
  }

  const align = auth.domainAlignment || {};
  const entries = align.entries || [];
  if (entries.length) {
    authBody += `<h3>Domain alignment</h3>${htmlTable(
      ["Check", "Comparison", "Result"],
      entries.map((e) => {
        const check = e.source.startsWith("DKIM") ? "DKIM" : e.source === "Return-Path" ? "SPF" : e.source;
        const note = e.dmarcRelevant ? "" : '<div class="dim small">Not a DMARC input</div>';
        const comparison = `<span class="cmp">${esc(e.source)} ${code(defangDomain(e.domain))}</span><span class="op">${e.aligned ? "=" : "≠"}</span><span class="cmp">From ${code(defangDomain(align.fromDomain || "none"))}</span>`;
        let result;
        if (!e.dmarcRelevant) result = `<span class="pill muted">${e.aligned ? "Same domain" : "Differs"}</span>`;
        else if (e.strict) result = '<span class="pill good">Aligned · strict</span>';
        else if (e.relaxed) result = `<span class="pill good">Aligned · relaxed</span><div class="dim small">both under ${esc(defangDomain(e.orgDomain))}</div>`;
        else result = '<span class="pill bad">Not aligned</span>';
        if (e.dmarcRelevant && e.aligned && !e.mechanismPassed) {
          result += `<div class="warn-text small">but ${check} did not pass</div>`;
        }
        return [`<strong>${esc(check)}</strong>${note}`, comparison, result];
      }),
    )}`;
    if (align.dmarcAligned === true) {
      authBody += '<div class="callout good">At least one authenticated mechanism aligns with the From domain.</div>';
    } else if (align.dmarcAligned === false) {
      authBody += '<div class="callout bad">No authenticated mechanism aligns with the From domain.</div>';
    }
  }

  const arc = auth.arc;
  if (arc?.present) {
    authBody += `<h3>ARC chain</h3><div class="callout ${arc.chainValid === false ? "bad" : "muted"}">${arc.sets} ARC set${
      arc.sets === 1 ? "" : "s"
    } present${arc.chainValid === false ? ", marked broken (cv=fail)" : ""}.${
      arc.oldest
        ? ` The first hop recorded SPF ${esc(arc.oldest.spf.toUpperCase())}, DKIM ${esc(
            arc.oldest.dkim.toUpperCase(),
          )}, DMARC ${esc(arc.oldest.dmarc.toUpperCase())} for the original sender. ARC is informational and is not verified here.`
        : ""
    }</div>`;
  }

  const anomalies = auth.anomalies || [];
  if (anomalies.length) {
    authBody += `<h3>Header anomalies</h3>${anomalies
      .map((a) => `<div class="callout ${a.severity === "high" ? "bad" : a.severity === "medium" ? "warn" : "muted"}">${esc(defangText(a.message))}</div>`)
      .join("")}`;
  }

  const warnings = auth.trust?.warnings || [];
  if (warnings.length) {
    authBody += `<h3>Header trust</h3>${warnings.map((w) => `<div class="callout warn">${esc(defangText(w))}</div>`).join("")}`;
  }
  const authentication = panel("authentication", "Authentication", authBody);

  // --- Sender path -----------------------------------------------------------------
  const chain = auth.receivedChain || [];
  const sender = auth.senderIp || {};
  const relay = chain.find((hop) => hop.ip);
  const pathCards = [];
  if (sender.publicIp) {
    pathCards.push(["Originating IP", "the sender's public address", sender.publicIp, sender.publicHop?.from, "primary"]);
  }
  if (sender.privateIp) {
    pathCards.push(["First hop", "private address", sender.privateIp, null, ""]);
  }
  if (relay?.ip && relay.ip !== sender.publicIp && relay.ip !== sender.privateIp) {
    pathCards.push(["Last relay", "delivered to you", relay.ip, relay.from, ""]);
  }
  let pathBody = pathCards.length
    ? `<div class="path-grid">${pathCards
        .map(
          ([role, hint, ip, host, cls]) => `<div class="path ${cls}">
            <div class="eyebrow">${esc(role)} <span class="dim">· ${esc(hint)}</span></div>
            <div class="path-ip">${code(defangIp(ip))}</div>
            ${host ? `<div class="path-host">${code(defangDomain(host))}</div>` : ""}
            ${vt(ip) ? `<div class="lookup">VirusTotal: ${esc(vt(ip))}</div>` : ""}
            ${abuse(ip) ? `<div class="lookup">AbuseIPDB: ${esc(abuse(ip))}</div>` : ""}
            ${whois(ip) ? `<div class="lookup">Registration: ${esc(defangText(whois(ip)))}</div>` : ""}
          </div>`,
        )
        .join("")}</div>`
    : EMPTY;

  if (chain.length) {
    pathBody += `<h3>Received chain <span class="dim small">hop 1 is where the message started</span></h3>${htmlTable(
      ["Hop", "From", "By", "IP", "Time"],
      [...chain]
        .sort((a, b) => a.number - b.number)
        .map((hop) => [
          `<span class="hop">${hop.number}</span>`,
          hop.from ? code(defangDomain(hop.from)) : DASH,
          hop.by ? code(defangDomain(hop.by)) : DASH,
          hop.ip ? code(defangIp(hop.ip)) : DASH,
          hop.date ? `<span class="small">${esc(hop.date)}</span>` : DASH,
        ]),
    )}`;
  }
  const senderPath = panel("sender-path", "Sender path", pathBody);

  // --- IOCs -----------------------------------------------------------------------------
  const grouped = groupUrls(urls);
  const urlBody = grouped.length
    ? `<ol class="url-list">${grouped
        .map(
          ({ url, destinations }) => `<li class="url-card">
            <div class="url-value">${code(defangUrl(url.value), "ioc")}</div>
            <div class="url-meta"><span class="dim">Source</span> ${esc(url.source || "—")} <span class="sep"></span> ${flagPills(url)}</div>
            ${destinations
              .map(
                (d) => `<div class="destination">
                  <div class="eyebrow">Real destination</div>
                  <div class="url-value">${code(defangUrl(d.value), "ioc")}</div>
                  <div class="url-meta">${flagPills(d)}</div>
                  ${vt(d.value) ? `<div class="lookup">VirusTotal: ${esc(vt(d.value))}</div>` : ""}
                </div>`,
              )
              .join("")}
            ${vt(url.value) ? `<div class="lookup">VirusTotal: ${esc(vt(url.value))}</div>` : ""}
          </li>`,
        )
        .join("")}</ol>`
    : EMPTY;

  const iocTable = (items, label, defang, services = []) => {
    if (!items.length) return EMPTY;
    const cols = services.filter(([, get]) => items.some((it) => get(it.value)));
    return htmlTable(
      [label, "Source", "Flags", ...cols.map(([n]) => n)],
      items.map((it) => [
        code(defang(it.value), "ioc"),
        esc(it.source || "—"),
        flagPills(it),
        ...cols.map(([, get]) => (get(it.value) ? esc(get(it.value)) : DASH)),
      ]),
    );
  };

  const fileBody = files.length
    ? `<div class="file-grid">${files
        .map(
          (f) => `<div class="file-card">
            <div class="file-name">${esc(f.value || "unnamed")}${f.inline ? ' <span class="pill muted">inline</span>' : ""}</div>
            <div class="file-flags">${flagPills(f)}</div>
            ${kv([
              ["Type", esc(f.contentType || "unknown")],
              ["Size", esc(formatBytes(f.size))],
              ["SHA-256", f.sha256 ? code(f.sha256, "hash") : DASH],
              ["MD5", f.md5 ? code(f.md5, "hash") : DASH],
              ...(vt(f.value) ? [["VirusTotal", esc(vt(f.value))]] : []),
            ])}
          </div>`,
        )
        .join("")}</div>`
    : EMPTY;

  const deceptiveBody = deceptive.length
    ? `<p class="dim small lead">Links whose visible text shows one address while pointing to another.</p>${htmlTable(
        ["Displays", "Actually goes to"],
        deceptive.map((l) => [code(defangText(l.text), "ioc"), code(defangUrl(l.href), "ioc")]),
      )}`
    : EMPTY;

  const indicators = panel(
    "indicators",
    "Indicators of compromise",
    [
      sub("URLs", urls.length, urlBody),
      sub(
        "Domains",
        domains.length,
        iocTable(domains, "Domain", defangDomain, [
          ["VirusTotal", vt],
          ["Registration", whois],
          ["DNS", dnsOf],
        ]),
      ),
      sub(
        "IP addresses",
        ips.length,
        iocTable(ips, "IP", defangIp, [
          ["VirusTotal", vt],
          ["AbuseIPDB", abuse],
          ["Registration", whois],
        ]),
      ),
      sub("Email addresses", emails.length, iocTable(emails, "Email", defangEmail)),
      sub("Attachments", files.length, fileBody),
      sub("Deceptive links", deceptive.length, deceptiveBody),
    ].join(""),
  );

  const title = `Phishing Analysis Report — ${hd.subject ? defangText(hd.subject) : "email"}`;

  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; img-src data:; base-uri 'none'; form-action 'none'">
<meta name="referrer" content="no-referrer">
<meta name="generator" content="Phishing Email Analyzer">
<title>${esc(title)}</title>
<style>${REPORT_CSS}</style>
</head>
<body>
<div class="wrap">
  <header class="top">
    <div class="brand">${LOGO}<div><div class="brand-name">Phishing Email Analyzer</div><div class="brand-sub">IOC report</div></div></div>
    <div class="generated"><span class="eyebrow">Generated</span>${esc(formatTimestamp(now))}</div>
  </header>
  ${hero}
  <nav class="toc" aria-label="Contents">
    <a href="#message">Message</a>${identityPanel ? '<a href="#identity">Identity</a>' : ""}<a href="#verdict">Verdict</a><a href="#authentication">Authentication</a><a href="#sender-path">Sender path</a><a href="#indicators">Indicators</a>
  </nav>
  <div class="defang-note"><strong>Indicators are defanged</strong> — <code>hxxp[://]</code>, <code>[.]</code>, <code>[@]</code>, <code>[:]</code>. Re-fang before using them in tooling. Hashes are unmodified.</div>
  ${message}
  ${identityPanel}
  ${verdict}
  ${authentication}
  ${senderPath}
  ${indicators}
  <footer class="foot">Generated locally by Phishing Email Analyzer — no data left the analyst's browser. This file loads nothing and runs no scripts.</footer>
</div>
</body>
</html>
`;
}

const REPORT_CSS = `
:root{
  --bg:#0d1117;--panel:#161b22;--elev:#21262d;--surface:#30363d;--border:#30363d;--border-soft:#21262d;
  --text:#e6edf3;--text2:#8b949e;--muted:#6e7681;
  --accent:#9fef00;--accent-bg:rgba(159,239,0,.08);--accent-border:rgba(159,239,0,.25);
  --good:#9fef00;--good-bg:rgba(159,239,0,.08);--good-border:rgba(159,239,0,.28);
  --bad:#ff7b72;--bad-bg:rgba(255,123,114,.09);--bad-border:rgba(255,123,114,.3);
  --warn:#d29922;--warn-bg:rgba(210,153,34,.1);--warn-border:rgba(210,153,34,.3);
  --radius:10px;
  --sans:"Inter",-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;
  --mono:"JetBrains Mono",ui-monospace,SFMono-Regular,Menlo,Consolas,"Liberation Mono",monospace;
}
*{box-sizing:border-box;margin:0;padding:0}
html{-webkit-text-size-adjust:100%}
body{background:var(--bg);color:var(--text);font:14px/1.6 var(--sans);-webkit-font-smoothing:antialiased}
.wrap{max-width:1080px;margin:0 auto;padding:28px 24px 48px}
code{font-family:var(--mono);font-size:12.5px;background:var(--elev);border:1px solid var(--border);border-radius:5px;padding:1px 6px;color:var(--text);overflow-wrap:anywhere;word-break:break-word}
code.ioc{color:var(--accent);background:rgba(159,239,0,.05);border-color:rgba(159,239,0,.18)}
code.hash{user-select:all;word-break:break-all}
.dim{color:var(--muted)}.small{font-size:12px}.name{color:var(--text2)}
.eyebrow{font-size:11px;font-weight:600;letter-spacing:.08em;text-transform:uppercase;color:var(--text2)}
.eyebrow-inline{font-size:11px;font-weight:600;letter-spacing:.08em;text-transform:uppercase;color:var(--muted);margin-right:6px}
.warn-text{color:var(--warn)}

.top{display:flex;align-items:center;justify-content:space-between;gap:16px;padding:14px 20px;background:var(--panel);border:1px solid var(--border);border-radius:var(--radius);margin-bottom:16px}
.brand{display:flex;align-items:center;gap:12px}
.logo{width:36px;height:36px;flex-shrink:0}
.brand-name{font-weight:700;color:var(--accent);letter-spacing:-.01em}
.brand-sub{font-size:12px;color:var(--muted)}
.generated{display:flex;flex-direction:column;align-items:flex-end;font-family:var(--mono);font-size:12px;color:var(--text2)}

.hero{display:grid;grid-template-columns:minmax(220px,300px) 1fr;gap:24px;padding:24px;border-radius:var(--radius);border:1px solid var(--border);border-left:4px solid;margin-bottom:16px;background:var(--panel)}
.hero.bad{border-color:var(--bad-border);border-left-color:var(--bad);background:linear-gradient(135deg,var(--bad-bg),transparent 60%),var(--panel)}
.hero.warn{border-color:var(--warn-border);border-left-color:var(--warn);background:linear-gradient(135deg,var(--warn-bg),transparent 60%),var(--panel)}
.hero.good{border-color:var(--good-border);border-left-color:var(--good);background:linear-gradient(135deg,var(--good-bg),transparent 60%),var(--panel)}
.hero-tier{font-size:30px;font-weight:800;letter-spacing:-.02em;line-height:1.15;margin:4px 0}
.hero.bad .hero-tier{color:var(--bad)}.hero.warn .hero-tier{color:var(--warn)}.hero.good .hero-tier{color:var(--good)}
.hero-score{font-family:var(--mono);color:var(--text2);margin-bottom:10px}
.hero-score strong{font-size:22px;color:var(--text)}
.hero-subject{font-size:18px;font-weight:600;line-height:1.35;margin:4px 0 8px;overflow-wrap:anywhere}
.hero-from{margin-bottom:14px;overflow-wrap:anywhere}
.counts{display:flex;flex-wrap:wrap;gap:6px}
.count{font-size:12px;color:var(--text2);background:var(--elev);border:1px solid var(--border);border-radius:999px;padding:3px 10px}
.count strong{color:var(--text);font-family:var(--mono)}
.count.zero{opacity:.55}

.meter{height:8px;border-radius:99px;background:var(--bg);overflow:hidden;border:1px solid var(--border-soft)}
.meter.small{height:6px;margin:8px 0 12px}
.meter-fill{height:100%;border-radius:99px}
.meter-fill.bad{background:var(--bad)}.meter-fill.warn{background:var(--warn)}.meter-fill.good{background:var(--good)}

.toc{display:flex;flex-wrap:wrap;gap:6px;margin-bottom:12px}
.toc a{font-size:12px;font-weight:600;color:var(--text2);text-decoration:none;background:var(--panel);border:1px solid var(--border);border-radius:999px;padding:6px 14px}
.toc a:hover{color:var(--accent);border-color:var(--accent-border)}
.defang-note{font-size:12px;color:var(--text2);background:var(--accent-bg);border:1px solid var(--accent-border);border-radius:var(--radius);padding:10px 14px;margin-bottom:16px}
.defang-note strong{color:var(--accent)}
.defang-note code{font-size:11px;padding:0 4px}

.panel{background:var(--panel);border:1px solid var(--border);border-radius:var(--radius);padding:22px 24px;margin-bottom:16px}
.panel h2{display:flex;align-items:center;gap:10px;font-size:12px;font-weight:600;letter-spacing:.1em;text-transform:uppercase;color:var(--text2);padding-bottom:12px;margin-bottom:18px;border-bottom:1px solid var(--border)}
.panel h2::before{content:"";width:3px;height:14px;border-radius:2px;background:var(--accent)}
h3{display:flex;align-items:center;gap:8px;flex-wrap:wrap;font-size:13px;font-weight:700;color:var(--text);margin:22px 0 10px}
.sub:first-child h3{margin-top:0}
.sub+.sub{border-top:1px dashed var(--border);margin-top:22px;padding-top:4px}
.badge{font-family:var(--mono);font-size:11px;font-weight:600;color:var(--text2);background:var(--elev);border:1px solid var(--border);border-radius:999px;padding:0 8px;letter-spacing:0;text-transform:none}
.empty{color:var(--muted);font-size:13px}
.lead{margin-bottom:10px}

.kv{display:grid;grid-template-columns:130px 1fr;gap:0}
.kv dt,.kv dd{padding:8px 0;border-bottom:1px solid var(--border-soft)}
.kv dt{font-size:12px;color:var(--muted)}
.kv dd{overflow-wrap:anywhere;min-width:0}
.kv dt:last-of-type,.kv dd:last-of-type{border-bottom:0}

.pill{display:inline-block;font-size:11px;font-weight:700;letter-spacing:.03em;text-transform:uppercase;border-radius:999px;padding:2px 9px;border:1px solid;white-space:nowrap;font-family:var(--mono)}
.pill.good{color:var(--good);background:var(--good-bg);border-color:var(--good-border)}
.pill.bad{color:var(--bad);background:var(--bad-bg);border-color:var(--bad-border)}
.pill.warn{color:var(--warn);background:var(--warn-bg);border-color:var(--warn-border)}
.pill.muted{color:var(--text2);background:var(--elev);border-color:var(--border)}

.callout{font-size:13px;border-radius:8px;padding:10px 14px;margin:10px 0;border:1px solid;border-left-width:3px}
.callout.good{color:var(--good);background:var(--good-bg);border-color:var(--good-border)}
.callout.bad{color:var(--bad);background:var(--bad-bg);border-color:var(--bad-border)}
.callout.warn{color:var(--warn);background:var(--warn-bg);border-color:var(--warn-border)}

.score-grid{display:grid;grid-template-columns:repeat(3,1fr);gap:14px;margin-top:4px}
.score-card{background:var(--elev);border:1px solid var(--border);border-radius:8px;padding:14px 16px}
.score-head{display:flex;justify-content:space-between;align-items:baseline}
.score-num{font-family:var(--mono);font-size:18px;font-weight:700}
.reasons{list-style:none;display:flex;flex-direction:column;gap:6px;font-size:13px}
.reasons li{position:relative;padding-left:14px;overflow-wrap:anywhere}
.reasons li::before{content:"";position:absolute;left:0;top:.62em;width:5px;height:5px;border-radius:50%;background:var(--muted)}
.reasons li.none{color:var(--muted);padding-left:0}.reasons li.none::before{display:none}

.mech-grid{display:grid;grid-template-columns:repeat(3,1fr);gap:12px}
.mech{background:var(--elev);border:1px solid var(--border);border-left:3px solid var(--muted);border-radius:8px;padding:12px 14px}
.mech.good{border-left-color:var(--good)}.mech.bad{border-left-color:var(--bad)}.mech.warn{border-left-color:var(--warn)}
.mech-head{display:flex;justify-content:space-between;align-items:center;margin-bottom:6px}
.mech-name{font-weight:700;letter-spacing:.06em}
.mech-detail{font-size:12px;color:var(--text2);overflow-wrap:anywhere}

.table-wrap{overflow-x:auto;border:1px solid var(--border);border-radius:8px}
table{width:100%;border-collapse:collapse;font-size:13px}
th{text-align:left;font-size:11px;font-weight:600;letter-spacing:.06em;text-transform:uppercase;color:var(--muted);background:var(--elev);padding:9px 12px;border-bottom:1px solid var(--border)}
td{padding:9px 12px;border-bottom:1px solid var(--border-soft);vertical-align:top;overflow-wrap:anywhere}
tbody tr:last-child td{border-bottom:0}
tbody tr:hover td{background:rgba(255,255,255,.015)}
.cmp{white-space:nowrap}.op{display:inline-block;margin:0 8px;font-weight:700;color:var(--accent)}
.hop{display:inline-flex;align-items:center;justify-content:center;min-width:24px;height:24px;border-radius:50%;background:var(--elev);border:1px solid var(--border);font-family:var(--mono);font-size:12px}

.path-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(230px,1fr));gap:12px}
.path{background:var(--elev);border:1px solid var(--border);border-radius:8px;padding:14px 16px}
.path.primary{border-color:var(--accent-border);box-shadow:inset 3px 0 0 var(--accent)}
.path-ip{margin-top:6px}.path-ip code{font-size:15px;font-weight:700;padding:3px 8px}
.path-host{margin-top:6px}
.lookup{font-size:12px;color:var(--text2);margin-top:8px}

.url-list{list-style:none;counter-reset:url;display:flex;flex-direction:column;gap:10px}
.url-card{position:relative;counter-increment:url;background:var(--elev);border:1px solid var(--border);border-radius:8px;padding:12px 14px 12px 48px}
.url-card::before{content:counter(url);position:absolute;left:14px;top:12px;min-width:22px;height:22px;display:flex;align-items:center;justify-content:center;border-radius:50%;background:var(--panel);border:1px solid var(--border);font-family:var(--mono);font-size:11px;color:var(--text2)}
.url-value code{display:block;width:fit-content;max-width:100%;font-size:12.5px;line-height:1.6;padding:3px 8px;word-break:break-all}
.url-meta{margin-top:6px;font-size:12px;display:flex;flex-wrap:wrap;align-items:center;gap:6px}
.sep{width:1px;height:14px;background:var(--border);margin:0 4px}
.destination{margin-top:10px;padding:10px 12px;border-radius:8px;background:var(--bg);border:1px dashed var(--accent-border)}

.file-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(320px,1fr));gap:12px}
.file-card{background:var(--elev);border:1px solid var(--border);border-radius:8px;padding:14px 16px}
.file-name{font-weight:700;overflow-wrap:anywhere}
.file-flags{margin:6px 0 4px}
.file-card .kv{grid-template-columns:80px 1fr}
.file-card .kv dt,.file-card .kv dd{padding:6px 0}

.foot{text-align:center;font-size:12px;color:var(--muted);margin-top:24px}

@media (max-width:720px){
  .wrap{padding:14px 12px 32px}
  .top{flex-direction:column;align-items:flex-start;padding:12px 14px}
  .generated{align-items:flex-start}
  .hero{grid-template-columns:1fr;gap:16px;padding:18px}
  .hero-tier{font-size:26px}
  .panel{padding:16px}
  .score-grid,.mech-grid{grid-template-columns:1fr}
  .kv{grid-template-columns:1fr}
  .kv dt{border-bottom:0;padding-bottom:0}
  .file-grid{grid-template-columns:1fr}
  .toc a{padding:8px 14px}
  .table-wrap{border:0;overflow:visible}
  table,thead,tbody,tr,td{display:block;width:100%}
  thead{display:none}
  tbody tr{background:var(--elev);border:1px solid var(--border);border-radius:8px;padding:8px 12px;margin-bottom:8px}
  td{border:0;padding:4px 0}
  td::before{content:attr(data-label);display:block;font-size:11px;font-weight:600;letter-spacing:.06em;text-transform:uppercase;color:var(--muted)}
  tbody tr:hover td{background:transparent}
  .cmp{white-space:normal}
  .url-card{padding-left:44px}
}

@media print{
  :root{--bg:#fff;--panel:#fff;--elev:#f6f8fa;--surface:#eaeef2;--border:#d0d7de;--border-soft:#eaeef2;--text:#1f2328;--text2:#57606a;--muted:#6e7781;
    --accent:#2f7d0f;--accent-bg:#f0f9e8;--accent-border:#b7dca0;--good:#1a7f37;--good-bg:#e6f4ea;--good-border:#a6d8b3;
    --bad:#cf222e;--bad-bg:#ffebe9;--bad-border:#ffcecb;--warn:#9a6700;--warn-bg:#fff8c5;--warn-border:#eed888}
  *{-webkit-print-color-adjust:exact;print-color-adjust:exact}
  body{font-size:12px}
  .wrap{max-width:none;padding:0}
  .toc{display:none}
  .panel,.hero,.top{box-shadow:none;break-inside:auto}
  h2,h3{break-after:avoid}
  tr,.url-card,.file-card,.mech,.score-card,.path,.callout{break-inside:avoid}
  code.ioc{background:#f0f9e8}
}
`;

// ===== CSV =====

export const CSV_COLUMNS = [
  "type",
  "indicator",
  "source",
  "risk_flags",
  "details",
  "virustotal",
  "abuseipdb",
  "registration",
];

/**
 * One indicator per row, a fixed column set so imports do not break between
 * reports. RFC 4180 quoting, CRLF line endings, and a UTF-8 byte-order mark so
 * Excel reads non-ASCII (punycode reveals, subjects) correctly.
 */
export function buildCsvReport(analysis, { lookups = new Map(), local = new Map(), includeRaw = false } = {}) {
  const iocs = analysis.iocs || {};
  const vt = (v) => lookups.get(`vt:${v}`) || "";
  const abuse = (v) => lookups.get(`abuse:${v}`) || "";
  // Registration and DNS answers the analyst already pulled up, if any.
  const whois = (v) => local.get(`whois:${v}`) || "";
  const dnsOf = (v) => local.get(`dns:${v}`) || "";
  const flags = (it) => flagsOf(it).join("; ");
  const rows = [];
  const add = (type, raw, defanged, source, riskFlags, details, lookupKey = raw) => {
    const row = [
      type,
      defanged,
      source || "",
      riskFlags || "",
      details || "",
      vt(lookupKey),
      abuse(lookupKey),
      whois(lookupKey),
    ];
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

/**
 * The same analysis as structured data, for a SIEM, MISP, a ticket system or a
 * script. Indicators are given both live and defanged: a pipeline needs the
 * real value, a human reading the file does not.
 */
export function buildJsonReport(analysis, { lookups = new Map(), local = new Map(), now = new Date() } = {}) {
  const hd = analysis.headers || {};
  const auth = analysis.auth || {};
  const iocs = analysis.iocs || {};
  const score = analysis.score || {};
  const enrich = (value) => {
    const out = {};
    const vt = lookups.get(`vt:${value}`);
    const abuse = lookups.get(`abuse:${value}`);
    const whois = local.get(`whois:${value}`);
    const dns = local.get(`dns:${value}`);
    if (vt) out.virustotal = vt;
    if (abuse) out.abuseipdb = abuse;
    if (whois) out.registration = whois;
    if (dns) out.dns = dns;
    return Object.keys(out).length ? out : undefined;
  };
  const item = (value, defanged, extra = {}) => ({
    indicator: value,
    defanged,
    ...extra,
    lookups: enrich(value),
  });

  return JSON.stringify(
    {
      tool: "Phishing Email Analyzer",
      generated: now.toISOString(),
      verdict: {
        tier: score.tier || "Unknown",
        score: score.score ?? null,
        breakdown: score.breakdown || {},
        reasons: score.reasons || [],
        caveats: score.caveats || [],
      },
      message: {
        subject: hd.subject || null,
        from: hd.from?.email || null,
        fromName: hd.from?.name || null,
        replyTo: hd.replyTo?.email || null,
        returnPath: hd.returnPath?.email || null,
        to: hd.to?.email || null,
        date: hd.date || null,
        messageId: hd.messageId || null,
      },
      authentication: {
        spf: auth.mechanisms?.spf || null,
        dkim: auth.mechanisms?.dkim || null,
        dmarc: auth.mechanisms?.dmarc || null,
        alignment: auth.domainAlignment
          ? {
              fromDomain: auth.domainAlignment.fromDomain,
              dmarcAligned: auth.domainAlignment.dmarcAligned,
              entries: auth.domainAlignment.entries,
              mismatches: auth.domainAlignment.mismatches,
            }
          : null,
        trustWarnings: auth.trust?.warnings || [],
        anomalies: auth.anomalies || [],
        arc: auth.arc || null,
        senderIp: auth.senderIp || null,
        receivedChain: (auth.receivedChain || []).map((h) => ({
          hop: h.number,
          from: h.from,
          by: h.by,
          ip: h.ip,
          date: h.date,
          warnings: h.warnings,
        })),
      },
      identity: analysis.identity?.findings || [],
      language: analysis.languageAnalysis
        ? Object.fromEntries(
            Object.entries(analysis.languageAnalysis.categories || {})
              .filter(([, c]) => c.matchCount)
              .map(([k, c]) => [k, { label: c.label, count: c.matchCount, phrases: (c.matches || []).map((m) => m.phrase) }]),
          )
        : {},
      indicators: {
        urls: (iocs.urls || []).map((u) =>
          item(u.value, defangUrl(u.value), {
            source: u.source || null,
            flags: flagsOf(u),
            unwrappedFrom: u.unwrappedFrom || undefined,
          }),
        ),
        domains: (iocs.domains || []).map((d) =>
          item(d.value, defangDomain(d.value), { source: d.source || null, flags: flagsOf(d) }),
        ),
        ips: (iocs.ips || []).map((i) =>
          item(i.value, defangIp(i.value), { source: i.source || null, flags: flagsOf(i), private: !!i.private }),
        ),
        emails: (iocs.emails || []).map((e) =>
          item(e.value, defangEmail(e.value), { source: e.source || null, flags: flagsOf(e) }),
        ),
        files: (iocs.attachments || []).map((f) => ({
          filename: f.value || null,
          contentType: f.contentType || null,
          size: f.size ?? null,
          inline: !!f.inline,
          sha256: f.sha256 || null,
          md5: f.md5 || null,
          flags: flagsOf(f),
          lookups: enrich(f.value),
        })),
        deceptiveLinks: (iocs.mismatchedLinks || []).map((l) => ({
          displays: l.text || null,
          destination: l.href || null,
          defanged: defangUrl(l.href || ""),
        })),
      },
    },
    null,
    2,
  );
}

function csvCell(value) {
  let s = value == null ? "" : String(value);
  // A cell starting with = + - @ is evaluated as a formula by spreadsheet
  // software. An IOC report is exactly the file an attacker would like to get
  // a formula into.
  if (/^[=+\-@\t\r]/.test(s)) s = `'${s}`;
  return /[",\r\n]/.test(s) || s !== s.trim() ? `"${s.replace(/"/g, '""')}"` : s;
}
