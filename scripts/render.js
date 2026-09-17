import { isValidIP, isRoutableIP, findIPs } from "./ip-utils.js";
import { URL_DECODERS, detectEncodings, safeRun } from "./url-decode.js";

// Rows rendered per IOC table before the rest are collapsed behind a button.
// A bulk HTML email routinely carries 100+ links; rendering them all built
// thousands of table rows and inline SVGs in a single innerHTML assignment.
const IOC_ROW_LIMIT = 50;

// ===== FOCUSED SUMMARY =====
export async function renderSummary(container, analysis, apiKeys) {
  const h = analysis.headers;
  const auth = analysis.auth;
  const iocs = analysis.iocs;
  const lang = analysis.languageAnalysis;

  const from = h.from?.email || "N/A";
  // Only a real Reply-To header. This used to fall back to Return-Path, so the
  // card labelled "Reply-To" silently showed a different header's address.
  const replyTo = h.replyTo?.email || null;
  const sip = extractSenderIP(h);
  const sd = extractDomain(from);
  const rd = replyTo ? extractDomain(replyTo) : null;
  const dm = !!rd && rd !== sd;

  // Get auth statuses
  const spfStatus = auth?.mechanisms?.spf?.status || "unknown";
  const dkimStatus = auth?.mechanisms?.dkim?.status || "unknown";
  const dmarcStatus = auth?.mechanisms?.dmarc?.status || "unknown";
  // dmarcAligned is the real verdict: DMARC needs one authenticated mechanism
  // to align, not every source to match. A differing Reply-To is reported on
  // its own card and does not make the message "MISMATCHED".
  const dmarcAligned = auth?.domainAlignment?.dmarcAligned;
  const alignLabel =
    dmarcAligned === true
      ? "ALIGNED"
      : dmarcAligned === false
        ? "MISMATCHED"
        : "NO DATA";
  const alignClass =
    dmarcAligned === true ? "pass" : dmarcAligned === false ? "fail" : "none";

  // Count IOCs
  const urlCount = iocs?.urls?.length || 0;
  const ipCount = iocs?.ips?.length || 0;
  const domainCount = iocs?.domains?.length || 0;
  const emailCount = iocs?.emails?.length || 0;
  const attCount = iocs?.attachments?.length || 0;
  const hasHighRisk = (iocs?.urls || []).some(u => u.riskFlags?.some(f => f.type === "high"));

  let html = '';

  // === VERDICT STRIP ===
  // The one question the summary exists to answer, answered first. It was
  // previously only in the separate Analysis Result panel further down.
  const sc = analysis.score || {};
  const tierClass =
    sc.tier === "High Risk" ? "tier-high" : sc.tier === "Suspicious" ? "tier-medium" : "tier-low";
  const topReasons = (sc.reasons || []).slice(0, 3);
  html += `<div class="summary-verdict ${tierClass}">
    <div class="summary-verdict-main"><span class="summary-verdict-tier">${esc(sc.tier || "Unknown")}</span><span class="summary-verdict-score">${sc.score ?? 0}/100</span></div>
    ${topReasons.length ? `<ul class="summary-verdict-reasons">${topReasons.map((r) => `<li>${esc(r)}</li>`).join("")}</ul>` : ""}
    ${(sc.caveats || []).map((c) => `<div class="summary-caveat">&#9888; ${esc(c)}</div>`).join("")}
  </div>`;

  // === TOP ROW: Auth badges + Score ===
  html += '<div class="summary-top-row">';

  // Authentication badges
  html += `<div class="summary-auth-card">
    <div class="auth-card-header">
      <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
      <span>Authentication</span>
    </div>
    <div class="auth-badges-row">
      <span class="auth-badge-pill ${spfStatus}">SPF ${esc(spfStatus.toUpperCase())}</span>
      <span class="auth-badge-pill ${dkimStatus}">DKIM ${esc(dkimStatus.toUpperCase())}</span>
      <span class="auth-badge-pill ${dmarcStatus}">DMARC ${esc(dmarcStatus.toUpperCase())}</span>
      <span class="auth-badge-pill ${alignClass}">${alignLabel}</span>
    </div>
  </div>`;

  // IOC summary mini-card
  html += `<div class="summary-ioc-card">
    <div class="ioc-card-header">
      <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>
      <span>IOCs Found</span>
    </div>
    <div class="ioc-count-grid">
      ${urlCount ? `<div class="ioc-count-item ${hasHighRisk ? 'high' : ''}"><span class="ioc-count-num">${urlCount}</span><span class="ioc-count-label">URLs</span></div>` : ''}
      ${domainCount ? `<div class="ioc-count-item"><span class="ioc-count-num">${domainCount}</span><span class="ioc-count-label">Domains</span></div>` : ''}
      ${ipCount ? `<div class="ioc-count-item"><span class="ioc-count-num">${ipCount}</span><span class="ioc-count-label">IPs</span></div>` : ''}
      ${emailCount ? `<div class="ioc-count-item"><span class="ioc-count-num">${emailCount}</span><span class="ioc-count-label">Emails</span></div>` : ''}
      ${attCount ? `<div class="ioc-count-item ${iocs.attachments.some(a => isRiskyExt(a.value)) ? 'high' : ''}"><span class="ioc-count-num">${attCount}</span><span class="ioc-count-label">Files</span></div>` : ''}
      ${(!urlCount && !domainCount && !ipCount && !emailCount && !attCount) ? '<div class="ioc-count-item"><span class="ioc-count-num">0</span><span class="ioc-count-label">None</span></div>' : ''}
    </div>
  </div>`;

  html += '</div>';

  // === BOTTOM ROW: Sender details ===
  html += '<div class="summary-bottom-row">';

  // The sender card must not look safe for a spoofed From. Whether the From
  // domain is genuine is exactly what DMARC decides.
  const dmarc = auth?.mechanisms?.dmarc?.status;
  const spoofed = dmarc === "fail" || dmarcAligned === false;
  const verifiedSender = dmarc === "pass" && dmarcAligned === true;
  const lookalike = isSuspiciousDomain(sd);
  html += mkCard(
    "Sender",
    "user",
    [
      { l: "From", v: trunc(from, 40), t: from, m: 1 },
      { l: "Domain", v: sd, m: 1, c: lookalike ? "suspicious" : "" },
      spoofed
        ? { l: "Authenticity", v: "Not verified — fails DMARC", c: "malicious" }
        : verifiedSender
          ? { l: "Authenticity", v: "Verified by DMARC", c: "verified" }
          : { l: "Authenticity", v: "Could not be verified", c: "suspicious" },
    ],
    spoofed || lookalike ? "high" : verifiedSender ? "low" : "medium",
  );

  // Reply-To is informational in DMARC terms, so a differing domain is a
  // caution (amber), not a failure (red).
  html += mkCard(
    "Reply-To",
    "edit",
    replyTo
      ? [
          { l: "Address", v: trunc(replyTo, 40), t: replyTo, m: 1, c: dm ? "suspicious" : "" },
          dm
            ? { l: "Note", v: "Replies go to a different domain", c: "suspicious" }
            : { l: "Note", v: "Same domain as From", c: "verified" },
        ]
      : [{ l: "Address", v: "None — replies go to From" }],
    dm ? "medium" : "neutral",
  );

  html += mkCard(
    "Message",
    "file",
    [
      { l: "Subject", v: trunc(h.subject || "(no subject)", 60), t: h.subject || "" },
      { l: "Date", v: h.date ? trunc(h.date, 40) : "N/A", t: h.date || "" },
      ...(h.xMailer ? [{ l: "Mailer", v: trunc(h.xMailer, 40), t: h.xMailer, m: 1 }] : []),
    ],
    "neutral",
  );

  html += '</div>';

  // === SENDER IP ===
  // The originating IP is the one that matters: Received headers are prepended,
  // so the LAST one is where the message entered the mail system. The card
  // previously showed it under the misleading label "Last Hop".
  const chain = auth?.receivedChain || [];
  const senderIp = auth?.senderIp || {};
  const relay = chain.find((h) => isValidIP(h.ip)) || null;

  // The public address the message left the sender's network from. When the
  // originating hop is private (NAT, internal submission relay) the walk
  // continues outward until a routable address is found.
  const originIp = senderIp.publicIp || (isRoutableIP(sip) ? sip : null);
  const originHost = senderIp.publicHop?.from || null;
  const internalIp = senderIp.privateIp;
  const relayIp = relay?.ip || null;
  const showRelay = relayIp && relayIp !== originIp && relayIp !== internalIp;
  const originLabel = originIp || "No public IP recorded in these headers";

  // originIp is public by construction now, so the border flags the odd case:
  // a chain that records no public address at all.
  html += `<div class="summary-card summary-ip-card ${chain.length && !originIp ? "risk-border-high" : "risk-border-neutral"}" data-lookup-scope>
    <div class="card-header">
      <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">${ICONS.globe}</svg>
      <h3>Sender IP</h3>
    </div>
    <div class="ip-primary">
      <div class="ip-label">Originating IP <span class="ip-hint">(the sender's public address)</span></div>
      <div class="ip-value-row">
        <span class="ip-value mono ${originIp ? "" : "muted"}">${esc(originLabel)}</span>
        ${ipLookupButtons(originIp, apiKeys)}
      </div>
      ${originHost ? `<div class="ip-host mono">${esc(originHost)}</div>` : ""}
      ${
        internalIp
          ? `<div class="ip-internal">First hop recorded <span class="mono">${esc(internalIp)}</span>, a private address${senderIp.privateHopsSkipped ? ` (plus ${senderIp.privateHopsSkipped} more private hop${senderIp.privateHopsSkipped > 1 ? "s" : ""})` : ""}. ${originIp ? "Walked outward to the first public address above." : "No public address appears anywhere in the chain."}</div>`
          : ""
      }
    </div>
    ${
      showRelay
        ? `<div class="ip-secondary">
      <div class="ip-label">Last relay <span class="ip-hint">(the server that delivered to you)</span></div>
      <div class="ip-value-row">
        <span class="ip-value mono">${esc(relayIp)}</span>
        ${ipLookupButtons(relayIp, apiKeys)}
      </div>
    </div>`
        : ""
    }
    <div class="lookup-result-content"></div>
  </div>`;

  container.innerHTML = html;
}

/**
 * VirusTotal + AbuseIPDB buttons for a single IP, outside the IOC table.
 *
 * Nothing is offered for an address the services cannot answer for. Sending a
 * malformed or private address just produces a vendor error in the panel.
 */
function ipLookupButtons(ip, apiKeys) {
  if (!isValidIP(ip)) return "";
  if (!isRoutableIP(ip)) {
    return `<span class="ip-actions"><button class="btn-sm" onclick="copyText('${esc(ip)}', this)" title="Copy">Copy</button><span class="ip-note">private/reserved — not published in reputation data</span></span>`;
  }

  const vt = apiKeys?.virustotal
    ? `<button class="btn-ioc-lookup btn-vt" data-value="${esc(ip)}" data-type="ip" onclick="lookupVirusTotal(this)" title="Check this IP on VirusTotal">VT</button>`
    : `<button class="btn-ioc-lookup btn-vt disabled" onclick="promptSettings()" title="Add a VirusTotal API key in Settings">VT</button>`;
  const abuse = apiKeys?.abuseipdb
    ? `<button class="btn-ioc-lookup btn-abuse" data-value="${esc(ip)}" onclick="lookupAbuseIPDB(this)" title="Check this IP on AbuseIPDB">AbuseIPDB</button>`
    : `<button class="btn-ioc-lookup btn-abuse disabled" onclick="promptSettings()" title="Add an AbuseIPDB API key in Settings">AbuseIPDB</button>`;
  const copy = `<button class="btn-sm" onclick="copyText('${esc(ip)}', this)" title="Copy">Copy</button>`;
  return `<span class="ip-actions">${copy}${vt}${abuse}</span>`;
}

const ICONS = {
  user: `<path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/>`,
  edit: `<path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"/><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"/>`,
  globe: `<circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/>`,
  shield: `<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>`,
  link: `<path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"/><path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"/>`,
  file: `<path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/><polyline points="10 9 9 9 8 9"/>`,
  clip: `<path d="M21.44 11.05l-9.19 9.19a6 6 0 0 1-8.49-8.49l9.19-9.19a4 4 0 0 1 5.66 5.66l-9.2 9.19a2 2 0 0 1-2.83-2.83l8.49-8.48"/>`,
};

function mkCard(title, iconKey, rows, risk) {
  const rh = rows
    .map((r) => {
      if (r.r) return `<div class="summary-row">${r.v}</div>`;
      // r.t is an untrusted header value (a From address). Unescaped it broke
      // out of the title attribute on any address containing a double quote.
      return `<div class="summary-row"><span class="label">${esc(r.l)}</span><span class="value ${r.m ? "mono" : ""} ${r.c || ""}" title="${esc(r.t || "")}">${esc(r.v)}</span></div>`;
    })
    .join("");

  return `<div class="summary-card risk-border-${risk}">
    <div class="card-header">
      <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">${ICONS[iconKey] || ""}</svg>
      <h3>${esc(title)}</h3>
    </div>
    ${rh}
  </div>`;
}

function trunc(s, m) {
  return !s || typeof s !== "string"
    ? "N/A"
    : s.length > m
      ? s.slice(0, m) + "..."
      : s;
}
function isSuspiciousDomain(d) {
  return d && d !== "N/A" && (d.startsWith("xn--") || /^\d/.test(d));
}
function isRiskyExt(f) {
  if (!f) return false;
  const r = [
    ".exe",
    ".scr",
    ".js",
    ".hta",
    ".vbs",
    ".bat",
    ".cmd",
    ".ps1",
    ".dll",
    ".jar",
  ];
  const l = f.toLowerCase();
  return r.some((e) => l.endsWith(e)) || /\.\w+\.\w{3,4}$/.test(l);
}
function extractDomain(e) {
  if (!e) return "N/A";
  const s = typeof e === "string" ? e : e?.email || e?.raw || "";
  const m = s.match(/@([^>\s]+)/);
  return m ? m[1] : "N/A";
}
function extractSenderIP(h) {
  const r = h.received;
  if (!r || !r.length) return "N/A";
  return findIPs(String(r[r.length - 1]))[0] || "N/A";
}

function renderLangFlags(a) {
  if (!a || !a.categories)
    return '<p style="color:var(--muted);font-size:12px;">No suspicious language detected</p>';
  const flags = Object.entries(a.categories)
    .filter(([, c]) => c.matchCount > 0)
    .map(
      ([n, c]) =>
        `<div class="lang-flag"><span class="flag-name">${esc(n)}</span><span class="flag-count">${c.matchCount}</span></div>`,
    );
  return flags.length
    ? flags.join("")
    : '<p style="color:var(--muted);font-size:12px;">No suspicious language detected</p>';
}

// ===== VERDICT =====
export function renderVerdict(c, sc, langAnalysis) {
  if (!sc) {
    c.innerHTML = "<p>No score data</p>";
    return;
  }
  const tc =
    sc.tier === "High Risk"
      ? "tier-high"
      : sc.tier === "Suspicious"
        ? "tier-medium"
        : "tier-low";
  const langFlagsHtml = langAnalysis ? renderLangFlags(langAnalysis) : "";

  // Each category shows its bar and, directly beneath it, the reasons that
  // produced it — instead of one centred cloud of every reason at once. A bar
  // is coloured by how bad its score is; a full green bar read as "all good".
  const groups = sc.reasonGroups || { auth: sc.reasons || [], iocs: [], language: [] };
  const labels = { auth: "Authentication", iocs: "Indicators", language: "Language" };
  const severity = (v) => (v >= 60 ? "high" : v >= 30 ? "medium" : "low");
  const columns = ["auth", "iocs", "language"]
    .map((k) => {
      const v = sc.breakdown?.[k] || 0;
      const reasons = groups[k] || [];
      return `<div class="score-item"><div class="score-head"><span class="score-label">${labels[k]}</span><span class="score-value">${v}</span></div><div class="score-bar"><div class="score-fill ${severity(v)}" style="width:${v}%"></div></div><ul class="score-reasons">${reasons.length ? reasons.map((r) => `<li>${esc(r)}</li>`).join("") : '<li class="none">Nothing found</li>'}</ul></div>`;
    })
    .join("");

  const caveats = (sc.caveats || [])
    .map((cv) => `<div class="verdict-caveat">&#9888; ${esc(cv)}</div>`)
    .join("");

  c.innerHTML = `<div class="verdict-box ${tc}"><div class="verdict-tier">${esc(sc.tier || "Unknown")}</div><div class="verdict-score">Score: ${sc.score || 0}/100</div>${caveats}</div><div class="score-breakdown">${columns}</div>${langFlagsHtml ? `<div class="lang-flags-section"><h4>Language Flags</h4>${langFlagsHtml}</div>` : ""}`;
}

// Colour per authentication result. "unverified", "neutral", "permerror" and
// "temperror" are distinct states now, and each needs to read differently from
// a clean pass and from an outright failure.
const STATUS_STYLES = {
  pass: { cls: "pass", color: "#22c55e" },
  fail: { cls: "fail", color: "#ef4444" },
  softfail: { cls: "softfail", color: "#f59e0b" },
  permerror: { cls: "softfail", color: "#f59e0b" },
  temperror: { cls: "none", color: "#9ca3af" },
  neutral: { cls: "none", color: "#9ca3af" },
  unverified: { cls: "softfail", color: "#f59e0b" },
  none: { cls: "none", color: "#9ca3af" },
  unknown: { cls: "none", color: "#9ca3af" },
};

function statusStyle(s) {
  return STATUS_STYLES[s] || STATUS_STYLES.unknown;
}

/**
 * Both SPF headers side by side, with the IP each evaluated, whether they
 * agree, and how that IP relates to the sender's public IP.
 */
function renderSpfSources(spf) {
  const rows = spf.sources
    .map((s) => {
      const { color } = statusStyle(s.status);
      return `<div class="spf-src">
        <div class="spf-src-head"><span class="spf-src-name">${esc(s.header)}</span><span class="spf-src-result" style="color:${color}">${esc((s.rawResult || s.status).toUpperCase())}</span></div>
        <div class="spf-src-line">IP <span class="mono">${esc(s.ip || "not recorded")}</span></div>
        ${s.identity ? `<div class="spf-src-line">for <span class="mono">${esc(s.identity)}</span></div>` : ""}
      </div>`;
    })
    .join("");

  let agreement;
  if (spf.sources.length < 2) {
    agreement = `<div class="spf-verdict muted">Only ${esc(spf.sources[0].header)} is present — nothing to cross-check.</div>`;
  } else if (spf.resultsAgree && spf.ipsAgree !== false) {
    agreement = `<div class="spf-verdict ok">✓ Both headers agree${spf.ip ? ` on <span class="mono">${esc(spf.ip)}</span>` : ""}</div>`;
  } else {
    const parts = [];
    if (spf.resultsAgree === false) parts.push("results differ");
    if (spf.ipsAgree === false) parts.push("checked different IPs");
    agreement = `<div class="spf-verdict bad">⚠ Headers disagree — ${parts.join(" and ")}. Authentication-Results decides the status above.</div>`;
  }

  let sender = "";
  if (spf.senderPublicIp) {
    const rel =
      spf.matchesSenderIp === true
        ? '<span class="verified">✓ same IP SPF checked</span>'
        : spf.matchesSenderIp === false
          ? '<span class="muted">≠ SPF checked a relay, not the origin (normal for ESPs and forwarding)</span>'
          : "";
    sender = `<div class="spf-sender">Sender public IP <span class="mono">${esc(spf.senderPublicIp)}</span> ${rel}</div>`;
  }

  return `<div class="spf-sources">${rows}</div>${agreement}${sender}`;
}

// ===== AUTHENTICATION =====
export function renderAuth(c, auth) {
  if (!auth) {
    c.innerHTML = "<p>No authentication data</p>";
    return;
  }
  const mech = auth.mechanisms || {};
  const align = auth.domainAlignment || {};
  const recv = auth.receivedChain || [];

  // Render mechanism badges with colored indicators
  const mechHtml = Object.entries(mech)
    .map(([n, r]) => {
      const s = r.status || "none";
      const { cls, color } = statusStyle(s);
      // SPF gets a per-header breakdown: its two headers can disagree, and
      // showing only the winner hides exactly the case worth seeing.
      const body =
        n === "spf" && auth.spf?.sources?.length
          ? renderSpfSources(auth.spf)
          : `${r.details ? `<div class="mech-details">${esc(r.details)}</div>` : ""}${r.source ? `<div class="mech-source">via ${esc(r.source)}</div>` : ""}`;
      return `<div class="auth-mech ${cls}" style="border-left:4px solid ${color}"><div class="mech-name">${esc(n.toUpperCase())}</div><div class="mech-status" style="color:${color};font-weight:700">${esc(s.toUpperCase())}</div>${body}</div>`;
    })
    .join("");

  // Each row spells the comparison out — "Return-Path (x) = From (y)" — and
  // says why it did or did not align, rather than a bare ALIGNED/MISMATCH.
  const fromDomain = align.fromDomain;
  const alignRows = (align.entries || [])
    .map((e) => {
      const check = e.source.startsWith("DKIM")
        ? `DKIM<div class="align-note">signing domain vs From</div>`
        : e.source === "Return-Path"
          ? `SPF<div class="align-note">envelope sender vs From</div>`
          : `${esc(e.source)}<div class="align-note">not a DMARC input</div>`;

      const comparison = `<span class="align-side">${esc(e.source)} <span class="mono">(${esc(e.domain)})</span></span><span class="align-op">${e.aligned ? "=" : "≠"}</span><span class="align-side">From <span class="mono">(${esc(fromDomain || "none")})</span></span>`;

      let result;
      if (!fromDomain) {
        result = '<span class="muted">No From domain to compare</span>';
      } else if (e.strict) {
        result = `<span class="verified">✓ ALIGNED</span><div class="align-why">strict — identical domains</div>`;
      } else if (e.relaxed) {
        result = `<span class="verified">✓ ALIGNED</span><div class="align-why">relaxed — both under <span class="mono">${esc(e.orgDomain)}</span></div>`;
      } else {
        result = `<span class="${e.dmarcRelevant ? "malicious" : "muted"}">✗ NOT ALIGNED</span><div class="align-why">organizational domains differ: <span class="mono">${esc(e.orgDomain || "?")}</span> ≠ <span class="mono">${esc(align.fromOrgDomain || "?")}</span></div>`;
      }

      // Alignment only counts toward DMARC if the mechanism itself passed.
      if (e.dmarcRelevant && e.aligned && !e.mechanismPassed) {
        const mech = e.source === "Return-Path" ? "SPF" : "DKIM";
        result += `<div class="align-why warn">but ${mech} did not pass, so this does not satisfy DMARC</div>`;
      }

      const cls = e.dmarcRelevant && !e.aligned ? "mismatch-row" : "";
      return `<tr class="${cls}"><td>${check}</td><td class="align-compare">${comparison}</td><td>${result}</td></tr>`;
    })
    .join("");

  const verdict =
    align.dmarcAligned === true
      ? '<p class="align-verdict verified">Domain alignment satisfied — at least one authenticated mechanism matches the From domain.</p>'
      : align.dmarcAligned === false
        ? '<p class="align-verdict malicious">No authenticated mechanism aligns with the From domain.</p>'
        : '<p class="align-verdict muted">Not enough information to evaluate alignment.</p>';

  // hop.number is assigned so hop 1 is where the message originated; the array
  // is in header order, which is the reverse.
  const recvHtml = recv
    .map(
      (hop) =>
        `<div class="received-hop ${hop.suspicious ? "suspicious-hop" : ""}"><div class="hop-num">${hop.number}</div><div class="hop-details"><div class="hop-from">From: ${esc(hop.from || "N/A")}${hop.isOrigin ? ' <span class="hop-tag">origin</span>' : ""}</div><div class="hop-by">By: ${esc(hop.by || "N/A")}</div><div class="hop-ip">IP: <span class="mono">${esc(hop.ip || "N/A")}</span></div><div class="hop-date">${esc(hop.date || "N/A")}</div>${(hop.warnings || []).map((w) => `<div class="hop-warning">&#9888; ${esc(w)}</div>`).join("")}</div></div>`,
    )
    .join("");

  const trustHtml = (auth.trust?.warnings || []).length
    ? `<div class="auth-section"><h3>Header Trust</h3><div class="trust-warnings">${auth.trust.warnings
        .map((w) => `<div class="trust-warning">&#9888; ${esc(w)}</div>`)
        .join("")}</div></div>`
    : "";

  const sourceNote = auth.trust?.authservId
    ? `<p class="auth-source-note">Results reported by <span class="mono">${esc(auth.trust.authservId)}</span>${auth.trust.authResultsCount > 1 ? ` — ${auth.trust.authResultsCount} Authentication-Results headers present, only the topmost is trusted.` : "."}</p>`
    : "";

  c.innerHTML = `<div class="auth-section"><h3>Mechanism Results</h3>${sourceNote}<div class="auth-mechanisms">${mechHtml || "<p>No auth data</p>"}</div></div>${trustHtml}<div class="auth-section"><h3>Domain Alignment</h3>${verdict}<div class="table-scroll"><table class="alignment-table"><thead><tr><th>Check</th><th>Comparison</th><th>Result</th></tr></thead><tbody>${alignRows || '<tr><td colspan="3">No alignment data</td></tr>'}</tbody></table></div></div><div class="auth-section"><h3>Received Chain</h3><div class="received-chain">${recvHtml || "<p>No received chain data</p>"}</div></div>`;
}

// ===== IOCS =====
// Section contents are kept so "show all" can re-render one section on demand
// instead of building every row up front.
const iocSectionData = new Map();

export function renderIOCs(container, iocs, apiKeys) {
  if (!iocs) {
    container.innerHTML = "<p>No IOCs found</p>";
    return;
  }
  iocSectionData.clear();
  const sections = [];

  const add = (title, items, type) => {
    if (!items?.length) return;
    const id = `ioc-sec-${iocSectionData.size}`;
    iocSectionData.set(id, { title, items, type, apiKeys });
    sections.push(renderIOCSection(id, title, items, type, apiKeys, false));
  };

  add("URLs", iocs.urls, "url");
  add("Domains", iocs.domains, "domain");
  add("IP Addresses", iocs.ips, "ip");
  add("Email Addresses", iocs.emails, "email");
  add("Attachments", iocs.attachments, "attachment");

  if (iocs.mismatchedLinks?.length)
    sections.push(renderMismatchedLinks(iocs.mismatchedLinks));

  container.innerHTML = sections.join("") || "<p>No IOCs found</p>";
}

/**
 * Fill a URL's decoder panel the first time it is opened. Decoders that find
 * something in this URL are highlighted; the rest stay clickable so the
 * analyst can confirm there is nothing there. Wired to window in main.js.
 */
export function renderDecoders(details) {
  if (!details.open) return;
  const body = details.querySelector(".decode-body");
  if (!body || body.dataset.ready) return;
  body.dataset.ready = "1";

  const found = detectEncodings(details.dataset.url);
  const buttons = URL_DECODERS.map(
    (d) =>
      `<button type="button" class="decode-btn${d.id === "all" || found.includes(d.id) ? " applies" : ""}" onclick="runDecoder(this, '${d.id}')">${esc(d.label)}</button>`,
  ).join("");
  body.innerHTML = `<div class="decode-buttons">${buttons}</div><div class="decode-result" hidden></div>`;
}

/** Run one decoder against the panel's URL and show the result. */
export function runDecoder(btn, id) {
  const details = btn.closest(".url-decode");
  const result = details?.querySelector(".decode-result");
  const decoder = URL_DECODERS.find((d) => d.id === id);
  if (!result || !decoder) return;

  details
    .querySelectorAll(".decode-btn")
    .forEach((b) => b.classList.toggle("active", b === btn));

  const r = safeRun(decoder.run, details.dataset.url);
  result.hidden = false;
  if (!r) {
    result.innerHTML = `<div class="decode-empty">${esc(decoder.label)}: nothing to decode in this URL.</div>`;
    return;
  }
  result.innerHTML = `${r.note ? `<div class="decode-note">${esc(r.note)}</div>` : ""}<pre class="decode-output mono">${esc(r.output)}</pre><button type="button" class="btn-sm" onclick="copyText(this.previousElementSibling.textContent, this)">Copy</button>`;
}

/** Re-render one IOC section with every row shown. Wired to window in main.js. */
export function showAllIOCs(id) {
  const data = iocSectionData.get(id);
  const el = document.getElementById(id);
  if (!data || !el) return;
  el.outerHTML = renderIOCSection(
    id,
    data.title,
    data.items,
    data.type,
    data.apiKeys,
    true,
  );
}

function renderIOCSection(id, title, items, type, apiKeys, showAll) {
  const shown = showAll ? items : items.slice(0, IOC_ROW_LIMIT);
  const hiddenCount = items.length - shown.length;

  const rows = shown
    .map((item) => {
      const value =
        typeof item === "string"
          ? item
          : item.value ||
            item.url ||
            item.domain ||
            item.ip ||
            item.filename ||
            "N/A";
      const riskFlags = item.riskFlags || [];
      const riskHtml = riskFlags
        .map((f) => `<span class="risk-tag ${f.type}">${esc(f.label)}</span>`)
        .join("");
      const defanged = defang(value);
      const hasVtKey = apiKeys?.virustotal;
      const hasAbuseKey = apiKeys?.abuseipdb;

      // A private or reserved address has no reputation data to fetch, so no
      // lookup button is offered for one. Declared before the buttons that
      // read it.
      const lookupUseless = type === "ip" && !isRoutableIP(value);

      // Files carry their hash on the button so a VirusTotal lookup needs no
      // re-derivation, and the hash is visible without clicking anything.
      const shaAttr =
        type === "attachment" && item.sha256
          ? ` data-sha256="${esc(item.sha256)}"`
          : "";
      const hashHtml =
        type === "attachment"
          ? `<div class="ioc-hashes">${
              item.sha256
                ? `<div class="hash-line"><span class="hash-label">SHA-256</span><span class="mono hash-val">${esc(item.sha256)}</span></div><div class="hash-line"><span class="hash-label">MD5</span><span class="mono hash-val">${esc(item.md5 || "")}</span></div>`
                : '<div class="hash-line"><span class="hash-label muted">no decodable content</span></div>'
            }<div class="att-meta">${esc(item.contentType || "unknown type")} · ${formatSize(item.size)}${item.inline ? " · inline" : ""}</div></div>`
          : "";

      const vtBtn = lookupUseless
        ? ""
        : hasVtKey
        ? `<button class="btn-ioc-lookup btn-vt" data-value="${esc(value)}" data-type="${type}"${shaAttr} onclick="lookupVirusTotal(this)" title="Check VirusTotal">
            <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>
            VT
          </button>`
        : `<button class="btn-ioc-lookup btn-vt disabled" onclick="promptSettings()" title="Add VirusTotal API key in Settings">
            <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>
            VT
          </button>`;

      let abuseBtn = "";
      if (type === "ip" && !lookupUseless) {
        abuseBtn = hasAbuseKey
          ? `<button class="btn-ioc-lookup btn-abuse" data-value="${esc(value)}" onclick="lookupAbuseIPDB(this)" title="Check AbuseIPDB">
              <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
              AbuseIPDB
            </button>`
          : `<button class="btn-ioc-lookup btn-abuse disabled" onclick="promptSettings()" title="Add AbuseIPDB API key in Settings">
              <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
              AbuseIPDB
            </button>`;
      }

      // For email addresses, add a VT domain lookup button
      let emailDomainBtn = "";
      if (type === "email" && value && value.includes("@")) {
        const domain = value.split("@")[1];
        if (domain) {
          emailDomainBtn = hasVtKey
            ? `<button class="btn-ioc-lookup btn-vt" data-value="${esc(domain)}" data-type="domain" onclick="lookupVirusTotal(this)" title="Check domain on VirusTotal">
                <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>
                VT Domain
              </button>`
            : `<button class="btn-ioc-lookup btn-vt disabled" onclick="promptSettings()" title="Add VirusTotal API key in Settings">
                <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>
                VT Domain
              </button>`;
        }
      }

      // URL decoders sit inside the value cell, not in a row of their own:
      // lookup results are found as the row directly after the IOC row.
      let decodeHtml = "";
      if (type === "url") {
        const found = detectEncodings(value);
        const labels = URL_DECODERS.filter((d) => found.includes(d.id)).map(
          (d) => d.label,
        );
        decodeHtml = `<details class="url-decode${found.length ? " has-encoding" : ""}" data-url="${esc(value)}" ontoggle="renderDecoders(this)"><summary>Decode URL${
          found.length
            ? `<span class="decode-hint">encoded: ${esc(labels.join(", "))}</span>`
            : ""
        }</summary><div class="decode-body"></div></details>`;
      }

      return `<tr class="ioc-row"><td class="ioc-value-cell"><span class="ioc-original mono">${esc(value)}</span><span class="ioc-defanged mono hidden">${esc(defanged)}</span>${hashHtml}${decodeHtml}</td><td class="ioc-risk-cell">${riskHtml}</td><td class="ioc-actions"><button class="btn-sm" onclick="copyIOC(this)" title="Copy">Copy</button><button class="btn-sm" onclick="toggleDefang(this)" title="Defang">Defang</button><div class="ioc-lookup-btns">${vtBtn}${emailDomainBtn}${abuseBtn}</div></td></tr><tr class="lookup-result-row hidden" data-ioc-value="${esc(value)}"><td colspan="3" class="lookup-result-cell"><div class="lookup-result-content"></div></td></tr>`;
    })
    .join("");

  const more = hiddenCount
    ? `<div class="ioc-more"><button class="btn-sm" onclick="showAllIOCs('${id}')">Show all ${items.length}</button><span class="ioc-more-note">${hiddenCount} more not shown</span></div>`
    : "";

  return `<div class="ioc-section" id="${id}"><h3>${esc(title)} (${items.length})</h3><div class="table-scroll"><table class="ioc-table"><thead><tr><th>Value</th><th>Risk</th><th>Actions</th></tr></thead><tbody>${rows}</tbody></table></div>${more}</div>`;
}

function renderMismatchedLinks(links) {
  const shown = links.slice(0, IOC_ROW_LIMIT);
  const rows = shown
    .map(
      (link) =>
        `<tr><td class="mono" data-label="Displays">${esc(link.text || "N/A")}</td><td class="mono" data-label="Actually goes to">${esc(link.href || "N/A")}</td><td><span class="risk-tag high">MISMATCH</span></td></tr>`,
    )
    .join("");
  const more =
    links.length > shown.length
      ? `<div class="ioc-more"><span class="ioc-more-note">${links.length - shown.length} more not shown</span></div>`
      : "";
  return `<div class="ioc-section"><h3>Mismatched Links (${links.length})</h3><div class="table-scroll"><table class="ioc-table"><thead><tr><th>Display Text</th><th>Actual URL</th><th>Risk</th></tr></thead><tbody>${rows}</tbody></table></div>${more}</div>`;
}

function defang(value) {
  return value.replace(/http/gi, "hxxp").replace(/\./g, "[.]");
}

function formatSize(bytes) {
  if (!bytes) return "0 B";
  const units = ["B", "KB", "MB", "GB"];
  const i = Math.min(
    Math.floor(Math.log(bytes) / Math.log(1024)),
    units.length - 1,
  );
  return `${(bytes / Math.pow(1024, i)).toFixed(i ? 1 : 0)} ${units[i]}`;
}

// ===== BODY & LANGUAGE =====
export function renderBody(container, body, languageAnalysis) {
  if (!body) {
    container.innerHTML = "<p>No body content</p>";
    return;
  }
  const plainText = body.text || "";
  const htmlContent = body.html || "";
  let highlightedText = esc(plainText);
  if (languageAnalysis && languageAnalysis.matches) {
    languageAnalysis.matches.forEach((match) => {
      const escaped = esc(match.phrase);
      highlightedText = highlightedText.replace(
        new RegExp(escaped, "gi"),
        `<mark class="lang-highlight ${match.category}">${escaped}</mark>`,
      );
    });
  }
  container.innerHTML = `<div class="body-tabs"><button class="tab-btn active" data-tab="plain">Plain Text</button><button class="tab-btn" data-tab="html">HTML Preview</button></div><div class="tab-content" id="tab-plain"><pre class="body-text">${highlightedText}</pre></div><div class="tab-content hidden" id="tab-html"><p class="preview-note">Remote images and scripts are blocked. Nothing in this preview contacts the sender.</p><iframe class="html-preview" sandbox referrerpolicy="no-referrer"></iframe></div>${renderLanguageAnalysis(languageAnalysis)}`;

  // The preview must not phone home. `sandbox` with no allow-list drops the
  // frame into a unique origin with scripts disabled, and the injected CSP
  // blocks every remote fetch — previously the preview loaded the sender's
  // tracking pixels the moment the tab was opened, which is exactly what this
  // tool promises never to do.
  const iframe = container.querySelector(".html-preview");
  if (iframe && htmlContent) iframe.srcdoc = withBlockingCSP(htmlContent);
  container.querySelectorAll(".tab-btn").forEach((btn) => {
    btn.addEventListener("click", () => {
      container
        .querySelectorAll(".tab-btn")
        .forEach((b) => b.classList.remove("active"));
      container
        .querySelectorAll(".tab-content")
        .forEach((c) => c.classList.add("hidden"));
      btn.classList.add("active");
      const tabId = "tab-" + btn.dataset.tab;
      const tabEl = container.querySelector("#" + tabId);
      if (tabEl) tabEl.classList.remove("hidden");
    });
  });
}

/**
 * Prepend a content-security policy that blocks every outbound request the
 * email's HTML might make. `default-src 'none'` covers images, fonts, frames,
 * scripts and fetches; inline styles stay allowed so the layout still reads.
 */
function withBlockingCSP(html) {
  const meta =
    '<meta http-equiv="Content-Security-Policy" ' +
    "content=\"default-src 'none'; style-src 'unsafe-inline'; img-src data:;\">";
  return /<head[^>]*>/i.test(html)
    ? html.replace(/<head[^>]*>/i, (m) => m + meta)
    : meta + html;
}

function renderLanguageAnalysis(analysis) {
  if (!analysis) return "";
  const categories = Object.entries(analysis.categories || {})
    .filter(([, cat]) => cat.matchCount > 0)
    .map(
      ([name, cat]) =>
        `<div class="lang-category"><div class="lang-cat-header"><span class="lang-cat-name">${esc(name)}</span><span class="lang-cat-count">${cat.matchCount}</span></div><div class="lang-cat-phrases">${(
          cat.matches || []
        )
          .slice(0, 5)
          .map((m) => `<span class="lang-phrase">${esc(m.phrase)}</span>`)
          .join("")}</div></div>`,
    )
    .join("");
  return `<div class="language-panel"><h3>Language Analysis</h3><div class="lang-summary">${esc(analysis.summary || "No suspicious language detected")}</div><div class="lang-categories">${categories || "<p>No flags</p>"}</div></div>`;
}

// ===== HEADERS TABLE =====
export function renderHeaders(container, headers) {
  if (!headers) {
    container.innerHTML = "<p>No header data</p>";
    return;
  }
  // Use headers.all for raw header display, fall back to headers itself
  const rawHeaders = headers.all || headers;
  const rows = [];
  const headerOrder = [
    "from",
    "reply-to",
    "return-path",
    "to",
    "subject",
    "date",
    "message-id",
    "authentication-results",
    "received-spf",
    "dkim-signature",
    "content-type",
    "x-mailer",
    "x-originating-ip",
  ];
  headerOrder.forEach((key) => {
    if (rawHeaders[key] !== undefined) {
      const value = rawHeaders[key];
      if (Array.isArray(value)) {
        value.forEach((v) =>
          rows.push({ key: formatHeaderName(key), value: v }),
        );
      } else {
        rows.push({ key: formatHeaderName(key), value });
      }
    }
  });
  Object.entries(rawHeaders).forEach(([key, value]) => {
    if (!headerOrder.includes(key)) {
      if (Array.isArray(value)) {
        value.forEach((v) =>
          rows.push({ key: formatHeaderName(key), value: v }),
        );
      } else {
        rows.push({ key: formatHeaderName(key), value });
      }
    }
  });
  const tableRows = rows
    .map((row) => {
      const displayValue =
        typeof row.value === "object"
          ? JSON.stringify(row.value)
          : String(row.value);
      return `<tr><td class="header-name">${esc(row.key)}</td><td class="header-value mono">${esc(displayValue)}</td></tr>`;
    })
    .join("");
  // Original order: exactly as the message carries them. Each server prepends
  // its own Received header, so reading them in place shows the real path —
  // something the grouped view above cannot, since it collects repeats.
  const ordered = headers.ordered || [];
  const receivedTotal = ordered.filter((h) => /^received$/i.test(h.name)).length;
  let receivedSeen = 0;
  const orderedRows = ordered
    .map((h, i) => {
      const lower = h.name.toLowerCase();
      let marker = "";
      let cls = "";
      if (lower === "received") {
        receivedSeen++;
        // First Received is the last hop (your server); the last one is where
        // the message started.
        const hop = receivedTotal - receivedSeen + 1;
        marker = `<span class="hdr-tag">hop ${hop}${hop === 1 ? " · origin" : ""}${receivedSeen === 1 && receivedTotal > 1 ? " · last" : ""}</span>`;
        cls = "hdr-received";
      } else if (/^(authentication-results|received-spf|dkim-signature|arc-)/.test(lower)) {
        cls = "hdr-auth";
      }
      return `<tr class="${cls}"><td class="header-index">${i + 1}</td><td class="header-name">${esc(h.name)}${marker}</td><td class="header-value mono">${esc(h.value)}</td></tr>`;
    })
    .join("");

  // Both views are collapsed by default: routed mail routinely carries 50+
  // X-headers, and an expanded dump pushes every other panel off the screen.
  container.innerHTML = `<div class="headers-views">
    <details class="headers-details">
      <summary class="headers-summary">Key headers first <span class="headers-count">${rows.length} headers · important ones on top</span></summary>
      <div class="headers-table-wrapper">
        <div class="headers-toolbar"><button class="btn-sm" data-copy="grouped">Copy headers</button></div>
        <div class="table-scroll headers-scroll"><table class="headers-table"><thead><tr><th>Header</th><th>Value</th></tr></thead><tbody>${tableRows}</tbody></table></div>
      </div>
    </details>
    <details class="headers-details">
      <summary class="headers-summary">Original order <span class="headers-count">${ordered.length} headers · exactly as in the email</span></summary>
      <div class="headers-table-wrapper">
        <div class="headers-toolbar">
          <p class="headers-note">Top to bottom as the message carries them. Every server adds its Received header above the previous one, so the chain reads bottom-up — the lowest Received header is where the message started.</p>
          <button class="btn-sm" data-copy="raw">Copy raw headers</button>
        </div>
        <div class="table-scroll headers-scroll"><table class="headers-table headers-ordered"><thead><tr><th>#</th><th>Header</th><th>Value</th></tr></thead><tbody>${orderedRows}</tbody></table></div>
      </div>
    </details>
  </div>`;

  for (const btn of container.querySelectorAll("button[data-copy]")) {
    btn.addEventListener("click", () => {
      const text =
        btn.dataset.copy === "raw"
          ? // Byte-for-byte the original header block, folding included.
            String(headers.raw || "").replace(/\s+$/, "")
          : rows
              .map((r) => `${r.key}: ${typeof r.value === "object" ? JSON.stringify(r.value) : r.value}`)
              .join("\n");
      const label = btn.textContent;
      navigator.clipboard.writeText(text).then(
        () => {
          btn.textContent = "Copied!";
          setTimeout(() => (btn.textContent = label), 2000);
        },
        () => {
          btn.textContent = "Copy failed";
          setTimeout(() => (btn.textContent = label), 2000);
        },
      );
    });
  }
}

function formatHeaderName(key) {
  return key
    .split("-")
    .map((w) => w.charAt(0).toUpperCase() + w.slice(1))
    .join("-");
}

function esc(s) {
  if (s == null) return "";
  return String(s)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}
