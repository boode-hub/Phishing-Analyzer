// Local DNS and WHOIS/RDAP lookups, performed by this machine.
//
// The browser cannot do either: it has no DNS API, and WHOIS speaks a plain TCP
// protocol on port 43. Running them here keeps the promise the app makes — the
// only machine involved is the analyst's own, using the analyst's own resolver.
// Nothing is sent to a third-party API, and no key is needed.
//
// Both are read-only and take a single name or address.

const dns = require("node:dns").promises;
const net = require("node:net");

const DOMAIN_RE = /^(?!-)[a-z0-9-]{1,63}(?<!-)(\.(?!-)[a-z0-9-]{1,63}(?<!-))+\.?$/i;
const IPV4_RE = /^(\d{1,3}\.){3}\d{1,3}$/;
const IPV6_RE = /^[0-9a-f:]+$/i;

function isDomain(value) {
  return DOMAIN_RE.test(String(value || "")) && String(value).length <= 253;
}
function isIp(value) {
  return net.isIP(String(value || "")) > 0;
}

/** Only a plain domain or IP is ever passed on to a resolver or a WHOIS server. */
function validTarget(value) {
  const v = String(value || "").trim().toLowerCase().replace(/\.$/, "");
  if (isIp(v)) return { kind: "ip", value: v };
  if (isDomain(v)) return { kind: "domain", value: v };
  return null;
}

const settle = (p) => p.then((value) => value, () => null);

/**
 * The records that decide whether mail from a domain can be trusted, plus the
 * ones that say whether the domain is a real mail sender at all.
 */
async function dnsRecords(domain) {
  const [txt, dmarcTxt, mx, a, aaaa, ns] = await Promise.all([
    settle(dns.resolveTxt(domain)),
    settle(dns.resolveTxt(`_dmarc.${domain}`)),
    settle(dns.resolveMx(domain)),
    settle(dns.resolve4(domain)),
    settle(dns.resolve6(domain)),
    settle(dns.resolveNs(domain)),
  ]);

  const flat = (rows) => (rows || []).map((parts) => parts.join(""));
  const spf = flat(txt).find((t) => /^v=spf1\b/i.test(t)) || null;
  const dmarc = flat(dmarcTxt).find((t) => /^v=DMARC1\b/i.test(t)) || null;

  const tag = (record, name) =>
    record ? (record.match(new RegExp(`\\b${name}\\s*=\\s*([^;\\s]+)`, "i")) || [])[1] || null : null;

  return {
    domain,
    spf,
    // "-all" rejects everything not listed, "~all" only marks it, "?all" says
    // nothing at all — the difference between a real policy and a decorative one.
    spfAll: spf ? (spf.match(/([-~?+])all\b/) || [])[1] || null : null,
    dmarc,
    dmarcPolicy: tag(dmarc, "p"),
    dmarcSubdomainPolicy: tag(dmarc, "sp"),
    dmarcPercent: tag(dmarc, "pct"),
    mx: (mx || []).map((r) => `${r.exchange} (priority ${r.priority})`),
    a: a || [],
    aaaa: aaaa || [],
    ns: ns || [],
  };
}

async function reverseDns(ip) {
  const names = await settle(dns.reverse(ip));
  return { ip, ptr: names || [] };
}

// ===== RDAP (the modern, structured replacement for WHOIS) =====

const RDAP_TIMEOUT = 8000;
const BOOTSTRAP_URL = "https://data.iana.org/rdap/dns.json";
let bootstrapCache = null;

async function getJson(url) {
  const res = await fetch(url, {
    headers: { Accept: "application/rdap+json", "User-Agent": "phishing-email-analyzer" },
    redirect: "follow",
    signal: AbortSignal.timeout(RDAP_TIMEOUT),
  });
  if (!res.ok) throw new Error(`RDAP ${res.status}`);
  return res.json();
}

/**
 * IANA publishes which RDAP server owns each TLD. Fetched once per run and
 * kept in memory; the aggregator services that save this step are unreliable
 * for automated clients.
 */
async function rdapServiceFor(tld) {
  if (!bootstrapCache) bootstrapCache = await getJson(BOOTSTRAP_URL);
  for (const [tlds, urls] of bootstrapCache.services || []) {
    if (tlds.includes(tld)) return String(urls[0]).replace(/\/$/, "");
  }
  return null;
}

async function rdap(kind, value) {
  if (kind === "ip") {
    // ARIN redirects to whichever registry actually holds the range.
    return getJson(`https://rdap.arin.net/registry/ip/${encodeURIComponent(value)}`);
  }
  const base = await rdapServiceFor(value.split(".").pop());
  if (!base) throw new Error("No RDAP service for this TLD");
  return getJson(`${base}/domain/${encodeURIComponent(value)}`);
}

/** vCard arrays are awkward; pull out the fields worth showing. */
function entityInfo(entity) {
  const vcard = entity?.vcardArray?.[1] || [];
  const get = (name) => vcard.find((f) => f[0] === name)?.[3];
  const adr = vcard.find((f) => f[0] === "adr");
  const country = Array.isArray(adr?.[3]) ? adr[3][6] : null;
  return {
    roles: entity?.roles || [],
    name: typeof get("fn") === "string" ? get("fn") : null,
    org: typeof get("org") === "string" ? get("org") : null,
    email: typeof get("email") === "string" ? get("email") : null,
    country: country || null,
  };
}

function eventDate(events, action) {
  return (events || []).find((e) => e.eventAction === action)?.eventDate || null;
}

function summariseRdap(kind, data) {
  const entities = (data.entities || []).map(entityInfo);
  const pick = (role) => entities.find((e) => e.roles.includes(role));
  const abuse = entities
    .flatMap((e) => (e.roles.includes("abuse") ? [e] : []))
    .concat((data.entities || []).flatMap((e) => (e.entities || []).map(entityInfo)))
    .find((e) => e.roles?.includes("abuse") || e.email);

  const common = {
    source: "RDAP",
    registered: eventDate(data.events, "registration"),
    updated: eventDate(data.events, "last changed") || eventDate(data.events, "last update of RDAP database"),
    expires: eventDate(data.events, "expiration"),
    statuses: data.status || [],
    abuseEmail: abuse?.email || null,
  };

  if (kind === "ip") {
    return {
      ...common,
      kind: "ip",
      target: data.handle || null,
      range: data.startAddress && data.endAddress ? `${data.startAddress} – ${data.endAddress}` : null,
      network: data.name || null,
      country: data.country || pick("registrant")?.country || null,
      org: pick("registrant")?.org || pick("registrant")?.name || entities[0]?.org || entities[0]?.name || null,
      type: data.type || null,
    };
  }

  return {
    ...common,
    kind: "domain",
    target: data.ldhName || null,
    registrar: pick("registrar")?.name || pick("registrar")?.org || null,
    registrant: pick("registrant")?.org || pick("registrant")?.name || null,
    country: pick("registrant")?.country || null,
    nameservers: (data.nameservers || []).map((n) => n.ldhName).filter(Boolean),
  };
}

// ===== WHOIS over port 43, for the registries RDAP does not cover =====

function whois43(server, query, timeout = 8000) {
  return new Promise((resolve, reject) => {
    let text = "";
    const socket = net.connect(43, server, () => socket.write(query + "\r\n"));
    socket.setTimeout(timeout);
    socket.on("data", (chunk) => {
      text += chunk.toString("latin1");
      if (text.length > 200000) socket.destroy();
    });
    socket.on("end", () => resolve(text));
    socket.on("timeout", () => {
      socket.destroy();
      text ? resolve(text) : reject(new Error("WHOIS timed out"));
    });
    socket.on("error", reject);
  });
}

/** Ask IANA which server owns this TLD, then ask that server. */
async function whoisChain(domain) {
  const tld = domain.split(".").pop();
  const iana = await whois43("whois.iana.org", tld);
  const refer = (iana.match(/^\s*(?:refer|whois):\s*(\S+)/im) || [])[1];
  if (!refer) return { server: "whois.iana.org", text: iana };
  const text = await whois43(refer, domain);
  const second = (text.match(/^\s*(?:Registrar WHOIS Server|whois):\s*(\S+)/im) || [])[1];
  if (second && second.toLowerCase() !== refer.toLowerCase()) {
    try {
      return { server: second, text: await whois43(second, domain) };
    } catch {
      /* the registry answer is good enough */
    }
  }
  return { server: refer, text };
}

const FIELD = (text, ...names) => {
  for (const name of names) {
    const m = text.match(new RegExp(`^\\s*${name}\\s*:\\s*(.+)$`, "im"));
    if (m) return m[1].trim();
  }
  return null;
};

function summariseWhois(kind, server, text) {
  // Registries answer "no match" with a 200-shaped response; say so plainly,
  // because an unregistered domain in a live email is itself a finding.
  if (/^\s*(no match|not found|no entries found|no data found|domain not found)/im.test(text)) {
    return { source: `WHOIS (${server})`, kind, target: null, notFound: true, statuses: [], nameservers: [], raw: text.slice(0, 4000) };
  }
  const nameservers = [...text.matchAll(/^\s*(?:Name Server|nserver|nameserver)\s*:\s*(\S+)/gim)].map(
    (m) => m[1].toLowerCase(),
  );
  return {
    source: `WHOIS (${server})`,
    kind,
    target: FIELD(text, "Domain Name", "domain", "inetnum", "NetRange"),
    registrar: FIELD(text, "Registrar", "Sponsoring Registrar"),
    registrant: FIELD(text, "Registrant Organization", "Registrant Name", "org-name", "OrgName", "descr"),
    country: FIELD(text, "Registrant Country", "country", "Country"),
    registered: FIELD(text, "Creation Date", "created", "Registered On", "RegDate"),
    updated: FIELD(text, "Updated Date", "last-modified", "Last Modified"),
    expires: FIELD(text, "Registry Expiry Date", "Expiry Date", "expires", "paid-till"),
    statuses: [...text.matchAll(/^\s*(?:Domain Status|status)\s*:\s*(.+)$/gim)].map((m) => m[1].trim()),
    abuseEmail: FIELD(text, "Registrar Abuse Contact Email", "abuse-mailbox", "OrgAbuseEmail"),
    nameservers,
    raw: text.slice(0, 20000),
  };
}

/** Ask IANA which registry holds an address, then ask that registry. */
async function whoisIp(ip) {
  const iana = await whois43("whois.iana.org", ip);
  const refer = (iana.match(/^\s*(?:refer|whois):\s*(\S+)/im) || [])[1];
  if (!refer) return { server: "whois.iana.org", text: iana };
  return { server: refer, text: await whois43(refer, ip) };
}

/** RDAP first, port-43 WHOIS as the fallback. */
async function whoisLookup(kind, value) {
  try {
    const data = await rdap(kind, value);
    return summariseRdap(kind, data);
  } catch {
    const { server, text } = kind === "ip" ? await whoisIp(value) : await whoisChain(value);
    return summariseWhois(kind, server, text);
  }
}

module.exports = { validTarget, dnsRecords, reverseDns, whoisLookup };
