// Sender identity analysis
//
// Authentication answers "did this domain really send it". It does not answer
// "is this domain the one the reader thinks it is". A message from
// account@gmail.com with the display name "PayPal Support" passes SPF, DKIM and
// DMARC perfectly, and a domain like paypa1-secure.com authenticates for
// itself. Both are what most real phishing actually looks like, and neither was
// visible anywhere in this tool before.
//
// Everything here is local string analysis: no list of "known bad" domains, no
// network call.

import { orgDomain } from "./parse-auth.js";

/** Brands phishing impersonates most, with the domains they really send from. */
export const BRANDS = [
  ["paypal", ["paypal.com"]],
  ["microsoft", ["microsoft.com", "microsoftonline.com", "office.com", "office365.com"]],
  ["outlook", ["outlook.com", "microsoft.com"]],
  ["office365", ["office.com", "microsoft.com"]],
  ["apple", ["apple.com", "icloud.com"]],
  ["icloud", ["icloud.com", "apple.com"]],
  ["amazon", ["amazon.com", "amazon.co.uk", "amazon.de"]],
  ["google", ["google.com", "gmail.com"]],
  ["gmail", ["gmail.com", "google.com"]],
  ["netflix", ["netflix.com"]],
  ["facebook", ["facebook.com", "fb.com"]],
  ["instagram", ["instagram.com"]],
  ["whatsapp", ["whatsapp.com"]],
  ["linkedin", ["linkedin.com"]],
  ["dropbox", ["dropbox.com"]],
  ["docusign", ["docusign.com", "docusign.net"]],
  ["adobe", ["adobe.com"]],
  ["zoom", ["zoom.us"]],
  ["slack", ["slack.com"]],
  ["github", ["github.com"]],
  ["dhl", ["dhl.com", "dhl.de"]],
  ["fedex", ["fedex.com"]],
  ["ups", ["ups.com"]],
  ["usps", ["usps.com"]],
  ["hsbc", ["hsbc.com", "hsbc.co.uk"]],
  ["chase", ["chase.com"]],
  ["santander", ["santander.com", "santander.co.uk"]],
  ["barclays", ["barclays.co.uk", "barclays.com"]],
  ["citibank", ["citi.com", "citibank.com"]],
  ["wellsfargo", ["wellsfargo.com"]],
  ["bankofamerica", ["bankofamerica.com"]],
  ["revolut", ["revolut.com"]],
  ["binance", ["binance.com"]],
  ["coinbase", ["coinbase.com"]],
  ["metamask", ["metamask.io"]],
  ["steam", ["steampowered.com", "valvesoftware.com"]],
  ["ebay", ["ebay.com"]],
  ["stripe", ["stripe.com"]],
  ["shopify", ["shopify.com"]],
  ["booking", ["booking.com"]],
  ["airbnb", ["airbnb.com"]],
  ["emirates", ["emirates.com"]],
  ["etisalat", ["etisalat.ae"]],
  ["stc", ["stc.com.sa"]],
];

// Characters that render like an ASCII letter. A homograph domain is built out
// of exactly these, and a typosquat out of the digit rows.
const CONFUSABLES = {
  а: "a", е: "e", о: "o", р: "p", с: "c", х: "x", у: "y", і: "i", ј: "j",
  ѕ: "s", ԁ: "d", һ: "h", ӏ: "l", ν: "v", ο: "o", α: "a", ρ: "p", ε: "e",
  ι: "i", κ: "k", τ: "t", υ: "u", "0": "o", "1": "l", "3": "e", "4": "a",
  "5": "s", "6": "g", "7": "t", "8": "b", "9": "g",
};

/**
 * Fold a string to the shape a human eye sees: confusable characters become
 * their ASCII twin, "rn" becomes "m", "vv" becomes "w", and separators go.
 */
export function skeleton(value) {
  let s = String(value || "").toLowerCase().normalize("NFKC");
  s = [...s].map((ch) => CONFUSABLES[ch] ?? ch).join("");
  return s.replace(/rn/g, "m").replace(/vv/g, "w").replace(/[^a-z0-9]/g, "");
}

/** True when one label mixes Latin letters with Greek or Cyrillic ones. */
export function isMixedScript(label) {
  const s = String(label || "");
  const latin = /[a-z]/i.test(s);
  const cyrillic = /[Ѐ-ӿ]/.test(s);
  const greek = /[Ͱ-Ͽ]/.test(s);
  return latin && (cyrillic || greek);
}

function levenshtein(a, b) {
  if (a === b) return 0;
  const prev = Array.from({ length: b.length + 1 }, (_, i) => i);
  for (let i = 1; i <= a.length; i++) {
    let last = prev[0];
    prev[0] = i;
    for (let j = 1; j <= b.length; j++) {
      const tmp = prev[j];
      prev[j] = Math.min(
        prev[j] + 1,
        prev[j - 1] + 1,
        last + (a[i - 1] === b[j - 1] ? 0 : 1),
      );
      last = tmp;
    }
  }
  return prev[b.length];
}

const brandOf = (name) => BRANDS.find(([b]) => b === name);

/** Does this hostname legitimately belong to the brand? */
function isBrandDomain(host, brand) {
  const org = orgDomain(host);
  const entry = brandOf(brand);
  return !!org && !!entry && entry[1].some((d) => org === d);
}

/**
 * Compare a hostname against the brand list.
 *
 * Returns the strongest finding, or null:
 *  - "confusable": it reads as the brand but is written differently
 *    (paypa1.com, pаypal.com with a Cyrillic а)
 *  - "typosquat":  one or two edits away (paypol.com, micorsoft.com)
 *  - "contains":   the brand appears as a separate word in a domain that is not
 *    the brand's (paypal.secure-login.tld, login-paypal.tld)
 */
export function lookalikeOf(host) {
  const h = String(host || "").toLowerCase().replace(/^www\./, "");
  if (!h) return null;
  const org = orgDomain(h) || h;
  const name = org.split(".")[0];
  const flat = skeleton(h.replace(/\.[a-z.]+$/, ""));
  const nameSkeleton = skeleton(name);

  for (const [brand] of BRANDS) {
    if (isBrandDomain(h, brand)) return null;
  }

  for (const [brand] of BRANDS) {
    if (nameSkeleton === brand && name !== brand) {
      return { brand, kind: "confusable", host: h };
    }
  }
  for (const [brand] of BRANDS) {
    if (brand.length < 5) continue;
    const distance = levenshtein(nameSkeleton, brand);
    if (distance > 0 && distance <= (brand.length >= 8 ? 2 : 1)) {
      return { brand, kind: "typosquat", host: h };
    }
  }
  for (const [brand] of BRANDS) {
    if (brand.length < 4) continue;
    // The brand as its own word somewhere in the name: "paypal-billing.tld",
    // "secure.apple.evil.tld". Skipped when it is simply part of a longer word.
    const parts = flat === brand ? [] : h.split(/[.\-_]/).map(skeleton);
    if (parts.includes(brand)) return { brand, kind: "contains", host: h };
  }
  return null;
}

const emailIn = (text) =>
  String(text || "").match(/[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}/i)?.[0] || null;

const domainOf = (email) => (email && email.includes("@") ? email.split("@").pop().toLowerCase() : null);

/**
 * Findings about who the message claims to be from.
 * @param {Object} headers - parsed headers
 * @returns {{findings: Array<{id,severity,title,detail}>, fromDomain, displayName}}
 */
export function analyzeIdentity(headers) {
  const findings = [];
  const from = headers?.from || null;
  const fromEmail = from?.email || null;
  const fromDomain = domainOf(fromEmail);
  const fromOrg = orgDomain(fromDomain);
  const displayName = from?.name || null;

  const add = (id, severity, title, detail) =>
    findings.push({ id, severity, title, detail });

  // 1. The display name carries a different address than the real sender.
  if (displayName) {
    const shown = emailIn(displayName);
    const shownOrg = orgDomain(domainOf(shown));
    if (shown && shownOrg && fromOrg && shownOrg !== fromOrg) {
      add(
        "display-name-address",
        "high",
        "The display name shows a different address",
        `The name reads "${displayName}" but the message is really from ${fromEmail}. Most mail apps show only the name.`,
      );
    }
  }

  // 2. The display name names a brand the sending domain does not belong to.
  if (displayName && fromDomain) {
    const words = skeleton(displayName);
    for (const [brand] of BRANDS) {
      if (brand.length < 4 || !words.includes(brand)) continue;
      if (isBrandDomain(fromDomain, brand)) break;
      add(
        "display-name-brand",
        "high",
        `The display name claims to be ${brand}`,
        `"${displayName}" is not sent from a ${brand} domain — it comes from ${fromDomain}.`,
      );
      break;
    }
  }

  // 3. The sending domain itself imitates a brand.
  const look = fromDomain ? lookalikeOf(fromDomain) : null;
  if (look) {
    const how =
      look.kind === "confusable"
        ? `reads as "${look.brand}" but is spelled differently`
        : look.kind === "typosquat"
          ? `is one or two characters away from "${look.brand}"`
          : `uses "${look.brand}" as part of a domain that is not ${look.brand}'s`;
    add(
      `lookalike-${look.kind}`,
      "high",
      `The sending domain imitates ${look.brand}`,
      `${fromDomain} ${how}.`,
    );
  }

  // 4. Mixed scripts inside one label — the classic homograph domain.
  for (const label of String(fromDomain || "").split(".")) {
    if (isMixedScript(label)) {
      add(
        "mixed-script",
        "high",
        "The sending domain mixes alphabets",
        `"${label}" contains both Latin and non-Latin letters that look alike, which is how lookalike domains are built.`,
      );
      break;
    }
  }

  // 5. A Reply-To whose display name impersonates the From domain's brand is
  //    covered by the alignment panel; here we only note a free-mail Reply-To
  //    on a corporate-looking sender, which is the BEC pattern.
  const replyDomain = domainOf(headers?.replyTo?.email);
  const FREE_MAIL = new Set([
    "gmail.com", "outlook.com", "hotmail.com", "yahoo.com", "aol.com",
    "protonmail.com", "proton.me", "gmx.com", "mail.com", "yandex.com",
    "zoho.com", "icloud.com",
  ]);
  if (replyDomain && fromOrg && orgDomain(replyDomain) !== fromOrg && FREE_MAIL.has(orgDomain(replyDomain))) {
    add(
      "replyto-freemail",
      "medium",
      "Replies would go to a free webmail account",
      `Reply-To points at ${headers.replyTo.email}, a personal mailbox on a different domain than ${fromDomain}.`,
    );
  }

  return { findings, fromDomain, displayName };
}
