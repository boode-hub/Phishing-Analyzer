// Scoring Module
// Composite risk score calculation
//
// Two rules this module now holds to:
//
// 1. Each sub-score is capped BEFORE it is weighted. Previously the weighted
//    total used the uncapped IOC score, so twenty newsletter shortener links
//    (20 x 8 = 160, weighted to 48) pushed a message with SPF, DKIM and DMARC
//    all passing into "Suspicious". Volume of low-severity indicators must not
//    substitute for severity.
// 2. Every point added emits a reason. If the tool cannot say why a message
//    scored what it scored, the score is not usable by an analyst.

const TIER_HIGH = 60;
const TIER_SUSPICIOUS = 30;

/**
 * Calculate overall risk score
 * @param {Object} auth - Authentication analysis
 * @param {Object} iocs - Extracted IOCs
 * @param {Object} languageAnalysis - Language analysis results
 * @param {Object} [headers] - Parsed headers, for evidence-quality caveats
 * @param {Object} [identity] - Sender identity findings (analyze-identity.js)
 * @returns {Object} Risk score and breakdown
 */
export function calculateScore(auth, iocs, languageAnalysis, headers, identity) {
  const authResult = scoreAuthentication(auth, identity);
  const iocResult = scoreIOCs(iocs);
  const langResult = scoreLanguage(languageAnalysis);

  // Cap first, then weight. The displayed bars and the total agree.
  const authScore = clamp(authResult.score);
  const iocScore = clamp(iocResult.score);
  const langScore = clamp(langResult.score);

  // Authentication is weighted so that a total authentication failure — SPF,
  // DKIM and DMARC all failing on a misaligned domain — reaches "High Risk" on
  // its own, without needing a suspicious link to tip it over. Language is the
  // weakest signal and cannot reach any tier by itself.
  let total = Math.round(
    Math.min(authScore * 0.6 + iocScore * 0.25 + langScore * 0.15, 100),
  );

  // Business email compromise is the one attack this scoring cannot see: the
  // mail is sent from a real, fully authenticated mailbox, carries no link and
  // no attachment, and only its wording gives it away. Weighted normally that
  // lands at "Low Risk", which is exactly the message an accounts team must not
  // wave through, so a payment-fraud phrase forces at least "Suspicious".
  // Two or more signals, not one: a single "approve the payment" appears in
  // ordinary finance mail, while real payment fraud stacks the instruction, the
  // bank details, the excuse for not talking and the demand for secrecy.
  const becMatches = languageAnalysis?.categories?.bec?.matchCount || 0;
  const becSuspected = becMatches >= 2;
  if (becSuspected && total < TIER_SUSPICIOUS) total = TIER_SUSPICIOUS;

  const reasons = [
    ...authResult.reasons,
    ...iocResult.reasons,
    ...langResult.reasons,
  ];

  return {
    tier:
      total >= TIER_HIGH
        ? "High Risk"
        : total >= TIER_SUSPICIOUS
          ? "Suspicious"
          : "Low Risk",
    score: total,
    reasons: [...new Set(reasons)],
    // Reasons kept per category, so the verdict can show why each bar is high.
    reasonGroups: {
      auth: [...new Set(authResult.reasons)],
      iocs: [...new Set(iocResult.reasons)],
      language: [...new Set(langResult.reasons)],
    },
    caveats: [
      ...evidenceCaveats(auth, headers),
      ...(becSuspected
        ? [
            "This message asks about payments or bank details. Confirm any change by phone on a number you already had — never one from this email — before anything is paid.",
          ]
        : []),
    ],
    breakdown: {
      // "auth" is the key the renderer reads. "authentication" is kept as an
      // alias so nothing that reached for the old name silently reads 0.
      auth: authScore,
      authentication: authScore,
      iocs: iocScore,
      language: langScore,
    },
  };
}

function clamp(n) {
  return Math.max(0, Math.min(Math.round(n), 100));
}

/**
 * Situations where a low score means "not enough to judge", not "safe".
 *
 * The most common way a user submits a suspicious message is by forwarding it,
 * and a forward's headers describe the forwarder — the original sender's
 * authentication and routing are gone. Without that evidence a Low Risk result
 * would read as a clean bill of health it has not earned.
 */
function evidenceCaveats(auth, headers) {
  const caveats = [];
  const hasAuth =
    (auth?.trust?.authResultsCount || 0) > 0 || (auth?.spf?.sources?.length || 0) > 0;
  const hasRouting = (auth?.receivedChain?.length || 0) > 0;

  if (/^\s*(fw|fwd)\s*:/i.test(headers?.subject || "")) {
    caveats.push(
      "This looks like a forwarded message. Its headers describe the forward, not the original — attach or paste the original message source for a reliable verdict.",
    );
  }
  if (!hasAuth && !hasRouting) {
    caveats.push(
      "No authentication or routing headers were found, so sender authenticity could not be checked. A low score here is not a clean result.",
    );
  } else if (!hasAuth) {
    caveats.push(
      "No SPF, DKIM or DMARC results were recorded, so sender authenticity could not be verified.",
    );
  }
  return caveats;
}

/**
 * Score authentication results.
 *
 * Weighting reflects what each signal actually proves. A DMARC failure on an
 * aligned domain is the strongest single indicator of spoofing available from
 * headers alone; a missing SPF record is weak, because plenty of small senders
 * never published one.
 */
function scoreAuthentication(auth, identity) {
  const reasons = [];
  let score = 0;

  // Who the message claims to be from. A display name reading "PayPal Support"
  // on a gmail.com account authenticates perfectly and is still a fake.
  for (const f of identity?.findings || []) {
    const points = f.severity === "high" ? 20 : 8;
    score += points;
    reasons.push(`${f.title} — ${f.detail}`);
  }

  if (!auth || !auth.mechanisms) return { score: Math.max(0, score), reasons };

  const add = (points, reason) => {
    score += points;
    if (reason) reasons.push(reason);
  };

  switch (auth.mechanisms.spf.status) {
    case "fail":
      add(30, "SPF failed — the sending server is not authorized for this domain");
      break;
    case "softfail":
      add(18, "SPF soft-failed — the sending server is not authorized");
      break;
    case "permerror":
      add(8, "The sending domain's SPF record is malformed");
      break;
    case "neutral":
      add(5, "The sending domain's SPF record makes no assertion");
      break;
    case "none":
      add(5, "The sending domain publishes no SPF record");
      break;
    case "temperror":
      add(2, "SPF could not be evaluated (temporary DNS error)");
      break;
    case "unknown":
      add(2, "No SPF result was recorded by the receiving server");
      break;
  }

  switch (auth.mechanisms.dkim.status) {
    case "fail":
      add(25, "DKIM signature failed verification — the message was altered or forged");
      break;
    case "permerror":
      add(8, "DKIM signature is malformed");
      break;
    case "unverified":
      add(4, "The message is signed but the receiving server did not verify it");
      break;
    case "none":
      add(5, "The message carries no DKIM signature");
      break;
    case "unknown":
      add(2, "No DKIM result was recorded by the receiving server");
      break;
  }

  switch (auth.mechanisms.dmarc.status) {
    case "fail":
      add(35, "DMARC failed — the message does not authenticate as its From domain");
      break;
    case "none":
      add(5, "The sending domain publishes no DMARC policy");
      break;
    case "unknown":
      add(2, "No DMARC result was recorded by the receiving server");
      break;
  }

  const align = auth.domainAlignment;
  if (align) {
    if (align.dmarcAligned === false) {
      add(30, null);
      for (const m of align.mismatches) reasons.push(m);
    }
    // Reply-To is not a DMARC input, so it is a hint and priced like one.
    if (align.replyToMismatch) {
      add(
        8,
        `Reply-To points at a different domain (${align.replyToDomain}) than From`,
      );
    }
  }

  // Forged lower Authentication-Results, duplicate From headers, and similar.
  for (const w of auth.trust?.warnings || []) {
    add(12, w);
  }

  // Odd headers: a Date that disagrees with delivery, a foreign Message-ID,
  // reply headers on a message that is not a reply.
  for (const a of auth.anomalies || []) {
    add(a.severity === "high" ? 12 : a.severity === "medium" ? 6 : 3, a.message);
  }

  // Full authentication is affirmative evidence, but only when all three
  // mechanisms actually ran. It can reduce accumulated noise, never go
  // negative on its own.
  const allPass =
    auth.mechanisms.spf.status === "pass" &&
    auth.mechanisms.dkim.status === "pass" &&
    auth.mechanisms.dmarc.status === "pass" &&
    align?.dmarcAligned === true;
  if (allPass) score -= 10;

  return { score: Math.max(0, score), reasons };
}

/**
 * Score IOCs.
 *
 * Severity leads and volume follows with diminishing returns: the second
 * shortener link in a newsletter says almost nothing the first did not.
 */
function scoreIOCs(iocs) {
  const reasons = [];
  let score = 0;
  if (!iocs) return { score, reasons };

  const hasRisk = (item, level) =>
    (item.risks || []).some((r) => r.level === level);
  const hasType = (item, type) =>
    (item.risks || []).some((r) => r.type === type);

  const urls = iocs.urls || [];
  const high = urls.filter((u) => hasRisk(u, "high"));
  const medium = urls.filter(
    (u) => hasRisk(u, "medium") && !hasRisk(u, "high"),
  );

  score += diminishing(high.length, 25, 12);
  score += diminishing(medium.length, 8, 4);

  if (urls.some((u) => hasType(u, "script-url")))
    reasons.push("A link runs script or carries its content inside itself instead of opening a page");
  if (urls.some((u) => hasType(u, "credentials-url")))
    reasons.push("A link hides its real destination behind an \"@\", so it reads as a trusted site");
  if (urls.some((u) => hasType(u, "brand-lookalike")))
    reasons.push("A link's domain imitates a well-known brand");
  if (urls.some((u) => hasType(u, "direct-download")))
    reasons.push("A link downloads a program or archive directly");
  if (urls.some((u) => hasType(u, "risky-tld")))
    reasons.push("A link uses a domain ending that is heavily abused");
  if (urls.some((u) => hasType(u, "mismatch")))
    reasons.push("A link's display text does not match its actual destination");
  if (urls.some((u) => hasType(u, "ip-url")))
    reasons.push("A link points at a raw IP address instead of a domain");
  if (urls.some((u) => hasType(u, "punycode")))
    reasons.push("A link uses a punycode domain (possible homograph attack)");
  if (medium.length)
    reasons.push(
      `${medium.length} link${medium.length > 1 ? "s use" : " uses"} a URL shortener, hiding the destination`,
    );

  const riskyAttachments = (iocs.attachments || []).filter((a) =>
    hasRisk(a, "high"),
  );
  if (riskyAttachments.length) {
    score += diminishing(riskyAttachments.length, 30, 15);
    const names = riskyAttachments
      .map((a) => a.value)
      .filter(Boolean)
      .slice(0, 3)
      .join(", ");
    reasons.push(
      names
        ? `Executable or double-extension attachment: ${names}`
        : "Executable or double-extension attachment present",
    );
  }

  const punycodeDomains = (iocs.domains || []).filter((d) =>
    hasType(d, "punycode"),
  );
  if (punycodeDomains.length) {
    score += diminishing(punycodeDomains.length, 20, 10);
    reasons.push("A punycode domain was found in the message");
  }

  const disposable = (iocs.emails || []).filter((e) => hasType(e, "disposable"));
  if (disposable.length) {
    score += 10;
    reasons.push("A disposable email address appears in the message");
  }

  return { score, reasons };
}

/**
 * First occurrence costs `firstWeight`; each additional one costs `restWeight`
 * and the tail is compressed, so 50 of something never swamps the total.
 */
function diminishing(count, firstWeight, restWeight) {
  if (count <= 0) return 0;
  return firstWeight + Math.min(count - 1, 4) * restWeight;
}

/**
 * Score language analysis. Language is the weakest signal here — real
 * companies send genuinely urgent mail — so it is capped low and never on its
 * own enough to reach "High Risk".
 */
function scoreLanguage(lang) {
  const reasons = [];
  if (!lang || !lang.categories) return { score: 0, reasons };

  const weights = {
    urgency: 0.5,
    authority: 0.5,
    financial: 0.8,
    credential: 0.8,
    // BEC mail usually authenticates cleanly and carries no link or file, so
    // its wording is weighted highest of the language signals.
    bec: 1.0,
  };
  const labels = {
    urgency: "urgency phrase",
    authority: "authority/fear phrase",
    financial: "financial/fraud phrase",
    credential: "credential-harvesting phrase",
    bec: "BEC / payment-fraud phrase",
  };

  let score = 0;
  for (const [name, cat] of Object.entries(lang.categories)) {
    if (!cat || !cat.matchCount) continue;
    score += (cat.score || 0) * (weights[name] ?? 0.5);
    const label = labels[name] || `${name} phrase`;
    reasons.push(
      `${cat.matchCount} ${label}${cat.matchCount > 1 ? "s" : ""} detected`,
    );
  }

  return { score: Math.round(score), reasons };
}
