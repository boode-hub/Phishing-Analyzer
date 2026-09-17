// Language / Urgency / Fraud Analysis
// Local keyword/pattern-based detection - no external API calls

// Keyword/pattern lists
const KEYWORD_PATTERNS = {
  urgency: {
    keywords: [
      "act now",
      "immediately",
      "urgent",
      "as soon as possible",
      "right away",
      "within 24 hours",
      "within 48 hours",
      "deadline",
      "expires soon",
      "account will be suspended",
      "account will be locked",
      "account will be closed",
      "verify now",
      "confirm now",
      "update now",
      "limited time",
      "time sensitive",
      "action required",
      "immediate action",
      "respond immediately",
      "your account expires",
      "final warning",
      "last chance",
      "don't delay",
      "hurry",
      "act fast",
      "time running out",
      "expires today",
      "expires in",
    ],
    weight: 1.0,
    label: "Urgency",
  },
  authority: {
    keywords: [
      "legal action",
      "lawsuit",
      "court",
      "attorney",
      "law enforcement",
      "irs",
      "tax authority",
      "government",
      "federal",
      "official notice",
      "your account has been compromised",
      "unauthorized access",
      "security breach",
      "suspicious activity",
      "final notice",
      "cease and desist",
      "penalty",
      "violation",
      "compliance required",
      "mandatory",
      "obligatory",
    ],
    weight: 1.2,
    label: "Authority/Fear",
  },
  financial: {
    keywords: [
      "wire transfer",
      "bank transfer",
      "swift",
      "iban",
      "gift card",
      "itunes gift card",
      "amazon gift card",
      "cryptocurrency",
      "bitcoin",
      "btc",
      "wallet address",
      "invoice payment",
      "payment request",
      "outstanding payment",
      "banking details",
      "account details",
      "routing number",
      "update your payment information",
      "payment method expired",
      "credit card expired",
      "billing information",
      "refund",
      "reimbursement",
      "compensation",
      "transaction",
      "payment confirmation",
      "order confirmation",
    ],
    weight: 1.1,
    label: "Financial/Fraud",
  },
  credential: {
    keywords: [
      "click here to verify",
      "click here to confirm",
      "verify your account",
      "confirm your password",
      "confirm your identity",
      "login to secure",
      "login to verify",
      "sign in to verify",
      "update your password",
      "reset your password",
      "validate your account",
      "authenticate your account",
      "security check",
      "account verification",
      "confirm login details",
      "update account information",
      "verify credentials",
      "secure your account now",
    ],
    weight: 1.3,
    label: "Credential Harvesting",
  },
  // Business Email Compromise and payment fraud: no link or attachment, just a
  // convincing request to move money — redirect an invoice to "new" bank
  // details, or an executive asking for a quick, confidential transfer. These
  // messages often authenticate perfectly, so the wording is the main signal.
  bec: {
    keywords: [
      // Changed payment details — the core of invoice / vendor fraud
      "new bank details",
      "updated bank details",
      "change of bank details",
      "change in bank details",
      "bank details have changed",
      "bank details has changed",
      "our bank account has changed",
      "changed our bank",
      "new bank account",
      "new account details",
      "updated account details",
      "change of payment details",
      "updated payment details",
      "new payment details",
      "new remittance details",
      "update the beneficiary",
      "new beneficiary",
      "beneficiary details",
      "beneficiary account",
      "wire instructions",
      "wiring instructions",
      "payment instructions",
      "sort code",
      "ach transfer",
      "direct deposit",
      "update my direct deposit",
      "change my direct deposit",
      "payroll change",
      "payroll update",
      // Invoice pressure
      "overdue invoice",
      "past due invoice",
      "unpaid invoice",
      "outstanding invoice",
      "overdue payment",
      "process the payment",
      "process this payment",
      "release the payment",
      "settle the invoice",
      "proof of payment",
      "remittance advice",
      "pro forma invoice",
      "proforma invoice",
      "same day payment",
      "same-day payment",
      "transfer the funds",
      "wire the funds",
      "urgent wire",
      "urgent payment",
      "vendor payment",
      // Executive impersonation, secrecy and isolation
      "are you available",
      "are you at your desk",
      "are you in the office",
      "quick favor",
      "quick favour",
      "quick task",
      "i need a favor",
      "i need a favour",
      "can you handle a task",
      "keep this confidential",
      "keep this between us",
      "strictly confidential",
      "confidential transaction",
      "confidential matter",
      "sensitive transaction",
      "do not discuss this",
      "don't discuss this",
      "don't mention this",
      "i'm in a meeting",
      "i am in a meeting",
      "can't talk right now",
      "cannot talk right now",
      "reply by email only",
      "send me your cell",
      "send me your mobile number",
      "purchase gift cards",
      "buy gift cards",
      "scratch the back",
      "send me the codes",
      "send the codes",
    ],
    weight: 1.4,
    label: "BEC / Payment Fraud",
  },
};

// Simple language detection wordlists
const LANGUAGE_MARKERS = {
  en: {
    words: [
      "the",
      "and",
      "is",
      "to",
      "of",
      "a",
      "in",
      "that",
      "have",
      "it",
      "for",
      "not",
      "on",
      "with",
      "he",
      "as",
      "you",
      "do",
      "at",
      "this",
      "be",
      "are",
      "was",
      "were",
      "been",
      "will",
      "would",
      "could",
      "should",
      "can",
      "may",
      "might",
      "must",
      "shall",
      "has",
      "had",
      "did",
      "does",
      "doing",
      "done",
    ],
    threshold: 0.2,
  },
  es: {
    words: [
      "el",
      "la",
      "de",
      "que",
      "y",
      "a",
      "en",
      "un",
      "ser",
      "se",
      "no",
      "haber",
      "por",
      "con",
      "su",
      "para",
      "como",
      "estar",
      "tener",
    ],
    threshold: 0.25,
  },
  fr: {
    words: [
      "le",
      "de",
      "et",
      "à",
      "un",
      "il",
      "être",
      "avoir",
      "ne",
      "je",
      "son",
      "que",
      "se",
      "qui",
      "ce",
      "dans",
      "en",
      "du",
      "elle",
      "au",
    ],
    threshold: 0.25,
  },
  de: {
    words: [
      "der",
      "die",
      "und",
      "in",
      "den",
      "von",
      "zu",
      "das",
      "mit",
      "sich",
      "des",
      "auf",
      "für",
      "ist",
      "im",
      "dem",
      "nicht",
      "ein",
      "eine",
    ],
    threshold: 0.25,
  },
};

/**
 * Analyze text for urgency, authority, financial, and credential-harvesting patterns
 * @param {string} text - The email body text to analyze
 * @returns {Object} Analysis results with scores, matches, and highlighted text
 */
export function analyzeLanguage(text) {
  if (!text || typeof text !== "string") {
    return {
      categories: {},
      totalScore: 0,
      detectedLanguage: "unknown",
      languageMismatch: false,
      highlightedText: "",
      summary: "No text provided for analysis",
    };
  }

  const lowerText = text.toLowerCase();
  const categories = {};
  const allMatches = [];

  // Analyze each category
  for (const [categoryKey, config] of Object.entries(KEYWORD_PATTERNS)) {
    const matches = [];

    for (const keyword of config.keywords) {
      // Whole words only. Plain substring matching made "irs" match "first",
      // "court" match "courtesy" and "swift" match "swiftly", so ordinary
      // business mail scored as fear tactics and fraud.
      const regex = new RegExp(
        `(?<![\\w])${keyword.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}(?![\\w])`,
        "gi",
      );

      let match;
      while ((match = regex.exec(text)) !== null) {
        matches.push({
          phrase: match[0],
          index: match.index,
          length: match[0].length,
        });
        allMatches.push({
          phrase: match[0],
          index: match.index,
          length: match[0].length,
          category: categoryKey,
        });
      }
    }

    // Deduplicate matches (same phrase at same position)
    const uniqueMatches = [];
    const seen = new Set();
    for (const match of matches) {
      const key = `${match.index}-${match.phrase}`;
      if (!seen.has(key)) {
        seen.add(key);
        uniqueMatches.push(match);
      }
    }

    const score = Math.min(uniqueMatches.length * config.weight * 10, 100);

    categories[categoryKey] = {
      label: config.label,
      score: Math.round(score),
      matches: uniqueMatches,
      matchCount: uniqueMatches.length,
      weight: config.weight,
    };
  }

  // Calculate total score
  const totalScore = Math.min(
    Object.values(categories).reduce((sum, cat) => sum + cat.score, 0),
    100,
  );

  // Detect language
  const detectedLanguage = detectLanguage(text);

  // Generate highlighted text
  const highlightedText = generateHighlightedText(text, allMatches);

  // Generate summary
  const summary = generateSummary(categories, totalScore);

  return {
    categories,
    totalScore: Math.round(totalScore),
    detectedLanguage,
    languageMismatch: false,
    highlightedText,
    summary,
    matches: allMatches,
  };
}

/**
 * Simple language detection based on common word frequency
 * @param {string} text - Text to analyze
 * @returns {string} Detected language code or "unknown"
 */
function detectLanguage(text) {
  const words = text.toLowerCase().match(/\b\w+\b/g) || [];
  const totalWords = words.length;

  if (totalWords < 10) return "unknown";

  let bestLang = "unknown";
  let bestScore = 0;

  for (const [lang, config] of Object.entries(LANGUAGE_MARKERS)) {
    const matches = words.filter((word) => config.words.includes(word)).length;
    const score = matches / totalWords;

    if (score > config.threshold && score > bestScore) {
      bestScore = score;
      bestLang = lang;
    }
  }

  return bestLang;
}

/**
 * Generate HTML with highlighted phrases
 * @param {string} text - Original text
 * @param {Array} matches - Array of match objects
 * @returns {string} HTML with highlighted spans
 */
function generateHighlightedText(text, matches) {
  if (!matches.length) return escapeHtml(text);

  // Sort matches by index
  matches.sort((a, b) => a.index - b.index);

  // Merge overlapping matches
  const merged = [];
  for (const match of matches) {
    const last = merged[merged.length - 1];
    if (last && match.index < last.index + last.length) {
      last.length = Math.max(
        last.length,
        match.index + match.length - last.index,
      );
      last.categories = last.categories || [last.category];
      if (!last.categories.includes(match.category)) {
        last.categories.push(match.category);
      }
    } else {
      merged.push({
        index: match.index,
        length: match.length,
        category: match.category,
        categories: [match.category],
      });
    }
  }

  // Build HTML
  let result = "";
  let lastIndex = 0;

  for (const match of merged) {
    result += escapeHtml(text.substring(lastIndex, match.index));
    const matchedText = text.substring(match.index, match.index + match.length);
    result += `<mark class="highlight-${match.category}" title="${getCategoryLabel(match.category)}">${escapeHtml(matchedText)}</mark>`;
    lastIndex = match.index + match.length;
  }

  result += escapeHtml(text.substring(lastIndex));
  return result;
}

/**
 * Get human-readable label for a category
 * @param {string} category - Category key
 * @returns {string} Human-readable label
 */
function getCategoryLabel(category) {
  const labels = {
    urgency: "Urgency indicator",
    authority: "Authority/Fear tactic",
    financial: "Financial fraud indicator",
    credential: "Credential harvesting attempt",
    bec: "BEC / payment fraud indicator",
  };
  return labels[category] || category;
}

/**
 * Generate analysis summary
 * @param {Object} categories - Category analysis results
 * @param {number} totalScore - Total risk score
 * @returns {string} Human-readable summary
 */
function generateSummary(categories, totalScore) {
  const parts = [];

  for (const [key, cat] of Object.entries(categories)) {
    if (cat.matchCount > 0) {
      parts.push(
        `${cat.matchCount} ${cat.label.toLowerCase()} phrase${cat.matchCount > 1 ? "s" : ""}`,
      );
    }
  }

  if (parts.length === 0) {
    return "No suspicious language patterns detected.";
  }

  return `Detected: ${parts.join(", ")}.`;
}

/**
 * Escape HTML special characters
 * @param {string} text - Text to escape
 * @returns {string} Escaped text
 */
function escapeHtml(text) {
  if (!text) return "";
  return text
    .replace(/&/g, "&" + "amp;")
    .replace(/</g, "&" + "lt;")
    .replace(/>/g, "&" + "gt;")
    .replace(/"/g, "&" + "quot;")
    .replace(/'/g, "&#39;");
}
