// Main Application Entry Point
// Phishing Email Analyzer - Local Browser-Based

import { parseHeaders } from "./parse-headers.js";
import { applyAccent, loadAccent, saveAccent, DEFAULT_ACCENT } from "./theme.js";
import { parseAuth } from "./parse-auth.js";
import { parseBody } from "./parse-body.js";
import { extractIOCs } from "./extract-iocs.js";
import { analyzeLanguage } from "./analyze-language.js";
import { analyzeIdentity } from "./analyze-identity.js";
import { calculateScore } from "./score.js";
import { sha256, sha256Bytes, md5Bytes } from "./hash-utils.js";
import { isValidIP, isRoutableIP } from "./ip-utils.js";
import {
  buildHtmlReport,
  buildCsvReport,
  buildJsonReport,
  reportFilename,
  defangUrl,
  defangDomain,
  defangIp,
  defangEmail,
} from "./report.js";
import {
  renderVerdict,
  renderAuth,
  renderIOCs,
  renderBody,
  renderHeaders,
  renderSummary,
  showAllIOCs,
  renderDecoders,
  runDecoder,
} from "./render.js";

// State
let currentAnalysis = null;
let apiKeys = {
  virustotal: "",
  abuseipdb: "",
  corsProxyUrl: "",
};

// Detect if running locally (via node server.js) vs GitHub Pages
const isLocalhost =
  window.location.hostname === "localhost" ||
  window.location.hostname === "127.0.0.1";

// Store attachment contents for hash lookups (keyed by attachment filename)
const attachmentContentMap = new Map();

// CORS proxy URL - user configurable in settings
function getCORSProxy() {
  return apiKeys.corsProxyUrl || "";
}

// Build API endpoint - uses local proxy when running locally, CORS proxy on GitHub Pages
//
// Local endpoints are relative on purpose. Hardcoding http://localhost:8080
// made every lookup cross-origin the moment the app was opened at
// 127.0.0.1, or on any port other than 8080.
//
// Proxied targets are URL-encoded. A CORS proxy takes the target as a query
// parameter (…?url=), so appending it raw handed the target's own query string
// to the proxy instead: AbuseIPDB's "&maxAgeInDays=90" was being parsed as a
// parameter of the proxy and never reached AbuseIPDB.
const VT_BASE = "https://www.virustotal.com";
const ABUSE_BASE = "https://api.abuseipdb.com/api/v2";

function viaProxy(targetUrl) {
  const proxy = getCORSProxy();
  return proxy ? proxy + encodeURIComponent(targetUrl) : targetUrl;
}

function getVTEndpoint(path) {
  if (isLocalhost) return "/proxy/vt" + path;
  return viaProxy(VT_BASE + path);
}

function getVTSubmitEndpoint() {
  if (isLocalhost) return "/proxy/vt-submit";
  return viaProxy(VT_BASE + "/api/v3/urls");
}

function getVTAnalyseEndpoint(path) {
  if (isLocalhost) return "/proxy/vt-analyse" + path;
  return viaProxy(VT_BASE + path);
}

function getAbuseIPDBEndpoint(query) {
  if (isLocalhost) return "/proxy/abuseipdb" + query;
  return viaProxy(ABUSE_BASE + query);
}

// VirusTotal accepts the SHA-256 of the URL string as its URL identifier.
// The previous btoa() approach emitted "+" and "/" (neither valid in a path
// segment) and threw outright on any non-ASCII URL — exactly the
// internationalized domains this tool exists to flag.
function vtUrlId(value) {
  return sha256(value);
}

// Lookups are cached for the life of the page. VirusTotal's free tier allows
// four requests per minute, so re-clicking an IOC used to burn the quota.
const lookupCache = new Map();

// Plain-text summaries of completed lookups, keyed "vt:<value>" / "abuse:<value>",
// so the exported report can include what the analyst already checked.
const lookupResults = new Map();

async function cachedLookup(key, fn) {
  if (lookupCache.has(key)) return lookupCache.get(key);
  const value = await fn();
  lookupCache.set(key, value);
  return value;
}

// Apply the saved theme colour before anything renders.
applyAccent(loadAccent());

// Safely get localStorage value
try {
  apiKeys.virustotal = localStorage.getItem("vt-api-key") || "";
  apiKeys.abuseipdb = localStorage.getItem("abuseipdb-api-key") || "";
  apiKeys.corsProxyUrl = localStorage.getItem("cors-proxy-url") || "";
} catch (e) {
  console.warn("localStorage not available:", e);
}

const elements = {};

function queryElements() {
  const ids = {
    emailInput: "email-input",
    fileUpload: "file-upload",
    analyzeBtn: "analyze-btn",
    clearBtn: "clear-btn",
    inputStatus: "input-status",
    settingsBtn: "settings-btn",
    settingsModal: "settings-modal",
    closeSettings: "close-settings",
    saveSettings: "save-settings",
    clearKeys: "clear-keys",
    virustotalKeyInput: "virustotal-key",
    abuseipdbKeyInput: "abuseipdb-key",
    corsProxyUrlInput: "cors-proxy-url",
    exportSection: "export-section",
    exportHtml: "export-html",
    exportCsv: "export-csv",
    exportJson: "export-json",
    exportRaw: "export-raw",
    exportDownload: "export-download",
    exportStatus: "export-status",
    apiAvailability: "api-availability",
    proxyField: "proxy-field",
    rememberKeys: "remember-keys",
    accentColor: "accent-color",
    accentValue: "accent-value",
    resetAccent: "reset-accent",
  };
  for (const [key, id] of Object.entries(ids)) {
    elements[key] = document.getElementById(id);
  }
}

// Initialize
function init() {
  console.log("%cBOoDe", "color:#9fef00;font:700 14px monospace");
  console.log("[Phishing Analyzer] Initializing...");

  // Query DOM elements now that DOM is ready
  queryElements();

  // Load saved API keys into inputs
  if (elements.virustotalKeyInput) {
    elements.virustotalKeyInput.value = apiKeys.virustotal;
  }
  if (elements.abuseipdbKeyInput) {
    elements.abuseipdbKeyInput.value = apiKeys.abuseipdb;
  }
  if (elements.corsProxyUrlInput) {
    elements.corsProxyUrlInput.value = apiKeys.corsProxyUrl;
  }
  if (elements.rememberKeys) elements.rememberKeys.checked = rememberKeys();

  // Event Listeners
  if (elements.analyzeBtn) {
    elements.analyzeBtn.addEventListener("click", handleAnalyze);
  }
  if (elements.clearBtn) {
    elements.clearBtn.addEventListener("click", handleClear);
  }
  if (elements.fileUpload) {
    elements.fileUpload.addEventListener("change", handleFileUpload);
  }
  if (elements.settingsBtn) {
    elements.settingsBtn.addEventListener("click", () => {
      if (elements.settingsModal) {
        elements.settingsModal.classList.remove("hidden");
      }
    });
  }
  if (elements.closeSettings) {
    elements.closeSettings.addEventListener("click", () => {
      if (elements.settingsModal) {
        elements.settingsModal.classList.add("hidden");
      }
    });
  }
  if (elements.saveSettings) {
    elements.saveSettings.addEventListener("click", handleSaveSettings);
  }
  if (elements.clearKeys) {
    elements.clearKeys.addEventListener("click", handleClearKeys);
  }

  // Close modal on outside click
  if (elements.settingsModal) {
    elements.settingsModal.addEventListener("click", (e) => {
      if (e.target === elements.settingsModal) {
        elements.settingsModal.classList.add("hidden");
      }
    });
  }

  // Keyboard shortcut: Escape to close modal
  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape" && elements.settingsModal) {
      elements.settingsModal.classList.add("hidden");
    }
  });

  renderApiAvailability();
  setupThemePicker();

  elements.exportDownload?.addEventListener("click", handleExportDownload);
  for (const box of [elements.exportHtml, elements.exportCsv]) {
    box?.addEventListener("change", syncExportControls);
  }
  syncExportControls();

  console.log("[Phishing Analyzer] Initialized successfully");
}

/**
 * State plainly whether lookups can work from where this page is served.
 *
 * Neither VirusTotal nor AbuseIPDB sends an Access-Control-Allow-Origin header
 * (AbuseIPDB rejects the preflight outright with 405), so a browser will block
 * the response for any page not served by something that can relay the call.
 * Served by server.js, the same origin relays them and an API key is all that
 * is needed. Served from GitHub Pages, no amount of client code can help, and
 * saying so is more useful than a failed request.
 */
function renderApiAvailability() {
  const el = elements.apiAvailability;
  if (!el) return;

  if (isLocalhost) {
    el.className = "api-notice ok";
    el.innerHTML =
      "<strong>Lookups are ready.</strong> This page is served by " +
      "<code>server.js</code>, which relays VirusTotal and AbuseIPDB calls for " +
      "you. Paste your API keys below and the lookup buttons will work — no " +
      "proxy setup, no other configuration.<br><br>DNS and WHOIS lookups also " +
      "run here, resolved by this machine with no API key and no third-party " +
      "service.";
    if (elements.proxyField) elements.proxyField.classList.add("hidden");
    return;
  }

  el.className = "api-notice";
  el.innerHTML =
    "<strong>Lookups cannot run from this address.</strong> VirusTotal and " +
    "AbuseIPDB do not send CORS headers, so your browser blocks their " +
    "responses on any page they do not serve themselves. An API key alone " +
    "cannot change that.<br><br>To use lookups, run the app locally — clone " +
    "the repo, then <code>node server.js</code> and open " +
    "<code>http://localhost:8080</code>. Your keys work immediately there. " +
    "Everything else on this page (parsing, scoring, hashing) is unaffected " +
    "and runs fine right here.";
}

// Headers every real message carries at least one of. Without any of them the
// input is not an email, and a verdict on it would be meaningless.
const EMAIL_HEADERS = [
  "from", "to", "subject", "date", "received", "message-id", "return-path",
  "authentication-results", "received-spf", "dkim-signature", "reply-to",
  "mime-version", "content-type",
];

/**
 * Run the whole pipeline over one raw message. Kept separate from the click
 * handler so a batch of files can be analyzed without touching the DOM.
 *
 * @param {string} input - raw email source
 * @returns {Promise<{analysis?: Object, error?: string}>}
 */
async function buildAnalysis(input) {
  const isFullEmail = detectFullEmail(input);
  const headers = parseHeaders(input);

  if (!EMAIL_HEADERS.some((h) => h in headers.all)) {
    return {
      error:
        "No email headers found — this doesn't look like an email. Paste the full raw message source (headers and body), or upload the .eml file.",
    };
  }

  const auth = parseAuth(headers);
  const body = isFullEmail ? parseBody(input) : null;
  const iocs = extractIOCs(headers, body);

  // Hash every extracted file — attachments and inline images alike — so the
  // hashes are on screen without a lookup, and a VirusTotal file check is one
  // click away.
  const files = new Map();
  for (const att of iocs.attachments || []) {
    if (att.bytes && att.bytes.length) {
      att.sha256 = await sha256Bytes(att.bytes);
      att.md5 = md5Bytes(att.bytes);
      files.set(att.value, att.bytes);
    }
  }

  const languageAnalysis = body && body.text ? analyzeLanguage(body.text) : null;
  // Who the message claims to be from, which authentication cannot answer.
  const identity = analyzeIdentity(headers);
  const score = calculateScore(auth, iocs, languageAnalysis, headers, identity);

  return {
    analysis: {
      headers,
      auth,
      identity,
      body,
      iocs,
      languageAnalysis,
      score,
      rawInput: input,
      isFullEmail,
      files,
    },
  };
}

// Handle Analyze Button
async function handleAnalyze() {
  const input = elements.emailInput ? elements.emailInput.value.trim() : "";

  if (!input) {
    hideResults();
    showStatus("Please paste an email or upload a file first.", "error");
    return;
  }

  try {
    showStatus("Analyzing email...", "info");
    const { analysis, error } = await buildAnalysis(input);
    if (error) {
      hideResults();
      showStatus(error, "error");
      return;
    }

    currentAnalysis = analysis;
    attachmentContentMap.clear();
    for (const [name, bytes] of analysis.files) attachmentContentMap.set(name, bytes);

    await renderResults(currentAnalysis);
    showStatus("Analysis complete!", "success");
  } catch (error) {
    console.error("[Phishing Analyzer] Analysis error:", error);
    hideResults();
    showStatus("Error analyzing email: " + error.message, "error");
  }
}

// ===== BATCH =====
//
// Phishing arrives in waves, and opening twenty files one at a time is how a
// real message gets missed. Every file is scored here; clicking a row loads
// that message into the full view.
const batchItems = [];

async function analyzeBatch(files) {
  const section = document.getElementById("batch-section");
  const body = document.getElementById("batch-content");
  if (!section || !body) return;

  batchItems.length = 0;
  section.classList.remove("hidden");
  body.innerHTML = `<p class="batch-progress">Analyzing ${files.length} files…</p>`;

  for (const file of files) {
    const text = await file.text();
    let row = { name: file.name, text };
    try {
      const { analysis, error } = await buildAnalysis(text);
      if (error) row.error = error;
      else
        row = {
          ...row,
          tier: analysis.score.tier,
          score: analysis.score.score,
          from: analysis.headers.from?.email || "—",
          subject: analysis.headers.subject || "(no subject)",
          top: (analysis.score.reasons || [])[0] || "",
        };
    } catch (e) {
      row.error = e.message;
    }
    batchItems.push(row);
  }

  // Worst first: that is the one the analyst should open.
  const order = { "High Risk": 0, Suspicious: 1, "Low Risk": 2 };
  const sorted = batchItems
    .map((item, index) => ({ item, index }))
    .sort((a, b) => (order[a.item.tier] ?? 3) - (order[b.item.tier] ?? 3) || (b.item.score || 0) - (a.item.score || 0));

  body.innerHTML = `<div class="table-scroll"><table class="batch-table">
      <thead><tr><th>File</th><th>Verdict</th><th>From</th><th>Subject</th><th></th></tr></thead>
      <tbody>${sorted
        .map(({ item, index }) =>
          item.error
            ? `<tr><td data-label="File">${esc(item.name)}</td><td data-label="Verdict" colspan="3" class="batch-error">${esc(item.error)}</td><td></td></tr>`
            : `<tr>
                <td data-label="File" class="mono">${esc(item.name)}</td>
                <td data-label="Verdict"><span class="batch-tier ${item.tier === "High Risk" ? "high" : item.tier === "Suspicious" ? "medium" : "low"}">${esc(item.tier)} ${item.score}</span></td>
                <td data-label="From" class="mono">${esc(item.from)}</td>
                <td data-label="Subject">${esc(item.subject)}</td>
                <td><button class="btn-sm" data-act="open-batch" data-index="${index}">Open</button></td>
              </tr>`,
        )
        .join("")}</tbody></table></div>
    <p class="batch-note">${batchItems.length} messages analyzed locally. Open one to see its full report.</p>`;
}

function openBatchItem(index) {
  const item = batchItems[Number(index)];
  if (!item || !elements.emailInput) return;
  elements.emailInput.value = item.text;
  handleAnalyze();
  document.getElementById("summary-section")?.scrollIntoView({ behavior: "smooth" });
}

// Detect if input is full email or headers-only
function detectFullEmail(input) {
  // Look for blank line separating headers from body
  const blankLineIndex = input.indexOf("\r\n\r\n");
  const blankLineIndexLF = input.indexOf("\n\n");

  if (blankLineIndex !== -1 || blankLineIndexLF !== -1) {
    return true;
  }

  // Check if it looks like headers only (no body-like content)
  const lines = input.split(/\r?\n/);
  let headerCount = 0;
  let bodyLikeCount = 0;

  for (const line of lines) {
    if (line.match(/^[\w-]+:/)) {
      headerCount++;
    } else if (line.length > 50 && !line.match(/^\s/)) {
      bodyLikeCount++;
    }
  }

  // If most lines are headers, treat as headers-only (not full email)
  return bodyLikeCount > headerCount;
}

// Handle Clear Button
function handleClear() {
  if (elements.emailInput) elements.emailInput.value = "";
  if (elements.fileUpload) elements.fileUpload.value = "";
  document.getElementById("batch-section")?.classList.add("hidden");
  hideResults();
  showStatus("");
}

/**
 * Hide every result panel. Called on Clear and whenever an analysis is refused
 * or fails — otherwise the previous message's verdict stays on screen beneath
 * the error and reads as the result for the new input.
 */
function hideResults() {
  currentAnalysis = null;
  for (const id of [
    "summary-section",
    "verdict-section",
    "auth-section",
    "ioc-section",
    "body-section",
    "headers-section",
    "export-section",
  ]) {
    document.getElementById(id)?.classList.add("hidden");
  }
}

// ===== EXPORT =====

/** Download needs at least one format; the raw-values option only applies to CSV. */
function syncExportControls() {
  const report = elements.exportHtml?.checked;
  const csv = elements.exportCsv?.checked;
  const json = elements.exportJson?.checked;
  if (elements.exportDownload) elements.exportDownload.disabled = !report && !csv && !json;
  if (elements.exportRaw) {
    elements.exportRaw.disabled = !csv;
    elements.exportRaw.closest("label")?.classList.toggle("disabled", !csv);
  }
}

function exportStatus(message, type = "ok") {
  const el = elements.exportStatus;
  if (!el) return;
  el.textContent = message;
  el.className = `export-status ${type}`;
  clearTimeout(exportStatus.timer);
  exportStatus.timer = setTimeout(() => (el.textContent = ""), 4000);
}

/**
 * Every indicator as one block of text, for a blocklist or a ticket. Defanged
 * by default; the raw list is one click away for tooling that needs live values.
 */
function copyAllIOCs(btn) {
  if (!currentAnalysis) return;
  const raw = btn.dataset.raw === "1";
  const iocs = currentAnalysis.iocs || {};
  const lines = [];
  const push = (label, values, defang) => {
    const list = (values || []).map((v) => (raw ? v.value : defang(v.value)));
    if (list.length) lines.push(`# ${label}`, ...list, "");
  };
  push("URLs", iocs.urls, defangUrl);
  push("Domains", iocs.domains, defangDomain);
  push("IPs", iocs.ips, defangIp);
  push("Emails", iocs.emails, defangEmail);
  const hashes = (iocs.attachments || []).flatMap((a) => [a.sha256, a.md5].filter(Boolean));
  if (hashes.length) lines.push("# File hashes", ...hashes, "");
  copyText(lines.join("\n").trim(), btn);
}

function handleExportDownload() {
  if (!currentAnalysis) return;
  const now = new Date();
  const files = [];

  if (elements.exportHtml?.checked) {
    files.push({
      name: reportFilename(currentAnalysis, "html", now),
      type: "text/html;charset=utf-8",
      content: buildHtmlReport(currentAnalysis, { lookups: lookupResults, now }),
    });
  }
  if (elements.exportJson?.checked) {
    files.push({
      name: reportFilename(currentAnalysis, "json", now),
      type: "application/json;charset=utf-8",
      content: buildJsonReport(currentAnalysis, { lookups: lookupResults, local: localResults, now }),
    });
  }
  if (elements.exportCsv?.checked) {
    files.push({
      name: reportFilename(currentAnalysis, "csv", now),
      type: "text/csv;charset=utf-8",
      content: buildCsvReport(currentAnalysis, {
        lookups: lookupResults,
        includeRaw: !!elements.exportRaw?.checked,
      }),
    });
  }
  if (!files.length) return;

  // Browsers can drop a second download triggered in the same tick; a short
  // gap lets both through.
  files.forEach((f, i) => setTimeout(() => downloadFile(f), i * 350));
  exportStatus(
    files.length > 1
      ? `Downloaded ${files.length} files.`
      : `Downloaded ${files[0].name}`,
  );
}

function downloadFile({ name, type, content }) {
  const url = URL.createObjectURL(new Blob([content], { type }));
  const a = document.createElement("a");
  a.href = url;
  a.download = name;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

// Handle File Upload
function handleFileUpload(e) {
  const chosen = [...e.target.files];
  if (!chosen.length) return;

  // Several files at once: score them all and show the list.
  if (chosen.length > 1) {
    const usable = chosen.filter((f) => !f.name.toLowerCase().endsWith(".msg"));
    if (usable.length < chosen.length) {
      showStatus(
        `${chosen.length - usable.length} .msg file(s) skipped — convert them to .eml first.`,
        "info",
      );
    }
    if (usable.length) analyzeBatch(usable);
    return;
  }

  const file = chosen[0];
  document.getElementById("batch-section")?.classList.add("hidden");

  if (file.name.toLowerCase().endsWith(".msg")) {
    showStatus(
      ".msg files are not yet supported. Please convert to .eml or paste the raw source.",
      "error",
    );
    if (elements.fileUpload) elements.fileUpload.value = "";
    return;
  }

  const reader = new FileReader();
  reader.onload = (event) => {
    if (elements.emailInput) {
      elements.emailInput.value = event.target.result;
    }
    showStatus(`Loaded: ${file.name}`, "success");
  };
  reader.onerror = () => {
    showStatus("Error reading file", "error");
  };
  reader.readAsText(file);
}

// Theme colour: live preview while picking, saved on every change.
function setupThemePicker() {
  const { accentColor, accentValue, resetAccent } = elements;
  if (!accentColor) return;
  const show = (hex) => {
    accentColor.value = hex;
    if (accentValue) accentValue.textContent = hex;
  };
  show(loadAccent());
  accentColor.addEventListener("input", () => {
    show(applyAccent(accentColor.value));
    saveAccent(accentColor.value);
  });
  resetAccent?.addEventListener("click", () => {
    show(applyAccent(DEFAULT_ACCENT));
    saveAccent(DEFAULT_ACCENT);
  });
}

/**
 * Whether API keys may be written to this browser's storage.
 *
 * A key in localStorage outlives the tab, syncs between devices on some
 * browsers, and is readable by anything that ever manages to run script on this
 * origin. Analysts on a shared machine should be able to say no.
 */
function rememberKeys() {
  try {
    return localStorage.getItem("remember-keys") !== "0";
  } catch {
    return false;
  }
}

// Handle Save Settings
function handleSaveSettings() {
  apiKeys.virustotal = elements.virustotalKeyInput
    ? elements.virustotalKeyInput.value.trim()
    : "";
  apiKeys.abuseipdb = elements.abuseipdbKeyInput
    ? elements.abuseipdbKeyInput.value.trim()
    : "";
  apiKeys.corsProxyUrl = elements.corsProxyUrlInput
    ? elements.corsProxyUrlInput.value.trim()
    : "";

  const remember = elements.rememberKeys ? elements.rememberKeys.checked : true;
  try {
    localStorage.setItem("remember-keys", remember ? "1" : "0");
    // The keys stay in memory for this tab either way; only storage differs.
    const store = (name, value) => {
      if (remember && value) localStorage.setItem(name, value);
      else localStorage.removeItem(name);
    };
    store("vt-api-key", apiKeys.virustotal);
    store("abuseipdb-api-key", apiKeys.abuseipdb);
    store("cors-proxy-url", apiKeys.corsProxyUrl);
  } catch (e) {
    console.warn("localStorage not available:", e);
  }

  if (elements.settingsModal) {
    elements.settingsModal.classList.add("hidden");
  }
  showStatus(
    remember
      ? "Settings saved!"
      : "Settings saved for this tab only — nothing was written to browser storage.",
    "success",
  );
}

// Handle Clear Keys
function handleClearKeys() {
  apiKeys.virustotal = "";
  apiKeys.abuseipdb = "";
  apiKeys.corsProxyUrl = "";
  if (elements.virustotalKeyInput) elements.virustotalKeyInput.value = "";
  if (elements.abuseipdbKeyInput) elements.abuseipdbKeyInput.value = "";
  if (elements.corsProxyUrlInput) elements.corsProxyUrlInput.value = "";
  try {
    localStorage.removeItem("vt-api-key");
    localStorage.removeItem("abuseipdb-api-key");
    localStorage.removeItem("cors-proxy-url");
  } catch (e) {
    console.warn("localStorage not available:", e);
  }
  showStatus("API keys cleared.", "info");
}

// Render Results
async function renderResults(analysis) {
  // Show summary section
  const summarySection = document.getElementById("summary-section");
  const summaryContent = document.getElementById("summary-content");
  if (summarySection) summarySection.classList.remove("hidden");
  if (summaryContent) await renderSummary(summaryContent, analysis, apiKeys);

  // Show verdict section
  const verdictSection = document.getElementById("verdict-section");
  const verdictContent = document.getElementById("verdict-content");
  if (verdictSection) verdictSection.classList.remove("hidden");
  if (verdictContent) renderVerdict(verdictContent, analysis.score, analysis.languageAnalysis);

  // Show auth section
  const authSection = document.getElementById("auth-section");
  const authContent = document.getElementById("auth-content");
  if (authSection) authSection.classList.remove("hidden");
  if (authContent) renderAuth(authContent, analysis.auth);

  // Show IOC section
  const iocSection = document.getElementById("ioc-section");
  const iocContent = document.getElementById("ioc-content");
  if (iocSection) iocSection.classList.remove("hidden");
  if (iocContent) renderIOCs(iocContent, analysis.iocs, apiKeys);

  // Show body section
  const bodySection = document.getElementById("body-section");
  const bodyContent = document.getElementById("body-content");
  if (analysis.isFullEmail && analysis.body) {
    if (bodySection) bodySection.classList.remove("hidden");
    if (bodyContent)
      renderBody(bodyContent, analysis.body, analysis.languageAnalysis);
  } else {
    if (bodySection) bodySection.classList.add("hidden");
  }

  // Show headers section
  const headersSection = document.getElementById("headers-section");
  const headersContent = document.getElementById("headers-content");
  if (headersSection) headersSection.classList.remove("hidden");
  if (headersContent) renderHeaders(headersContent, analysis.headers);

  document.getElementById("export-section")?.classList.remove("hidden");
}

// Show Status Message
function showStatus(message, type = "info") {
  if (elements.inputStatus) {
    elements.inputStatus.textContent = message;
    elements.inputStatus.className = "status-message " + type;
  }
}

// ===== LOCAL LOOKUPS: DNS and WHOIS =====
//
// Both run on the machine serving the page (see lookup-local.js), so they need
// no API key and reach no third-party service. On a hosted copy there is no
// such server, and the panels say so instead of failing silently.
const localResults = new Map(); // "whois:<value>" / "dns:<domain>" -> one-line summary
const localCache = new Map();

async function localLookup(path) {
  if (localCache.has(path)) return localCache.get(path);
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 20000);
  try {
    const res = await fetch(path, { signal: controller.signal });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || `HTTP ${res.status}`);
    localCache.set(path, data);
    return data;
  } finally {
    clearTimeout(timer);
  }
}

const NOT_LOCAL_NOTE =
  "This needs the app's own server: run <code>node server.js</code> and open http://localhost:8080. DNS and WHOIS are then resolved by your machine — no third-party service, no API key.";

function daysSince(value) {
  const t = Date.parse(value);
  return Number.isNaN(t) ? null : Math.floor((Date.now() - t) / 86400000);
}

function whoisRows(data) {
  const rows = [];
  const add = (label, value) => {
    if (value && String(value).length) rows.push([label, String(value)]);
  };
  if (data.kind === "ip") {
    add("Network", data.network);
    add("Range", data.range);
    add("Organisation", data.org);
    add("Country", data.country);
    add("Type", data.type);
  } else {
    add("Domain", data.target);
    add("Registrar", data.registrar);
    add("Registrant", data.registrant);
    add("Country", data.country);
    add("Name servers", (data.nameservers || []).slice(0, 4).join(", "));
  }
  add("Registered", data.registered);
  add("Updated", data.updated);
  add("Expires", data.expires);
  add("Status", (data.statuses || []).slice(0, 4).join(", "));
  add("Abuse contact", data.abuseEmail);
  add("Source", data.source);
  return rows;
}

async function fetchWhois(details) {
  const body = details.querySelector(".whois-body");
  if (!body || details.dataset.ready) return;
  details.dataset.ready = "1";
  const { kind, value } = details.dataset;

  if (!isLocalhost) {
    body.innerHTML = `<div class="whois-note">${NOT_LOCAL_NOTE}</div>`;
    return;
  }
  body.innerHTML = '<span class="whois-loading">Looking up registration…</span>';

  try {
    const data = await localLookup(`/lookup/whois?q=${encodeURIComponent(value)}`);
    if (data.notFound) {
      body.innerHTML =
        '<div class="whois-note bad">This domain is not registered. A live link to an unregistered domain is either already taken down or was never real.</div>';
      localResults.set(`whois:${value}`, "not registered");
      return;
    }
    const age = daysSince(data.registered);
    // A domain registered days ago is the single most reliable sign of a
    // throwaway phishing domain.
    const ageBadge =
      age != null
        ? `<span class="whois-age ${age <= 30 ? "bad" : age <= 180 ? "warn" : "ok"}">${
            age <= 1 ? "registered today" : `registered ${age} days ago`
          }</span>`
        : "";
    const rows = whoisRows(data);
    body.innerHTML = `${ageBadge}<dl class="whois-grid">${rows
      .map(([k, v]) => `<dt>${esc(k)}</dt><dd>${esc(v)}</dd>`)
      .join("")}</dl>`;
    localResults.set(
      `whois:${value}`,
      [data.registrar || data.org, data.country, age != null ? `registered ${age} days ago` : null]
        .filter(Boolean)
        .join(" · "),
    );
  } catch (e) {
    body.innerHTML = `<div class="whois-note">Lookup failed: ${esc(e.message)}</div>`;
    details.dataset.ready = "";
  }
}

async function fetchDns(btn) {
  const domain = btn.dataset.domain;
  const box = btn.parentElement?.querySelector(".dns-body");
  if (!box || !domain) return;

  if (!isLocalhost) {
    box.innerHTML = `<div class="whois-note">${NOT_LOCAL_NOTE}</div>`;
    return;
  }
  box.innerHTML = '<span class="whois-loading">Resolving…</span>';
  btn.disabled = true;

  try {
    const d = await localLookup(`/lookup/dns?q=${encodeURIComponent(domain)}`);
    // What the published policy would actually do with a failing message.
    const policy = (d.dmarcPolicy || "").toLowerCase();
    const enforcement =
      policy === "reject"
        ? ["ok", "p=reject — a message that fails DMARC for this domain is refused outright."]
        : policy === "quarantine"
          ? ["warn", "p=quarantine — a failing message is delivered to junk, not refused."]
          : policy === "none"
            ? ["bad", "p=none — the domain publishes DMARC but asks for no action, so a spoof is still delivered."]
            : ["bad", "No DMARC record — nothing stops anyone sending as this domain."];
    const spfNote =
      d.spfAll === "-"
        ? ["ok", "-all — the SPF record rejects every server it does not list."]
        : d.spfAll === "~"
          ? ["warn", "~all — SPF only marks unlisted servers, it does not reject them."]
          : d.spf
            ? ["warn", `${d.spfAll || "?"}all — the SPF record makes no firm assertion.`]
            : ["bad", "No SPF record published."];

    const list = (label, values) =>
      values && values.length
        ? `<div class="dns-row"><span class="dns-label">${esc(label)}</span><span class="dns-value mono">${esc(values.join(", "))}</span></div>`
        : "";

    box.innerHTML = `
      <div class="dns-verdicts">
        <div class="dns-verdict ${spfNote[0]}">${esc(spfNote[1])}</div>
        <div class="dns-verdict ${enforcement[0]}">${esc(enforcement[1])}</div>
      </div>
      ${d.spf ? `<div class="dns-row"><span class="dns-label">SPF</span><span class="dns-value mono">${esc(d.spf)}</span></div>` : ""}
      ${d.dmarc ? `<div class="dns-row"><span class="dns-label">DMARC</span><span class="dns-value mono">${esc(d.dmarc)}</span></div>` : ""}
      ${list("MX", d.mx)}
      ${list("A", d.a)}
      ${list("Name servers", d.ns)}
      ${!d.mx?.length ? '<div class="dns-verdict warn">This domain has no MX record, so it is not set up to receive mail — unusual for a real correspondent.</div>' : ""}
      <div class="dns-note">Resolved by this machine, with your own DNS resolver.</div>`;
    localResults.set(
      `dns:${domain}`,
      [d.spf ? `SPF ${d.spfAll || "?"}all` : "no SPF", d.dmarcPolicy ? `DMARC p=${d.dmarcPolicy}` : "no DMARC", d.mx?.length ? `${d.mx.length} MX` : "no MX"].join(" · "),
    );
  } catch (e) {
    box.innerHTML = `<div class="whois-note">Lookup failed: ${esc(e.message)}</div>`;
  } finally {
    btn.disabled = false;
  }
}

// ===== COPY IOC =====
function copyIOC(btn) {
  const row = btn.closest("tr");
  const original = row?.querySelector(".ioc-original");
  const defanged = row?.querySelector(".ioc-defanged");
  // Copy whichever is visible
  const textToCopy =
    defanged && !defanged.classList.contains("hidden")
      ? defanged.textContent
      : original?.textContent || "";
  navigator.clipboard
    .writeText(textToCopy)
    .then(() => {
      btn.textContent = "Copied!";
      setTimeout(() => (btn.textContent = "Copy"), 2000);
    })
    .catch(() => {
      btn.textContent = "Failed";
      setTimeout(() => (btn.textContent = "Copy"), 2000);
    });
}

// ===== TOGGLE DEFANG =====
function toggleDefang(btn) {
  const row = btn.closest("tr");
  const original = row?.querySelector(".ioc-original");
  const defanged = row?.querySelector(".ioc-defanged");
  if (!original || !defanged) return;

  const isDefanged = !defanged.classList.contains("hidden");
  if (isDefanged) {
    defanged.classList.add("hidden");
    original.classList.remove("hidden");
    btn.textContent = "Defang";
  } else {
    defanged.classList.remove("hidden");
    original.classList.add("hidden");
    btn.textContent = "Original";
  }
}

/**
 * Locate the panel a lookup result should render into.
 *
 * IOC tables put the result in a hidden row directly after the button's row;
 * the summary IP card marks itself with data-lookup-scope and holds its own
 * result box. Supporting both is what lets the same lookup buttons live
 * outside the IOC table.
 */
function findResultTarget(btn) {
  const row = btn.closest("tr");
  if (row) {
    const resultRow = row.nextElementSibling;
    const content = resultRow?.querySelector(".lookup-result-content");
    if (content) return { reveal: resultRow, content };
  }
  const scope = btn.closest("[data-lookup-scope]");
  const content = scope?.querySelector(".lookup-result-content");
  if (content) return { reveal: null, content };
  return null;
}

// ===== COPY ARBITRARY TEXT =====
function copyText(text, btn) {
  navigator.clipboard
    .writeText(text)
    .then(() => {
      const original = btn.textContent;
      btn.textContent = "Copied!";
      setTimeout(() => (btn.textContent = original), 2000);
    })
    .catch(() => {
      btn.textContent = "Failed";
      setTimeout(() => (btn.textContent = "Copy"), 2000);
    });
}

// ===== VIRUSTOTAL LOOKUP =====
async function lookupVirusTotal(btn) {
  const value = btn.dataset.value;
  const type = btn.dataset.type;
  if (!value || !apiKeys.virustotal) return;

  // Validate key format (VT keys are 64-char hex)
  const target = findResultTarget(btn);
  if (!target) return;
  const { reveal: resultRow, content: resultContent } = target;
  if (resultRow) resultRow.classList.remove("hidden");

  if (type === "ip" && !isValidIP(value)) {
    resultContent.innerHTML = `<span class="lookup-error">"${esc(value)}" is not a valid IP address, so there is nothing to look up.</span>`;
    return;
  }

  const key = apiKeys.virustotal.trim();
  if (!/^[a-f0-9]{64}$/i.test(key)) {
    resultContent.innerHTML =
      '<span class="lookup-error">Invalid VirusTotal API key format. Key should be 64 hex characters. Check Settings.</span>';
    return;
  }

  const cacheKey = `vt:${type}:${value}`;
  if (lookupCache.has(cacheKey)) {
    resultContent.innerHTML = lookupCache.get(cacheKey);
    return;
  }

  resultContent.innerHTML =
    '<span class="lookup-loading">Loading VirusTotal...</span>';
  btn.disabled = true;

  try {
    let endpoint = "";
    let submitEndpoint = "";
    let submitBody = "";
    let submitContentType = "";

    if (type === "attachment") {
      // File hash lookup. The button carries the hash computed at analysis
      // time; the byte map is the fallback.
      let hash = btn.dataset.sha256;
      if (!hash) {
        const bytes = attachmentContentMap.get(value);
        if (bytes) {
          resultContent.innerHTML =
            '<span class="lookup-loading">Computing hash...</span>';
          hash = await sha256Bytes(bytes);
        }
      }
      if (!hash) {
        resultContent.innerHTML =
          '<span class="lookup-error">Cannot compute hash: this part carried no decodable content. The pasted source may be truncated.</span>';
        btn.disabled = false;
        return;
      }
      endpoint = getVTEndpoint(`/api/v3/files/${hash}`);
    } else if (type === "ip") {
      // IP address lookup
      endpoint = getVTEndpoint(`/api/v3/ip_addresses/${encodeURIComponent(value)}`);
    } else if (type === "domain") {
      // Domain lookup
      endpoint = getVTEndpoint(`/api/v3/domains/${encodeURIComponent(value)}`);
    } else {
      // URL lookup (default)
      const urlId = await vtUrlId(value);
      endpoint = getVTEndpoint(`/api/v3/urls/${urlId}`);
      submitEndpoint = getVTSubmitEndpoint();
      submitBody = `url=${encodeURIComponent(value)}`;
      submitContentType = "application/x-www-form-urlencoded";
    }

    console.log("[VT] Fetching:", endpoint);
    console.log("[VT] Key prefix:", apiKeys.virustotal.substring(0, 8) + "...");

    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 15000);
    const response = await fetch(endpoint, {
      method: "GET",
      headers: {
        "x-apikey": apiKeys.virustotal,
        Accept: "application/json",
      },
      signal: controller.signal,
    });
    clearTimeout(timeoutId);

    console.log("[VT] Response status:", response.status);

    if (response.status === 404 && submitEndpoint) {
      // URL not analyzed yet - submit for analysis
      resultContent.innerHTML =
        '<span class="lookup-info">URL not found in VirusTotal. Submitting for analysis...</span>';
      const submitController = new AbortController();
      const submitTimeout = setTimeout(() => submitController.abort(), 15000);
      const submitResponse = await fetch(submitEndpoint, {
        method: "POST",
        headers: {
          "x-apikey": apiKeys.virustotal,
          "Content-Type": submitContentType,
        },
        body: submitBody,
        signal: submitController.signal,
      });
      clearTimeout(submitTimeout);
      console.log("[VT] Submit response status:", submitResponse.status);
      if (submitResponse.ok) {
        resultContent.innerHTML =
          '<span class="lookup-info">URL submitted to VirusTotal for analysis. Check back in a few minutes.</span>';
      } else {
        const err = await submitResponse.json();
        resultContent.innerHTML = `<span class="lookup-error">Error: ${esc(err.error?.message || "Unknown error")}</span>`;
      }
      return;
    }

    if (response.status === 404) {
      resultContent.innerHTML = `<span class="lookup-info">Not found in VirusTotal database.</span>`;
      return;
    }

    if (!response.ok) {
      const err = await response.json().catch(() => ({}));
      const errMsg = err.error?.message || `HTTP ${response.status}`;
      let hint = "";
      if (response.status === 401) hint = " API key is invalid or missing.";
      else if (response.status === 429) hint = " Rate limited. Wait a moment and try again.";
      else if (response.status === 403) hint = " API key lacks required permissions.";
      resultContent.innerHTML = `<span class="lookup-error">Error:${hint} ${esc(errMsg)}</span>`;
      return;
    }

    const data = await response.json();
    const attrs = data.data?.attributes || {};
    const stats = attrs.last_analysis_stats || {};
    const malicious = stats.malicious || 0;
    const suspicious = stats.suspicious || 0;

    const reputationClass =
      malicious > 0
        ? "lookup-malicious"
        : suspicious > 0
          ? "lookup-suspicious"
          : "lookup-clean";

    const engines =
      malicious + suspicious + (stats.harmless || 0) + (stats.undetected || 0);
    lookupResults.set(
      `vt:${value}`,
      `${malicious > 0 ? "Malicious" : suspicious > 0 ? "Suspicious" : "Clean"} — ${malicious + suspicious}/${engines} engines flagged`,
    );

    // Build type-specific display.
    // The rescan path is spelled "analyse": VirusTotal v3 uses the British
    // spelling, so every "/analyze" request returned 404.
    let typeLabel = "VirusTotal";
    let analysePath = "";
    if (type === "attachment") {
      typeLabel = "VirusTotal (File Hash)";
      const bytes = attachmentContentMap.get(value);
      const hash = btn.dataset.sha256 || (bytes ? await sha256Bytes(bytes) : null);
      if (hash) analysePath = `/api/v3/files/${hash}/analyse`;
    } else if (type === "ip") {
      typeLabel = "VirusTotal (IP)";
      analysePath = `/api/v3/ip_addresses/${encodeURIComponent(value)}/analyse`;
    } else if (type === "domain") {
      typeLabel = "VirusTotal (Domain)";
      analysePath = `/api/v3/domains/${encodeURIComponent(value)}/analyse`;
    } else {
      typeLabel = "VirusTotal (URL)";
      analysePath = `/api/v3/urls/${await vtUrlId(value)}/analyse`;
    }

    // Build creation date line.
    // The previous `attrs註冊_date` here was not a property access — CJK
    // characters are valid JS identifier characters, so it parsed as one
    // undefined variable and threw a ReferenceError on every domain lookup
    // that lacked creation_date. The outer catch then reported a successful
    // HTTP 200 as "API UNAVAILABLE".
    const created = attrs.creation_date ?? attrs.registration_date;
    const creationDateHtml = created
      ? `<div class="lookup-meta">Created: ${new Date(created * 1000).toLocaleDateString("en-US", { year: "numeric", month: "short", day: "numeric" })}</div>`
      : "";

    resultContent.innerHTML = `
      <div class="lookup-result vt-result">
        <div class="lookup-header">
          <strong>${esc(typeLabel)}</strong>
          <div class="lookup-header-actions">
            <span class="lookup-reputation ${reputationClass}">
              ${malicious > 0 ? "MALICIOUS" : suspicious > 0 ? "SUSPICIOUS" : "CLEAN"}
            </span>
          </div>
        </div>
        <div class="lookup-stats">
          <span class="stat malicious">${malicious} malicious</span>
          <span class="stat suspicious">${suspicious} suspicious</span>
          <span class="stat harmless">${stats.harmless || 0} harmless</span>
          <span class="stat undetected">${stats.undetected || 0} undetected</span>
        </div>
        ${creationDateHtml}
        ${attrs.last_analysis_date ? `<div class="lookup-meta">Last analyzed: ${new Date(attrs.last_analysis_date * 1000).toLocaleString()}</div>` : ""}
        ${attrs.reputation != null ? `<div class="lookup-meta">Reputation: ${attrs.reputation}</div>` : ""}
        ${attrs.as_owner ? `<div class="lookup-meta">AS Owner: ${esc(attrs.as_owner)}</div>` : ""}
        ${attrs.country ? `<div class="lookup-meta">Country: ${esc(attrs.country)}</div>` : ""}
        ${attrs.meaningful_name ? `<div class="lookup-meta">Name: ${esc(attrs.meaningful_name)}</div>` : ""}
        ${analysePath ? `<div class="lookup-actions"><button class="btn-rescan" data-url="${esc(value)}" data-act="rescan" data-path="${esc(analysePath)}" title="Force fresh analysis on VirusTotal">
          <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="23 4 23 10 17 10"/><polyline points="1 20 1 14 7 14"/><path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15"/></svg>
          Rescan
        </button>
        <a href="https://www.virustotal.com/gui/search/${encodeURIComponent(value)}" target="_blank" rel="noopener" class="btn-vt-web">Open in VT ↗</a>
        </div>` : ""}
      </div>
    `;
    // Only successful results are cached; errors stay retryable.
    lookupCache.set(cacheKey, resultContent.innerHTML);
  } catch (error) {
    let webUrl = "";
    let specificHint = "";
    if (error.name === "AbortError") {
      specificHint = "Request timed out. Try again or check your network.";
    } else if (error.message?.includes("Failed to fetch") || error.message?.includes("NetworkError")) {
      if (isLocalhost) {
        specificHint = "Is the server running? Start it with: node server.js";
      } else {
        specificHint = "CORS error. Configure a CORS proxy in Settings or run locally with: node server.js";
      }
    }
    if (type === "attachment") {
      const hash = btn.dataset.sha256;
      webUrl = hash
        ? `https://www.virustotal.com/gui/file/${hash}`
        : `https://www.virustotal.com/gui/search/${encodeURIComponent(value)}`;
    } else if (type === "ip") {
      webUrl = `https://www.virustotal.com/gui/ip-address/${encodeURIComponent(value)}`;
    } else if (type === "domain") {
      webUrl = `https://www.virustotal.com/gui/domain/${encodeURIComponent(value)}`;
    } else {
      webUrl = `https://www.virustotal.com/gui/search/${encodeURIComponent(value)}`;
    }

    resultContent.innerHTML = `
      <div class="lookup-result">
        <div class="lookup-header">
          <strong>VirusTotal</strong>
          <span class="lookup-reputation lookup-suspicious">API UNAVAILABLE</span>
        </div>
        <div class="lookup-info">
          ${specificHint ? `<div style="margin-bottom:6px;color:var(--accent,#9fef00);font-weight:600">${esc(specificHint)}</div>` : ""}
          ${esc(error.message || "Could not connect to VirusTotal API.")}
          <a href="${webUrl}" target="_blank" rel="noopener" class="btn-lookup" style="display:inline-block;margin-top:8px;">Open in VirusTotal ↗</a>
        </div>
      </div>
    `;
  } finally {
    btn.disabled = false;
  }
}

// ===== ABUSEIPDB LOOKUP =====
async function lookupAbuseIPDB(btn) {
  const ip = btn.dataset.value;
  if (!ip || !apiKeys.abuseipdb) return;

  // Validate key format (AbuseIPDB keys are typically 40+ chars)
  const target = findResultTarget(btn);
  if (!target) return;
  const { reveal: resultRow, content: resultContent } = target;
  if (resultRow) resultRow.classList.remove("hidden");

  // Never spend a request on something that is not an address. The renderer
  // already withholds the button, but the check belongs here too so no future
  // caller can reintroduce the problem.
  if (!isValidIP(ip)) {
    resultContent.innerHTML = `<span class="lookup-error">"${esc(ip)}" is not a valid IP address, so there is nothing to look up.</span>`;
    return;
  }
  if (!isRoutableIP(ip)) {
    resultContent.innerHTML = `<span class="lookup-info">${esc(ip)} is a private or reserved address. Reputation services hold no data for it.</span>`;
    return;
  }

  const key = apiKeys.abuseipdb.trim();
  if (key.length < 20) {
    resultContent.innerHTML =
      '<span class="lookup-error">Invalid AbuseIPDB API key format. Check Settings.</span>';
    return;
  }

  const cacheKey = `abuse:${ip}`;
  if (lookupCache.has(cacheKey)) {
    resultContent.innerHTML = lookupCache.get(cacheKey);
    return;
  }

  resultContent.innerHTML =
    '<span class="lookup-loading">Loading AbuseIPDB...</span>';
  btn.disabled = true;

  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 15000);
    const response = await fetch(
      getAbuseIPDBEndpoint(`/check?ipAddress=${encodeURIComponent(ip)}&maxAgeInDays=90`),
      {
        method: "GET",
        headers: {
          Key: apiKeys.abuseipdb,
          Accept: "application/json",
        },
        signal: controller.signal,
      },
    );
    clearTimeout(timeoutId);

    if (!response.ok) {
      const err = await response.json().catch(() => ({}));
      const errMsg = err.errors?.[0]?.detail || `HTTP ${response.status}`;
      let hint = "";
      if (response.status === 401) hint = " API key is invalid. ";
      else if (response.status === 429) hint = " Rate limited. Wait and try again. ";
      resultContent.innerHTML = `<span class="lookup-error">Error:${hint}${esc(errMsg)}</span>`;
      return;
    }

    const data = await response.json();
    const attrs = data.data || {};
    const score = attrs.abuseConfidenceScore || 0;

    const reputationClass =
      score >= 50
        ? "lookup-malicious"
        : score >= 25
          ? "lookup-suspicious"
          : "lookup-clean";

    lookupResults.set(
      `abuse:${ip}`,
      [
        `${score}% abuse confidence`,
        `${attrs.totalReports || 0} reports`,
        attrs.countryCode,
        attrs.isp,
      ]
        .filter(Boolean)
        .join(" · "),
    );

    resultContent.innerHTML = `
      <div class="lookup-result abuse-result">
        <div class="lookup-header">
          <strong>AbuseIPDB</strong>
          <span class="lookup-reputation ${reputationClass}">
            ${score >= 50 ? "⚠ HIGH RISK" : score >= 25 ? "⚡ ELEVATED" : "✓ LOW RISK"}
          </span>
        </div>
        <div class="lookup-stats">
          <span class="stat malicious">Abuse Score: ${score}%</span>
          <span class="stat suspicious">Total Reports: ${attrs.totalReports || 0}</span>
          <span class="stat harmless">Country: ${esc(attrs.countryCode || "N/A")}</span>
          <span class="stat undetected">ISP: ${esc(attrs.isp || "N/A")}</span>
        </div>
        ${attrs.domain ? `<div class="lookup-domain">Domain: ${esc(attrs.domain)}</div>` : ""}
        ${attrs.usageType ? `<div class="lookup-usage">Usage: ${esc(attrs.usageType)}</div>` : ""}
        ${attrs.lastReportedAt ? `<div class="lookup-date">Last reported: ${new Date(attrs.lastReportedAt).toLocaleString()}</div>` : ""}
      </div>
    `;
    lookupCache.set(cacheKey, resultContent.innerHTML);
  } catch (error) {
    const webUrl = `https://www.abuseipdb.com/check/${encodeURIComponent(ip)}`;
    let specificHint = "";
    if (error.name === "AbortError") {
      specificHint = "Request timed out. Try again or check your network.";
    } else if (error.message?.includes("Failed to fetch") || error.message?.includes("NetworkError")) {
      if (isLocalhost) {
        specificHint = "Is the server running? Start it with: node server.js";
      } else {
        specificHint = "CORS error. Configure a CORS proxy in Settings or run locally.";
      }
    }
    resultContent.innerHTML = `
      <div class="lookup-result">
        <div class="lookup-header">
          <strong>AbuseIPDB</strong>
          <span class="lookup-reputation lookup-suspicious">API UNAVAILABLE</span>
        </div>
        <div class="lookup-info">
          ${specificHint ? `<div style="margin-bottom:6px;color:var(--accent,#9fef00);font-weight:600">${esc(specificHint)}</div>` : ""}
          ${esc(error.message || "Could not connect to AbuseIPDB API.")}
          <a href="${webUrl}" target="_blank" rel="noopener" class="btn-lookup" style="display:inline-block;margin-top:8px;">Open in AbuseIPDB ↗</a>
        </div>
      </div>
    `;
  } finally {
    btn.disabled = false;
  }
}

// Escape HTML helper (uses DOM to avoid entity encoding issues)
function esc(s) {
  if (s == null) return "";
  const div = document.createElement("div");
  div.textContent = String(s);
  return div.innerHTML;
}

// ===== VT RESCAN =====
async function rescanVT(analysePath, btn) {
  if (!apiKeys.virustotal) return;
  btn.disabled = true;
  const originalHtml = btn.innerHTML;
  btn.innerHTML = '<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="23 4 23 10 17 10"/><polyline points="1 20 1 14 7 14"/><path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15"/></svg> Rescanning...';

  try {
    const url = getVTAnalyseEndpoint(analysePath);
    console.log("[VT] Rescan ->", url);

    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 15000);

    const response = await fetch(url, {
      method: "POST",
      headers: {
        "x-apikey": apiKeys.virustotal,
        Accept: "application/json",
      },
      signal: controller.signal,
    });
    clearTimeout(timeoutId);

    console.log("[VT] Rescan status:", response.status);

    if (response.status === 204 || response.ok) {
      btn.innerHTML = '<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="20 6 9 17 4 12"/></svg> Queued';
      btn.classList.add("rescan-queued");
      const row = btn.closest(".lookup-result");
      if (row) {
        const infoDiv = document.createElement("div");
        infoDiv.className = "lookup-meta";
        infoDiv.textContent = "Analysis queued. Click VT again in ~30s for fresh results.";
        row.appendChild(infoDiv);
      }
      return;
    }

    const errData = await response.json().catch(() => null);
    console.error("[VT] Rescan response:", response.status, errData);

    // Rescan of a URL VirusTotal has never seen fails; submitting it is the
    // documented way to get it analysed. The identifier is a SHA-256 now and
    // cannot be decoded back, so the original URL travels on the button.
    if (analysePath.includes("/urls/")) {
      const decoded = btn.dataset.url;
      if (decoded) {
        const submitController = new AbortController();
        const submitTimeout = setTimeout(() => submitController.abort(), 15000);
        const submitResp = await fetch(getVTSubmitEndpoint(), {
          method: "POST",
          headers: {
            "x-apikey": apiKeys.virustotal,
            "Content-Type": "application/x-www-form-urlencoded",
            Accept: "application/json",
          },
          body: `url=${encodeURIComponent(decoded)}`,
          signal: submitController.signal,
        });
        clearTimeout(submitTimeout);
        if (submitResp.ok || submitResp.status === 204) {
          btn.innerHTML = '<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="20 6 9 17 4 12"/></svg> Queued';
          btn.classList.add("rescan-queued");
          const row = btn.closest(".lookup-result");
          if (row) {
            const infoDiv = document.createElement("div");
            infoDiv.className = "lookup-meta";
            infoDiv.textContent = "URL resubmitted for analysis.";
            row.appendChild(infoDiv);
          }
          return;
        }
      }
    }

    const errMsg = errData?.error?.message || `HTTP ${response.status}`;
    btn.innerHTML = 'Failed';
    btn.classList.add("rescan-failed");
    btn.title = errMsg;
    setTimeout(() => { btn.innerHTML = originalHtml; btn.classList.remove("rescan-failed"); }, 3000);
  } catch (error) {
    console.error("[VT] Rescan error:", error);
    let hint = "";
    if (error.name === "AbortError") {
      hint = "Request timed out. ";
    } else if (error.message?.includes("Failed to fetch") && isLocalhost) {
      hint = "Is the server running? ";
    }
    btn.innerHTML = 'Failed';
    btn.classList.add("rescan-failed");
    btn.title = error.message;
    setTimeout(() => { btn.innerHTML = originalHtml; btn.classList.remove("rescan-failed"); }, 3000);
  } finally {
    btn.disabled = false;
  }
}

// One delegated listener for every result button.
//
// Results are built as HTML strings, and inline onclick handlers meant the page
// could never run under a strict Content-Security-Policy — one escaping mistake
// in a value taken from the email would have been code execution. Buttons now
// carry data-act and nothing is exposed on window.
const ACTIONS = {
  vt: (btn) => lookupVirusTotal(btn),
  abuse: (btn) => lookupAbuseIPDB(btn),
  rescan: (btn) => rescanVT(btn.dataset.path, btn),
  "copy-ioc": (btn) => copyIOC(btn),
  defang: (btn) => toggleDefang(btn),
  "copy-text": (btn) => copyText(btn.dataset.text || "", btn),
  "copy-prev": (btn) => copyText(btn.previousElementSibling?.textContent || "", btn),
  "show-all": (btn) => showAllIOCs(btn.dataset.section),
  decode: (btn) => runDecoder(btn, btn.dataset.decoder),
  settings: () => promptSettings(),
  dns: (btn) => fetchDns(btn),
  "copy-iocs": (btn) => copyAllIOCs(btn),
  "open-batch": (btn) => openBatchItem(btn.dataset.index),
};

document.addEventListener("click", (e) => {
  const btn = e.target.closest?.("[data-act]");
  if (!btn) return;
  const run = ACTIONS[btn.dataset.act];
  if (!run) return;
  e.preventDefault();
  run(btn);
});

// "toggle" does not bubble, so the decoder panels are caught in the capture phase.
document.addEventListener(
  "toggle",
  (e) => {
    if (e.target.classList?.contains("url-decode")) renderDecoders(e.target);
    if (e.target.classList?.contains("whois-panel") && e.target.open) fetchWhois(e.target);
  },
  true,
);

// Prompt user to open settings (for disabled lookup buttons)
function promptSettings() {
  if (elements.settingsModal) {
    elements.settingsModal.classList.remove("hidden");
  }
}

// Initialize on DOM ready
if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", init);
} else {
  init();
}
