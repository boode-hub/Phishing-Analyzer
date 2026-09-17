// Main Application Entry Point
// Phishing Email Analyzer - Local Browser-Based

import { parseHeaders } from "./parse-headers.js";
import { parseAuth } from "./parse-auth.js";
import { parseBody } from "./parse-body.js";
import { extractIOCs } from "./extract-iocs.js";
import { analyzeLanguage } from "./analyze-language.js";
import { calculateScore } from "./score.js";
import { sha256Bytes, md5Bytes } from "./hash-utils.js";
import { isValidIP, isRoutableIP } from "./ip-utils.js";
import { buildMarkdownReport, buildCsvReport, reportFilename } from "./report.js";
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
    exportMd: "export-md",
    exportCsv: "export-csv",
    exportRaw: "export-raw",
    exportDownload: "export-download",
    exportCopy: "export-copy",
    exportStatus: "export-status",
    apiAvailability: "api-availability",
    proxyField: "proxy-field",
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

  elements.exportDownload?.addEventListener("click", handleExportDownload);
  elements.exportCopy?.addEventListener("click", handleExportCopy);
  for (const box of [elements.exportMd, elements.exportCsv]) {
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
      "proxy setup, no other configuration.";
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
    console.log("[Phishing Analyzer] Starting analysis...");

    // Detect if it's headers-only or full email
    const isFullEmail = detectFullEmail(input);
    console.log("[Phishing Analyzer] isFullEmail:", isFullEmail);

    // Parse headers
    const headers = parseHeaders(input);
    console.log("[Phishing Analyzer] Headers parsed");

    // Refuse to issue a verdict on something that is not an email. Arbitrary
    // text used to come back "Low Risk", which reads as a clean bill of health.
    const EMAIL_HEADERS = [
      "from", "to", "subject", "date", "received", "message-id", "return-path",
      "authentication-results", "received-spf", "dkim-signature", "reply-to",
      "mime-version", "content-type",
    ];
    if (!EMAIL_HEADERS.some((h) => h in headers.all)) {
      hideResults();
      showStatus(
        "No email headers found — this doesn't look like an email. Paste the full raw message source (headers and body), or upload the .eml file.",
        "error",
      );
      return;
    }

    // Parse authentication
    const auth = parseAuth(headers);
    console.log("[Phishing Analyzer] Auth parsed:", auth?.overall);

    // Parse body (if full email)
    let body = null;
    if (isFullEmail) {
      body = parseBody(input);
      console.log("[Phishing Analyzer] Body parsed");
    }

    // Extract IOCs
    const iocs = extractIOCs(headers, body);
    console.log("[Phishing Analyzer] IOCs extracted:", {
      urls: iocs?.urls?.length,
      domains: iocs?.domains?.length,
      ips: iocs?.ips?.length,
    });

    // Hash every extracted file — attachments and inline images alike — so the
    // hashes are on screen without a lookup, and a VirusTotal file check is one
    // click away. Previously no attachment ever carried its content this far,
    // so the file-hash lookup always reported "content not available".
    attachmentContentMap.clear();
    for (const att of iocs.attachments || []) {
      if (att.bytes && att.bytes.length) {
        att.sha256 = await sha256Bytes(att.bytes);
        att.md5 = md5Bytes(att.bytes);
        attachmentContentMap.set(att.value, att.bytes);
      }
    }
    console.log(
      "[Phishing Analyzer] Files hashed:",
      (iocs.attachments || []).length,
    );

    // Analyze language (if body available)
    let languageAnalysis = null;
    if (body && body.text) {
      languageAnalysis = analyzeLanguage(body.text);
      console.log("[Phishing Analyzer] Language analyzed");
    }

    // Calculate score
    const score = calculateScore(auth, iocs, languageAnalysis, headers);
    console.log("[Phishing Analyzer] Score calculated:", score?.tier);

    // Store analysis
    currentAnalysis = {
      headers,
      auth,
      body,
      iocs,
      languageAnalysis,
      score,
      rawInput: input,
      isFullEmail,
    };

    // Render results
    await renderResults(currentAnalysis);

    showStatus("Analysis complete!", "success");
    console.log("[Phishing Analyzer] Analysis complete");
  } catch (error) {
    console.error("[Phishing Analyzer] Analysis error:", error);
    hideResults();
    showStatus("Error analyzing email: " + error.message, "error");
  }
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
  const md = elements.exportMd?.checked;
  const csv = elements.exportCsv?.checked;
  if (elements.exportDownload) elements.exportDownload.disabled = !md && !csv;
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

function handleExportDownload() {
  if (!currentAnalysis) return;
  const now = new Date();
  const files = [];

  if (elements.exportMd?.checked) {
    files.push({
      name: reportFilename(currentAnalysis, "md", now),
      type: "text/markdown;charset=utf-8",
      content: buildMarkdownReport(currentAnalysis, { lookups: lookupResults, now }),
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
    files.length === 2
      ? "Downloaded Markdown and CSV reports."
      : `Downloaded ${files[0].name}`,
  );
}

async function handleExportCopy() {
  if (!currentAnalysis) return;
  try {
    await navigator.clipboard.writeText(
      buildMarkdownReport(currentAnalysis, { lookups: lookupResults }),
    );
    exportStatus("Markdown report copied to the clipboard.");
  } catch {
    exportStatus("Could not access the clipboard — use Download instead.", "error");
  }
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
  const file = e.target.files[0];
  if (!file) return;

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

  try {
    if (apiKeys.virustotal) {
      localStorage.setItem("vt-api-key", apiKeys.virustotal);
    } else {
      localStorage.removeItem("vt-api-key");
    }

    if (apiKeys.abuseipdb) {
      localStorage.setItem("abuseipdb-api-key", apiKeys.abuseipdb);
    } else {
      localStorage.removeItem("abuseipdb-api-key");
    }

    if (apiKeys.corsProxyUrl) {
      localStorage.setItem("cors-proxy-url", apiKeys.corsProxyUrl);
    } else {
      localStorage.removeItem("cors-proxy-url");
    }
  } catch (e) {
    console.warn("localStorage not available:", e);
  }

  if (elements.settingsModal) {
    elements.settingsModal.classList.add("hidden");
  }
  showStatus("Settings saved!", "success");
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
        ${analysePath ? `<div class="lookup-actions"><button class="btn-rescan" data-url="${esc(value)}" onclick="rescanVT('${esc(analysePath)}', this)" title="Force fresh analysis on VirusTotal">
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

// Expose functions globally for inline onclick handlers
window.lookupVirusTotal = lookupVirusTotal;
window.lookupAbuseIPDB = lookupAbuseIPDB;
window.copyIOC = copyIOC;
window.toggleDefang = toggleDefang;
window.promptSettings = promptSettings;
window.rescanVT = rescanVT;
window.showAllIOCs = showAllIOCs;
window.renderDecoders = renderDecoders;
window.runDecoder = runDecoder;
window.copyText = copyText;

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
