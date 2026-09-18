// Compare page
//
// The main page answers "is this message phishing". This page answers the
// question that comes next in a real inbox: "are these ten messages the same
// campaign, and what do they have in common". Everything runs locally, exactly
// as on the main page — the same parsers, the same scoring.

import { parseHeaders } from "./parse-headers.js";
import { parseAuth } from "./parse-auth.js";
import { parseBody } from "./parse-body.js";
import { extractIOCs } from "./extract-iocs.js";
import { analyzeLanguage } from "./analyze-language.js";
import { analyzeIdentity } from "./analyze-identity.js";
import { calculateScore } from "./score.js";
import { sha256Bytes, md5Bytes } from "./hash-utils.js";
import { buildComparison, comparisonCsv, comparisonJson } from "./compare-model.js";
import { applyAccent, loadAccent } from "./theme.js";

// This page is no more meant to be framed than the main one.
if (window.top !== window.self) {
  document.documentElement.textContent = "This tool refuses to run inside a frame.";
  throw new Error("Refusing to run in a frame");
}

applyAccent(loadAccent());

const EMAIL_HEADERS = [
  "from", "to", "subject", "date", "received", "message-id", "return-path",
  "authentication-results", "received-spf", "dkim-signature", "reply-to",
  "mime-version", "content-type",
];

/** Messages currently on the page, in the order they were added. */
const items = [];

const $ = (id) => document.getElementById(id);
const esc = (value) => {
  const div = document.createElement("div");
  div.textContent = value == null ? "" : String(value);
  return div.innerHTML;
};

function status(message, type = "info") {
  const el = $("compare-status");
  if (!el) return;
  el.textContent = message;
  el.className = `status-message ${type}`;
}

/** The same pipeline the main page runs, minus the rendering. */
async function analyse(raw) {
  const headers = parseHeaders(raw);
  if (!EMAIL_HEADERS.some((h) => h in headers.all)) {
    throw new Error("No email headers found — this file is not a message.");
  }
  const auth = parseAuth(headers);
  const body = raw.includes("\r\n\r\n") || raw.includes("\n\n") ? parseBody(raw) : null;
  const iocs = extractIOCs(headers, body);
  for (const att of iocs.attachments || []) {
    if (att.bytes && att.bytes.length) {
      att.sha256 = await sha256Bytes(att.bytes);
      att.md5 = md5Bytes(att.bytes);
    }
  }
  const languageAnalysis = body && body.text ? analyzeLanguage(body.text) : null;
  const identity = analyzeIdentity(headers);
  const score = calculateScore(auth, iocs, languageAnalysis, headers, identity);
  return { headers, auth, body, iocs, languageAnalysis, identity, score };
}

async function addFiles(files) {
  const usable = [...files].filter((f) => !f.name.toLowerCase().endsWith(".msg"));
  const skipped = files.length - usable.length;
  if (!usable.length) {
    status(".msg files are not supported yet — convert them to .eml first.", "error");
    return;
  }

  status(`Analyzing ${usable.length} message${usable.length === 1 ? "" : "s"}…`);
  let failed = 0;
  for (const file of usable) {
    try {
      const analysis = await analyse(await file.text());
      items.push({ name: file.name, analysis });
    } catch (e) {
      failed++;
      console.warn("[compare]", file.name, e.message);
    }
  }

  render();
  const parts = [`${items.length} message${items.length === 1 ? "" : "s"} loaded`];
  if (failed) parts.push(`${failed} skipped (not an email)`);
  if (skipped) parts.push(`${skipped} .msg skipped`);
  status(parts.join(" · "), failed || skipped ? "info" : "success");
}

async function addSamples() {
  const names = ["phishing-spoofed.eml", "phishing-urgency.eml", "legitimate-email.eml"];
  const files = [];
  for (const name of names) {
    try {
      const res = await fetch(`sample-data/${name}`);
      if (res.ok) files.push(new File([await res.text()], name));
    } catch {
      /* the samples are optional */
    }
  }
  if (!files.length) {
    status("The sample messages could not be loaded from this copy.", "error");
    return;
  }
  addFiles(files);
}

// ===== rendering =====

function render() {
  $("compare-count").textContent = items.length ? `${items.length} loaded` : "";
  const hasItems = items.length > 0;
  $("table-panel").classList.toggle("hidden", !hasItems);
  $("shared-panel").classList.toggle("hidden", items.length < 2);
  if (!hasItems) {
    $("table-content").innerHTML = "";
    $("shared-content").innerHTML = "";
    return;
  }

  const { rows, shared } = buildComparison(items);
  renderShared(shared);
  renderTable(rows);
}

function tierClass(analysis) {
  const tier = analysis.score?.tier;
  return tier === "High Risk" ? "high" : tier === "Suspicious" ? "medium" : "low";
}

function renderTable(rows) {
  const onlyDiff = $("hide-identical").checked;
  const shownRows = onlyDiff ? rows.filter((r) => !r.identical) : rows;

  const headCells = items
    .map(
      (item, index) => `<th class="msg-col">
        <div class="msg-head">
          <span class="msg-index">${index + 1}</span>
          <span class="msg-name" title="${esc(item.name)}">${esc(item.name)}</span>
          <button class="msg-remove" type="button" data-act="remove" data-index="${index}" title="Remove this message" aria-label="Remove ${esc(item.name)}">×</button>
        </div>
        <span class="batch-tier ${tierClass(item.analysis)}">${esc(item.analysis.score?.tier || "Unknown")} ${item.analysis.score?.score ?? ""}</span>
      </th>`,
    )
    .join("");

  const body = shownRows
    .map(
      (row) => `<tr class="${row.identical ? "row-identical" : ""}">
        <th scope="row" class="prop-col">${esc(row.label)}</th>
        ${row.cells
          .map(
            (cell) =>
              `<td class="cell ${cell.tone || ""} ${cell.shared ? "cell-shared" : ""}" title="${esc(cell.value)}">${esc(cell.value)}${
                cell.shared ? '<span class="shared-dot" title="Also seen in another message">shared</span>' : ""
              }</td>`,
          )
          .join("")}
      </tr>`,
    )
    .join("");

  $("table-content").innerHTML = `<div class="table-scroll compare-scroll">
      <table class="compare-table">
        <thead><tr><th class="prop-col">Property</th>${headCells}</tr></thead>
        <tbody>${body}</tbody>
      </table>
    </div>
    <p class="compare-note">Values highlighted in green appear in more than one message — that is the thread tying a campaign together. Hover a cell to read the full value.</p>`;
}

function renderShared(shared) {
  if (items.length < 2) return;
  if (!shared.length) {
    $("shared-content").innerHTML =
      '<p class="compare-empty">Nothing in common: no shared sender, address, link, IP or file across these messages.</p>';
    return;
  }

  const strongest = shared.filter((s) => ["hash", "ip", "url", "urlDomain", "from", "replyTo"].includes(s.type));
  const lead = strongest.length
    ? `<p class="compare-lead">${strongest.length} strong link${strongest.length === 1 ? "" : "s"} between these messages — the same infrastructure or payload, not just similar wording.</p>`
    : '<p class="compare-lead">Only weak similarities: wording and headers, no shared infrastructure.</p>';

  $("shared-content").innerHTML = `${lead}<div class="table-scroll"><table class="shared-table">
      <thead><tr><th>Indicator</th><th>Type</th><th>Seen in</th></tr></thead>
      <tbody>${shared
        .map(
          (s) => `<tr>
            <td class="mono shared-value">${esc(s.defanged)}</td>
            <td>${esc(s.label)}</td>
            <td><span class="shared-count">${s.messages.length}</span> ${s.messages
              .map((i) => `<span class="msg-chip" title="${esc(items[i].name)}">${i + 1}</span>`)
              .join("")}</td>
          </tr>`,
        )
        .join("")}</tbody></table></div>
    <p class="compare-note">Indicators are defanged. The numbers match the column numbers in the table below.</p>`;
}

// ===== downloads =====

function download(name, type, content) {
  const url = URL.createObjectURL(new Blob([content], { type }));
  const a = document.createElement("a");
  a.href = url;
  a.download = name;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

function exportComparison(format) {
  if (!items.length) return;
  const date = new Date().toISOString().slice(0, 10);
  if (format === "csv") {
    download(`phishing-comparison_${date}.csv`, "text/csv;charset=utf-8", comparisonCsv(items));
  } else {
    download(`phishing-comparison_${date}.json`, "application/json;charset=utf-8", comparisonJson(items));
  }
  status(`Downloaded the comparison as ${format.toUpperCase()}.`, "success");
}

// ===== wiring =====

const ACTIONS = {
  "add-sample": () => addSamples(),
  "clear-all": () => {
    items.length = 0;
    render();
    status("Cleared.");
  },
  remove: (btn) => {
    items.splice(Number(btn.dataset.index), 1);
    render();
  },
  "export-csv": () => exportComparison("csv"),
  "export-json": () => exportComparison("json"),
};

document.addEventListener("click", (e) => {
  const btn = e.target.closest?.("[data-act]");
  if (!btn) return;
  const run = ACTIONS[btn.dataset.act];
  if (!run) return;
  e.preventDefault();
  run(btn);
});

$("hide-identical").addEventListener("change", render);

const dropzone = $("dropzone");
const fileInput = $("compare-files");

dropzone.addEventListener("click", () => fileInput.click());
dropzone.addEventListener("keydown", (e) => {
  if (e.key === "Enter" || e.key === " ") {
    e.preventDefault();
    fileInput.click();
  }
});
fileInput.addEventListener("change", () => {
  if (fileInput.files.length) addFiles(fileInput.files);
  fileInput.value = "";
});

// Drag and drop anywhere on the page, not only over the box.
for (const type of ["dragenter", "dragover"]) {
  document.addEventListener(type, (e) => {
    e.preventDefault();
    dropzone.classList.add("dragging");
  });
}
for (const type of ["dragleave", "drop"]) {
  document.addEventListener(type, (e) => {
    e.preventDefault();
    if (type === "drop" || e.target === dropzone) dropzone.classList.remove("dragging");
  });
}
document.addEventListener("drop", (e) => {
  const files = e.dataTransfer?.files;
  if (files && files.length) addFiles(files);
});

console.log("%cBOoDe", "color:#9fef00;font:700 14px monospace");
