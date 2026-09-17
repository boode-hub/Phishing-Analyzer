// Attachment content inspection
//
// The app hashes attachments but never looked inside them. A file called
// "Invoice.pdf" whose bytes begin with "MZ" is a Windows program with a
// harmless name — the single strongest attachment signal there is, and it costs
// only the first few bytes. Nothing here executes or unpacks anything.

/** Magic-number table: [label, extensions this content legitimately has, bytes]. */
const SIGNATURES = [
  ["Windows executable (PE)", ["exe", "dll", "scr", "sys", "cpl", "ocx", "msi"], [0x4d, 0x5a]],
  ["ELF executable", ["elf", "so", "bin"], [0x7f, 0x45, 0x4c, 0x46]],
  ["Mach-O executable", ["dylib", "bin", "app"], [0xcf, 0xfa, 0xed, 0xfe]],
  ["PDF document", ["pdf"], [0x25, 0x50, 0x44, 0x46]],
  ["ZIP archive or Office/OpenDocument file", ["zip", "docx", "xlsx", "pptx", "odt", "ods", "odp", "jar", "apk", "epub", "vsdx", "xlsm", "docm", "pptm"], [0x50, 0x4b]],
  ["RAR archive", ["rar"], [0x52, 0x61, 0x72, 0x21]],
  ["7-Zip archive", ["7z"], [0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c]],
  ["gzip archive", ["gz", "tgz"], [0x1f, 0x8b]],
  ["Legacy Office document (OLE2)", ["doc", "xls", "ppt", "msg", "vsd"], [0xd0, 0xcf, 0x11, 0xe0]],
  ["RTF document", ["rtf", "doc"], [0x7b, 0x5c, 0x72, 0x74, 0x66]],
  ["PNG image", ["png"], [0x89, 0x50, 0x4e, 0x47]],
  ["JPEG image", ["jpg", "jpeg"], [0xff, 0xd8, 0xff]],
  ["GIF image", ["gif"], [0x47, 0x49, 0x46, 0x38]],
  ["BMP image", ["bmp"], [0x42, 0x4d]],
  ["ICO icon", ["ico"], [0x00, 0x00, 0x01, 0x00]],
  ["Windows shortcut (.lnk)", ["lnk"], [0x4c, 0x00, 0x00, 0x00]],
  ["ISO disk image", ["iso"], null], // checked separately: "CD001" at 0x8001
  ["Class file", ["class"], [0xca, 0xfe, 0xba, 0xbe]],
];

// Content that can run, whatever the file is called.
const EXECUTABLE_LABELS = new Set([
  "Windows executable (PE)",
  "ELF executable",
  "Mach-O executable",
  "Windows shortcut (.lnk)",
  "Class file",
]);

const startsWith = (bytes, sig) =>
  sig.every((b, i) => bytes[i] === b);

export function extensionOf(filename) {
  const m = String(filename || "").match(/\.([A-Za-z0-9]+)$/);
  return m ? m[1].toLowerCase() : "";
}

/**
 * Identify content from its first bytes.
 * @param {Uint8Array} bytes
 * @returns {{label: string, extensions: string[]} | null}
 */
export function sniffFileType(bytes) {
  if (!bytes || bytes.length < 2) return null;
  for (const [label, extensions, sig] of SIGNATURES) {
    if (sig && startsWith(bytes, sig)) return { label, extensions };
  }
  if (bytes.length > 0x8006 && String.fromCharCode(...bytes.slice(0x8001, 0x8006)) === "CD001") {
    return { label: "ISO disk image", extensions: ["iso"] };
  }
  return null;
}

/** Decode the first part of a file as text, for the HTML checks below. */
function asText(bytes, limit = 200000) {
  try {
    return new TextDecoder("utf-8", { fatal: false }).decode(bytes.slice(0, limit));
  } catch {
    return "";
  }
}

/**
 * HTML smuggling: an attached page that carries the payload inside itself as
 * base64 and writes it to disk with a Blob and a download link, so nothing
 * malicious ever crosses the mail gateway as a file.
 */
function smugglingFindings(text) {
  const hits = [];
  if (/new\s+Blob\s*\(|msSaveOrOpenBlob|createObjectURL/i.test(text)) hits.push("builds a file in the browser");
  if (/download\s*=|\.click\s*\(\)/i.test(text)) hits.push("triggers a download automatically");
  if (/base64,[A-Za-z0-9+/=]{500,}|atob\s*\(/i.test(text)) hits.push("carries a large embedded payload");
  return hits;
}

/**
 * Risk flags for one attachment, from its content rather than its name.
 * @param {{value?: string, contentType?: string, bytes?: Uint8Array}} att
 * @returns {Array<{type: "high"|"medium", label: string, message: string}>}
 */
export function inspectAttachment(att) {
  const out = [];
  const bytes = att?.bytes;
  if (!bytes || !bytes.length) return out;

  const ext = extensionOf(att.value);
  const sniffed = sniffFileType(bytes);

  if (sniffed) {
    const matches = !ext || sniffed.extensions.includes(ext);
    if (!matches) {
      const executable = EXECUTABLE_LABELS.has(sniffed.label);
      out.push({
        type: executable ? "high" : "medium",
        label: executable ? "Executable content" : "Type mismatch",
        message: `Named ".${ext}" but the content is ${sniffed.label}.`,
      });
    } else if (EXECUTABLE_LABELS.has(sniffed.label)) {
      out.push({
        type: "high",
        label: "Executable content",
        message: `The content is ${sniffed.label}.`,
      });
    }
  }

  const isHtml =
    /html/i.test(att.contentType || "") || ["htm", "html", "shtml", "svg"].includes(ext);
  if (isHtml) {
    const hits = smugglingFindings(asText(bytes));
    if (hits.length >= 2) {
      out.push({
        type: "high",
        label: "HTML smuggling",
        message: `This attached page ${hits.join(", ")} — the payload travels inside the HTML, past mail filters.`,
      });
    }
    if (/<script/i.test(asText(bytes, 20000))) {
      out.push({
        type: "medium",
        label: "Scripted attachment",
        message: "The attached page contains script.",
      });
    }
  }

  // An archive is not malicious by itself, but it is how executables arrive.
  if (sniffed && /archive/i.test(sniffed.label) && !/Office/i.test(sniffed.label)) {
    out.push({
      type: "medium",
      label: "Archive",
      message: `${sniffed.label} — the contents cannot be checked from here; open it only in an isolated environment.`,
    });
  }

  return out;
}
