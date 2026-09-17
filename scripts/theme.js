// Theme accent colour.
//
// Only the green family is user-selectable. The base palette (backgrounds,
// text, red/yellow/blue/purple) stays fixed so severity colours keep their
// meaning. With no saved choice nothing is set and main.css's defaults apply.

export const DEFAULT_ACCENT = "#9fef00";
const STORAGE_KEY = "accent-color";
const VARS = [
  "--accent", "--green", "--border-hover", "--accent-hover", "--accent-dim",
  "--accent-bg", "--accent-border", "--accent-glow", "--green-bg",
  "--green-border", "--accent-contrast",
];

export function normalizeHex(value) {
  const m = /^#?([0-9a-f]{6})$/i.exec(String(value || "").trim());
  return m ? `#${m[1].toLowerCase()}` : null;
}

/** Every accent token derived from one colour. */
export function accentPalette(hex) {
  const h = normalizeHex(hex);
  if (!h) return null;
  const [r, g, b] = [1, 3, 5].map((i) => parseInt(h.slice(i, i + 2), 16));
  const mix = (t, k) => [r, g, b].map((c) => Math.round(c + (t - c) * k));
  const toHex = (rgb) => "#" + rgb.map((c) => c.toString(16).padStart(2, "0")).join("");
  const rgba = (a) => `rgba(${r}, ${g}, ${b}, ${a})`;
  // Relative luminance decides whether button text on the accent is dark or light.
  const lin = (c) => ((c /= 255) <= 0.03928 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4);
  const lum = 0.2126 * lin(r) + 0.7152 * lin(g) + 0.0722 * lin(b);
  return {
    "--accent": h,
    "--green": h,
    "--border-hover": h,
    "--accent-hover": toHex(mix(255, 0.2)),
    "--accent-dim": toHex(mix(0, 0.33)),
    "--accent-bg": rgba(0.08),
    "--accent-border": rgba(0.25),
    "--accent-glow": rgba(0.15),
    "--green-bg": rgba(0.08),
    "--green-border": rgba(0.25),
    "--accent-contrast": lum > 0.35 ? "#0d1117" : "#ffffff",
  };
}

/** Apply a colour, or restore the stylesheet defaults when given the default/invalid. */
export function applyAccent(hex, root = document.documentElement) {
  const h = normalizeHex(hex);
  for (const v of VARS) root.style.removeProperty(v);
  if (!h || h === DEFAULT_ACCENT) return DEFAULT_ACCENT;
  for (const [k, v] of Object.entries(accentPalette(h))) root.style.setProperty(k, v);
  return h;
}

export function loadAccent() {
  try {
    return normalizeHex(localStorage.getItem(STORAGE_KEY)) || DEFAULT_ACCENT;
  } catch {
    return DEFAULT_ACCENT;
  }
}

export function saveAccent(hex) {
  try {
    const h = normalizeHex(hex);
    if (!h || h === DEFAULT_ACCENT) localStorage.removeItem(STORAGE_KEY);
    else localStorage.setItem(STORAGE_KEY, h);
  } catch {
    // Storage blocked: the colour still applies for this visit.
  }
}
