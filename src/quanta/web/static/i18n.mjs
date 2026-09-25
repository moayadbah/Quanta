/** Every visible string comes from content/site.json (served at /content/site.json).
 *
 * Markup carries keys, never text:
 *   <h1 data-t="hero.title"></h1>
 *   <button data-t-attr="aria-label=menu.open"></button>
 * Code asks for text with t("key", {values}). Placeholders are {name}. A missing key
 * renders as the key itself, so a gap in the content file is visible, not silent.
 */

const listeners = new Set();
const state = { lang: "en", strings: {} };

export function format(template, values = {}) {
  return String(template).replace(/\{(\w+)\}/g, (match, name) =>
    Object.prototype.hasOwnProperty.call(values, name) ? String(values[name]) : match,
  );
}

export function lookup(strings, key, lang) {
  const entry = strings[key];
  if (!entry) return key;
  return entry[lang] || entry.en || key;
}

export function t(key, values) {
  return format(lookup(state.strings, key, state.lang), values);
}

/** The key if it exists, otherwise a fallback key (for open-ended codes from the API). */
export function tk(key, fallback, values) {
  return t(state.strings[key] ? key : fallback, values);
}

export function lang() {
  return state.lang;
}

export function onLanguage(listener) {
  listeners.add(listener);
  return () => listeners.delete(listener);
}

export function numberText(value, digits = 0) {
  // Figures stay in Western digits in both languages: they are data, and they match
  // the artifacts, the report and the CLI byte for byte.
  return Number(value).toLocaleString("en-US", {
    minimumFractionDigits: digits,
    maximumFractionDigits: digits,
  });
}

export function apply(root = document) {
  root.querySelectorAll("[data-t]").forEach((el) => {
    el.textContent = t(el.dataset.t);
  });
  root.querySelectorAll("[data-t-attr]").forEach((el) => {
    for (const pair of el.dataset.tAttr.split(";")) {
      const [attr, key] = pair.split("=").map((s) => s.trim());
      if (attr && key) el.setAttribute(attr, t(key));
    }
  });
}

export function setLanguage(next) {
  state.lang = next === "ar" ? "ar" : "en";
  const html = document.documentElement;
  html.lang = state.lang;
  html.dir = state.lang === "ar" ? "rtl" : "ltr";
  try { localStorage.setItem("quanta-language", state.lang); } catch { /* private mode */ }
  document.title = t(document.body.dataset.titleKey || "site.title");
  apply();
  for (const listener of listeners) listener(state.lang);
}

export async function loadContent(fetcher = fetch) {
  const response = await fetcher("/content/site.json", { credentials: "same-origin" });
  if (!response.ok) throw new Error("content unavailable");
  const payload = await response.json();
  state.strings = payload.strings || {};
  let saved = new URLSearchParams(location.search).get("lang");
  if (!saved) {
    try { saved = localStorage.getItem("quanta-language"); } catch { /* private mode */ }
  }
  const browser = (navigator.language || "").toLowerCase().startsWith("ar") ? "ar" : "en";
  setLanguage(saved || browser);
  return state.strings;
}

/** For tests: load a strings table without the network. */
export function useStrings(strings, language = "en") {
  state.strings = strings;
  state.lang = language;
}
