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

/** The faces each language draws. The page preloads its own language's (assets.py). */
const FACES = {
  en: ['400 1em "Inter"', '500 1em "Inter"', '600 1em "Inter"', '500 1em "Inter Display"', '400 1em "Geist Mono"'],
  ar: ['400 1em "Readex Pro"', '600 1em "Readex Pro"'],
};
const SAMPLE = { en: "Quanta", ar: "كمية" };

function meta(name) {
  return document.querySelector(`meta[name="${name}"]`)?.getAttribute("content") || "";
}

/** Download a language's faces now; resolves when they are ready, or after a short wait. */
export function prepareLanguage(next) {
  if (!document.fonts || !FACES[next]) return Promise.resolve();
  const ready = Promise.all(FACES[next].map((face) => document.fonts.load(face, SAMPLE[next]))).catch(() => {});
  return Promise.race([ready, new Promise((resolve) => setTimeout(resolve, 1500))]);
}

function remember(language) {
  try { localStorage.setItem("quanta-language", language); } catch { /* private mode */ }
  // The server renders the next page in this language from its first byte (assets.py).
  const secure = location.protocol === "https:" ? "; Secure" : "";
  document.cookie = `quanta-language=${language}; Path=/; Max-Age=31536000; SameSite=Lax${secure}`;
}

function commit(next) {
  state.lang = next === "ar" ? "ar" : "en";
  const html = document.documentElement;
  html.lang = state.lang;
  html.dir = state.lang === "ar" ? "rtl" : "ltr";
  remember(state.lang);
  document.title = t(document.body.dataset.titleKey || "site.title");
  apply();
  for (const listener of listeners) listener(state.lang);
}

/** Switch language as one clean change: the faces are ready first, then the page
 *  cross-fades from one language to the other in a single view transition. */
export async function setLanguage(next, { animate = false } = {}) {
  await prepareLanguage(next === "ar" ? "ar" : "en");
  const reduced = window.matchMedia?.("(prefers-reduced-motion: reduce)").matches;
  if (animate && !reduced && document.startViewTransition) {
    await document.startViewTransition(() => commit(next)).finished.catch(() => {});
  } else {
    commit(next);
  }
}

export async function loadContent(fetcher = fetch) {
  // The versioned copy never changes, so the browser keeps it; the page preloads it.
  const build = meta("quanta-build");
  const url = build ? `/_v/${build}/content/site.json` : "/content/site.json";
  const response = await fetcher(url, { credentials: "same-origin" });
  if (!response.ok) throw new Error("content unavailable");
  const payload = await response.json();
  state.strings = payload.strings || {};
  // The server already wrote the page in its language: keep it, so nothing re-renders.
  let chosen = new URLSearchParams(location.search).get("lang") || meta("quanta-lang");
  if (!chosen) {
    try { chosen = localStorage.getItem("quanta-language"); } catch { /* private mode */ }
  }
  const browser = (navigator.language || "").toLowerCase().startsWith("ar") ? "ar" : "en";
  commit(chosen || browser);
  // Once the page is idle, fetch the other language's faces so switching is instant.
  const other = state.lang === "ar" ? "en" : "ar";
  const idle = window.requestIdleCallback || ((fn) => setTimeout(fn, 1200));
  const later = () => idle(() => prepareLanguage(other));
  if (document.readyState === "complete") later();
  else window.addEventListener("load", later, { once: true });
  return state.strings;
}

/** For tests: load a strings table without the network. */
export function useStrings(strings, language = "en") {
  state.strings = strings;
  state.lang = language;
}
