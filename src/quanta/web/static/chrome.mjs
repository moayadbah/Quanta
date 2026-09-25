/** Shared page chrome: language switch, header state, reveal-on-scroll, mobile menu,
 * and the small builders every page uses. Untrusted data only ever becomes text. */
import { lang, setLanguage } from "./i18n.mjs";

const SVG = "http://www.w3.org/2000/svg";

export function mountChrome() {
  document.documentElement.classList.add("js");
  document.querySelectorAll("[data-action='language']").forEach((button) => {
    button.addEventListener("click", () => setLanguage(lang() === "ar" ? "en" : "ar"));
  });
  const menu = document.getElementById("mobile-menu");
  const open = document.getElementById("menu-open");
  const close = document.getElementById("menu-close");
  if (menu && open && close) {
    open.addEventListener("click", () => menu.showModal());
    close.addEventListener("click", () => menu.close());
    menu.querySelectorAll("a").forEach((a) => a.addEventListener("click", () => menu.close()));
  }
  const header = document.querySelector(".site-header");
  if (header) {
    const update = () => header.classList.toggle("scrolled", window.scrollY > 8);
    update();
    window.addEventListener("scroll", update, { passive: true });
  }
  observeReveals();
}

/** Fade elements marked .reveal in as they enter the viewport, once. */
export function observeReveals(root = document) {
  const nodes = root.querySelectorAll(".reveal:not(.in)");
  if (!("IntersectionObserver" in window)) {
    nodes.forEach((node) => node.classList.add("in"));
    return;
  }
  const observer = new IntersectionObserver(
    (entries) => {
      for (const entry of entries) {
        if (entry.isIntersecting) {
          entry.target.classList.add("in");
          observer.unobserve(entry.target);
        }
      }
    },
    { rootMargin: "0px 0px -8% 0px", threshold: 0.08 },
  );
  nodes.forEach((node) => observer.observe(node));
}

/** Build an element with text content only; untrusted data never becomes markup. */
export function el(tag, attrs = {}, ...children) {
  const node = document.createElement(tag);
  for (const [key, value] of Object.entries(attrs)) {
    if (value === undefined || value === null || value === false) continue;
    if (key === "class") node.className = value;
    else if (key === "text") node.textContent = value;
    else if (key.startsWith("on")) node.addEventListener(key.slice(2), value);
    else node.setAttribute(key, value === true ? "" : String(value));
  }
  for (const child of children.flat()) {
    if (child === undefined || child === null || child === false) continue;
    node.append(child instanceof Node ? child : document.createTextNode(String(child)));
  }
  return node;
}

/** replaceChildren, skipping null/false so optional children never print "null". */
export function fill(node, ...children) {
  node.replaceChildren(...children.flat().filter((c) => c !== null && c !== undefined && c !== false));
  return node;
}

/** A status pill: a coloured dot and a word. kind: ok, info, warn, bad, live, plain. */
export function badge(text, kind = "") {
  return el("span", { class: `badge ${kind}`.trim(), text });
}

/** A monospaced token: an algorithm, a file:line, an identifier. */
export function tag(text) {
  return el("span", { class: "tag", text });
}

/** A horizontal track of segments drawn as SVG geometry.
 * style-src 'self' can drop JS-set styles silently (tests/security/test_web_headers.py),
 * so continuous values travel as SVG attributes. Each segment: {start, width, cls} in
 * percent of the track. Right-to-left pages mirror the track in CSS. */
export function track(segments, { label, height = 6 } = {}) {
  const svg = document.createElementNS(SVG, "svg");
  svg.setAttribute("class", "track");
  svg.setAttribute("viewBox", `0 0 100 ${height}`);
  svg.setAttribute("preserveAspectRatio", "none");
  svg.setAttribute("height", String(height));
  if (label) {
    svg.setAttribute("role", "img");
    svg.setAttribute("aria-label", label);
  } else svg.setAttribute("aria-hidden", "true");
  const base = document.createElementNS(SVG, "rect");
  base.setAttribute("class", "track-base");
  for (const [k, v] of [["x", "0"], ["y", "0"], ["width", "100"], ["height", String(height)], ["rx", "1"]]) base.setAttribute(k, v);
  svg.append(base);
  for (const seg of segments) {
    const rect = document.createElementNS(SVG, "rect");
    rect.setAttribute("class", `seg ${seg.cls || ""}`.trim());
    rect.setAttribute("x", String(Math.max(0, Math.min(100, seg.start))));
    rect.setAttribute("y", "0");
    rect.setAttribute("width", String(Math.max(0.4, Math.min(100, seg.width))));
    rect.setAttribute("height", String(height));
    rect.setAttribute("rx", "1");
    svg.append(rect);
  }
  return svg;
}

const PATHS = {
  arrow: ["M3 9 9 3M4 3h5v5"],
  chevron: ["M4 6l4 4 4-4"],
  check: ["M3.5 8.5l3 3 6-7"],
  cross: ["M4.5 4.5l7 7M11.5 4.5l-7 7"],
  external: ["M6 3H3v10h10v-3", "M9 3h4v4", "M13 3 7 9"],
};

/** A stroked line icon. name: arrow, chevron, check, cross, external. */
export function icon(name, cls = "") {
  const svg = document.createElementNS(SVG, "svg");
  const box = name === "arrow" ? 12 : 16;
  svg.setAttribute("viewBox", `0 0 ${box} ${box}`);
  svg.setAttribute("aria-hidden", "true");
  svg.setAttribute("fill", "none");
  svg.setAttribute("class", cls || (name === "arrow" ? "arrow" : "ico"));
  for (const d of PATHS[name]) {
    const path = document.createElementNS(SVG, "path");
    path.setAttribute("d", d);
    path.setAttribute("stroke", "currentColor");
    path.setAttribute("stroke-width", "1.5");
    path.setAttribute("stroke-linecap", "round");
    path.setAttribute("stroke-linejoin", "round");
    svg.append(path);
  }
  return svg;
}

export function arrow() {
  return icon("arrow");
}
