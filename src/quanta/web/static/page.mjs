/** Plain content pages (privacy): strings and the language switch, nothing else. */
import { loadContent } from "./i18n.mjs";
import { mountChrome } from "./chrome.mjs";

loadContent().then(mountChrome);
