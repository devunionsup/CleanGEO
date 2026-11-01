// Content script: hides ad containers by CSS selector. The first test build has no selectors yet.
const SELECTORS = [];
if (SELECTORS.length) {
  const style = document.createElement("style");
  style.textContent = SELECTORS.map((s) => `${s} { display: none !important; }`).join("\n");
  (document.head || document.documentElement).appendChild(style);
}
