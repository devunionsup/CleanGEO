const BLOCKED_KEY = "blockedByTab";
const DISABLED_KEY = "disabledSites";

async function init() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  const toggle = document.getElementById("toggle");
  const countEl = document.getElementById("count");
  if (!tab || !tab.url) {
    countEl.textContent = "—";
    toggle.disabled = true;
    return;
  }
  const host = new URL(tab.url).hostname;
  const data = await chrome.storage.local.get([BLOCKED_KEY, DISABLED_KEY]);
  const blocked = (data[BLOCKED_KEY] || {})[tab.id];
  countEl.textContent = blocked === undefined ? "0" : String(blocked);
  const disabled = data[DISABLED_KEY] || {};
  toggle.checked = !disabled[host];
  toggle.addEventListener("change", async () => {
    const cur = (await chrome.storage.local.get(DISABLED_KEY))[DISABLED_KEY] || {};
    if (toggle.checked) delete cur[host];
    else cur[host] = true;
    await chrome.storage.local.set({ [DISABLED_KEY]: cur });
  });
}

init();
