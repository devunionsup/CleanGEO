// Service worker: counts blocked requests per tab. Everything stays on the device.
const BLOCKED_KEY = "blockedByTab";

chrome.declarativeNetRequest.onRuleMatchedDebug?.addListener(async (info) => {
  const tabId = info.request.tabId;
  if (tabId < 0) return;
  const data = await chrome.storage.local.get(BLOCKED_KEY);
  const map = data[BLOCKED_KEY] || {};
  map[tabId] = (map[tabId] || 0) + 1;
  await chrome.storage.local.set({ [BLOCKED_KEY]: map });
});

chrome.tabs.onRemoved.addListener(async (tabId) => {
  const data = await chrome.storage.local.get(BLOCKED_KEY);
  const map = data[BLOCKED_KEY] || {};
  delete map[tabId];
  await chrome.storage.local.set({ [BLOCKED_KEY]: map });
});
