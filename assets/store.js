/* CleanGEO — block list storage + automatic re-checking */
import {
  DEFAULT_SOURCE, LOCAL_SOURCE, PAGES_SOURCE, COMMIT_API,
  BlockList, diffRules, hash, ruleKeys,
} from './blocklist.js';

const K = {
  source: 'cg.source',
  text: 'cg.list.text',
  savedAt: 'cg.list.savedAt',
  etag: 'cg.list.etag',
  commit: 'cg.list.commit',
  auto: 'cg.auto',
  interval: 'cg.interval',
  log: 'cg.log',
  extra: 'cg.extra',
  settings: 'cg.settings',
  lastCheck: 'cg.lastCheck',
};

export const CHECK_INTERVALS = {
  15: 'ყოველ 15 წუთში',
  60: 'ყოველ საათში',
  360: 'ყოველ 6 საათში',
  1440: 'დღეში ერთხელ',
  0: 'მხოლოდ ხელით',
};

const DEFAULT_SETTINGS = {
  shield: true,        // check every result against the block list
  shieldFirst: true,   // open links filtered by default
  cosmetic: true,      // apply the list's CSS rules
  warn: true,          // warn before opening a blocked host
};

/* ---------- tiny storage helpers ---------- */
export function getSetting(key, fallback) {
  const s = readJSON(K.settings, {});
  return s[key] === undefined ? fallback : s[key];
}
export function setSetting(key, value) {
  const s = readJSON(K.settings, {});
  s[key] = value;
  writeJSON(K.settings, s);
}

function readJSON(k, d) {
  try { const raw = localStorage.getItem(k); return raw ? JSON.parse(raw) : d; } catch (e) { return d; }
}
function writeJSON(k, v) {
  try { localStorage.setItem(k, JSON.stringify(v)); } catch (e) {}
}
const readStr = (k, d = '') => { try { return localStorage.getItem(k) ?? d; } catch (e) { return d; } };
const writeStr = (k, v) => { try { localStorage.setItem(k, v); } catch (e) {} };

/* ---------- settings block ---------- */
export function settings() {
  return { ...DEFAULT_SETTINGS, ...readJSON(K.settings, {}) };
}
export function saveSettings(patch) {
  const next = { ...settings(), ...patch };
  writeJSON(K.settings, next);
  return next;
}

/* ---------- source ---------- */
export function source() {
  return readStr(K.source, DEFAULT_SOURCE) || DEFAULT_SOURCE;
}
export function setSource(url) {
  writeStr(K.source, url.trim());
}

/* ---------- auto refresh config ---------- */
export function autoConfig() {
  return {
    enabled: readStr(K.auto, '1') !== '0',
    interval: Number(readStr(K.interval, '60')) || 0,
  };
}
export function setAuto(patch) {
  if (patch.enabled !== undefined) writeStr(K.auto, patch.enabled ? '1' : '0');
  if (patch.interval !== undefined) writeStr(K.interval, String(patch.interval));
}

/* ---------- the list ---------- */
let cachedList = null;

export function listText() {
  return readStr(K.text, '');
}
export function savedAt() {
  return Number(readStr(K.savedAt, '0')) || 0;
}
export function lastCheck() {
  return Number(readStr(K.lastCheck, '0')) || 0;
}

export function blockList({ force = false } = {}) {
  const extra = readStr(K.extra, '');
  const text = listText();
  const sig = hash(text) + ':' + hash(extra) + ':' + text.length;
  if (!force && cachedList && cachedList.sig === sig) return cachedList.list;
  const list = new BlockList(text, extra);
  cachedList = { sig, list };
  return list;
}

/* locally added lines (user's own rules) */
export function extraRules() { return readStr(K.extra, ''); }
export function setExtraRules(text) {
  writeStr(K.extra, text);
  cachedList = null;
}

export function usernames() { return readJSON(K.log, []); }
export function changelog(n = 8) { return readJSON(K.log, []).slice(0, n); }

function pushLog(entry) {
  const log = readJSON(K.log, []);
  log.unshift(entry);
  writeJSON(K.log, log.slice(0, 30));
}

/* ---------- fetching (several routes, first that works) ---------- */
async function fetchText(url, { timeoutMs = 12000, etag = '', useEtag = false } = {}) {
  const tries = [];
  const isRaw = /raw\.githubusercontent\.com|github\.io/i.test(url);
  tries.push({ url, headers: useEtag && etag ? { 'If-None-Match': etag } : {} });

  const bare = url.replace(/^https?:\/\//, '');
  if (isRaw) {
    // mirror through a couple of CORS-friendly routes if the direct one is offline
    tries.push({ url: PAGES_SOURCE });
    tries.push({ url: 'https://cdn.jsdelivr.net/gh/devunionsup/CleanGEO@main/CleanGEO.txt' });
  }
  if (location.protocol !== 'file:') {
    const local = new URL(LOCAL_SOURCE, location.href).href;
    if (!tries.some(t => t.url === local)) tries.push({ url: local });
  }

  let lastErr = null;
  for (const t of tries) {
    const c = new AbortController();
    const timer = setTimeout(() => c.abort(), timeoutMs);
    try {
      const r = await fetch(t.url, { headers: t.headers, signal: c.signal, cache: 'no-store' });
      clearTimeout(timer);
      if (r.status === 304) return { notModified: true, etag };
      if (!r.ok) throw new Error('HTTP ' + r.status);
      const text = await r.text();
      if (!text || text.length < 20) throw new Error('ცარიელი პასუხი');
      return { text, etag: r.headers.get('etag') || '', url: t.url };
    } catch (e) {
      clearTimeout(timer);
      lastErr = e;
    }
  }
  throw lastErr || new Error('ჩამოტვირთვა ვერ მოხერხდა');
}

async function latestCommit() {
  try {
    const c = new AbortController();
    const timer = setTimeout(() => c.abort(), 8000);
    const r = await fetch(COMMIT_API, { signal: c.signal, headers: { Accept: 'application/vnd.github+json' } });
    clearTimeout(timer);
    if (!r.ok) return '';
    const j = await r.json();
    return j?.[0]?.sha || '';
  } catch (e) {
    return '';
  }
}

/* ---------- installing / updating ---------- */
export function installFromText(text, { url = '', commit = '', etag = '' } = {}) {
  const before = listText();
  writeStr(K.text, text);
  writeStr(K.savedAt, String(Date.now()));
  writeStr(K.etag, etag);
  if (url) writeStr(K.source, url);
  if (commit) writeStr(K.commit, commit);
  cachedList = null;
  const diff = before ? diffRules(before, text) : { added: [], removed: [], total: ruleKeys(text).size };
  return diff;
}

export async function downloadList({ url = source() } = {}) {
  const res = await fetchText(url, { timeoutMs: 15000 });
  if (res.notModified) return { notModified: true };
  const commit = await latestCommit();
  const diff = installFromText(res.text, { url, commit, etag: res.etag });
  writeStr(K.lastCheck, String(Date.now()));
  pushLog({
    at: Date.now(),
    type: 'install',
    message: 'სია ჩამოიტვირთა',
    added: diff.added.length || diff.total,
    removed: diff.removed.length,
    total: diff.total,
  });
  return { ...diff, url, commit, bytes: res.text.length };
}

/**
 * Check the remote list for changes. Downloads only when it actually differs,
 * and when rules disappear the local copy is replaced — deleted rules are gone.
 */
export async function checkForUpdates({ manual = false, url = source() } = {}) {
  writeStr(K.lastCheck, String(Date.now()));
  const current = listText();
  let res;
  try {
    res = await fetchText(url, {
      timeoutMs: manual ? 20000 : 12000,
      etag: readStr(K.etag, ''),
      useEtag: !!current,
    });
  } catch (e) {
    pushLog({ at: Date.now(), type: 'error', message: 'შემოწმება ვერ მოხერხდა: ' + (e.message || e), added: 0, removed: 0 });
    return { ok: false, error: String(e.message || e) };
  }

  if (res.notModified) {
    pushLog({ at: Date.now(), type: 'same', message: 'ცვლილება არ არის (304)', added: 0, removed: 0 });
    return { ok: true, changed: false, added: 0, removed: 0 };
  }

  if (res.etag) writeStr(K.etag, res.etag);
  const commit = await latestCommit();
  const prevCommit = readStr(K.commit, '');
  const isSame = current && current === res.text;

  if (isSame) {
    if (commit && commit !== prevCommit) writeStr(K.commit, commit);
    pushLog({ at: Date.now(), type: 'same', message: 'სია უცვლელია', added: 0, removed: 0 });
    return { ok: true, changed: false, added: 0, removed: 0, total: 0 };
  }

  const diff = current ? diffRules(current, res.text) : { added: [], removed: [], total: ruleKeys(res.text).size };
  installFromText(res.text, { url, commit: commit || prevCommit, etag: res.etag });

  if (!current) {
    pushLog({
      at: Date.now(), type: 'install', message: 'სია დაყენდა პირველად',
      added: diff.total, removed: 0, total: diff.total,
    });
    return { ok: true, changed: true, first: true, added: diff.total, removed: 0, total: diff.total };
  }

  pushLog({
    at: Date.now(),
    type: 'update',
    message: diff.added.length || diff.removed.length ? 'სია განახლდა' : 'სია განახლდა',
    added: diff.added.length,
    removed: diff.removed.length,
    total: diff.total,
    addedSample: diff.added.slice(0, 4),
    removedSample: diff.removed.slice(0, 4),
  });

  return {
    ok: true, changed: true,
    added: diff.added.length, removed: diff.removed.length, total: diff.total,
    addedSample: diff.added.slice(0, 5), removedSample: diff.removed.slice(0, 5),
  };
}

/* ---------- scheduler ---------- */
let timer = null;
let listeners = [];
export function onUpdate(fn) {
  listeners.push(fn);
  return () => { listeners = listeners.filter(f => f !== fn); };
}
function emit(payload) {
  listeners.forEach(f => { try { f(payload); } catch (e) {} });
  try { window.dispatchEvent(new CustomEvent('cg:update', { detail: payload })); } catch (e) {}
}

export function scheduleAuto() {
  clearInterval(timer);
  timer = null;
  const { enabled, interval } = autoConfig();
  if (!enabled || !interval) return;
  timer = setInterval(async () => {
    if (document.hidden) return;
    const r = await checkForUpdates({ manual: false });
    if (r.ok) emit(r);
  }, interval * 60 * 1000);
}

export async function bootstrap() {
  scheduleAuto();
  const { enabled, interval } = autoConfig();
  const since = Date.now() - lastCheck();
  if (enabled && (!listText() || since > interval * 60 * 1000)) {
    const r = await checkForUpdates({ manual: false });
    if (r.ok) emit(r);
    return r;
  }
  return { ok: true, changed: false, skipped: true };
}

/* re-check as soon as the tab becomes visible again */
export function watchVisibility() {
  document.addEventListener('visibilitychange', async () => {
    if (document.hidden) return;
    const { enabled, interval } = autoConfig();
    if (!enabled || !interval) return;
    if (Date.now() - lastCheck() < interval * 60 * 1000) return;
    const r = await checkForUpdates({ manual: false });
    if (r.ok) emit(r);
  });
  window.addEventListener('online', async () => {
    const { enabled } = autoConfig();
    if (!enabled) return;
    const r = await checkForUpdates({ manual: false });
    if (r.ok) emit(r);
  });
}
