/* CleanGEO — search backends (no API keys, all keyless) */

const JINA = 'https://r.jina.ai/';
const CACHE_PREFIX = 'cg.q.';

/* DuckDuckGo settings forced on every request, so they never stay switched on:
     kp=-2    Safe Search off
     kpsb=-1  'Always private' / 'Protected' reminder hidden */
const DDG_OFF = 'kp=-2&kpsb=-1';
const TTL = 5 * 60 * 1000;

/* Every search asks every engine at the same time. Each request carries that
   engine's own "safe search off" switch in the URL, so no filter stays on for
   this query whatever a cookie, an account or a saved profile says:

     DuckDuckGo  kp=-2    (kpsb=-1 also hides its safe-search reminder)
     Bing        adlt=off
     Yahoo       vm=p      (yahoo answers yAdultF=Off; vm=off still means
                            Moderate and vm=r means Strict, so p is the one)
     Mojeek      safe=0

   An engine that is slow, challenged or empty only drops its own results. */

export const ENGINES = {
  ddg: { id: 'ddg', label: 'DuckDuckGo' },
  bing: { id: 'bing', label: 'Bing' },
  yahoo: { id: 'yahoo', label: 'Yahoo' },
  wiki: { id: 'wiki', label: 'Wikipedia' },
};

/* every engine answers every search, in this order */
export const ENGINE_ORDER = ['ddg', 'bing', 'yahoo', 'wiki'];

const BING_OFF = 'adlt=off';
const YAHOO_OFF = 'vm=p';

function timeout(ms) {
  const c = new AbortController();
  const t = setTimeout(() => c.abort(), ms);
  return { signal: c.signal, done: () => clearTimeout(t) };
}

export function isGeorgian(q) {
  return /[\u10A0-\u10FF\u1C90-\u1CBF]/.test(q);
}

export function looksLikeUrl(q) {
  const s = q.trim();
  if (/^https?:\/\/\S+$/i.test(s)) return s;
  if (/^[a-z0-9-]+(\.[a-z0-9-]+)+(\/\S*)?$/i.test(s)) return 'https://' + s;
  return null;
}

function clean(s) {
  return String(s || '').replace(/\s+/g, ' ').trim();
}

function stripTags(s) {
  const d = document.createElement('div');
  d.innerHTML = String(s || '');
  return clean(d.textContent);
}

function decodeBingLink(href) {
  try {
    const u = new URL(href, 'https://www.bing.com');
    const enc = u.searchParams.get('u');
    if (!enc) return href;
    let b64 = enc.startsWith('a1') ? enc.slice(2) : enc;
    b64 = b64.replace(/-/g, '+').replace(/_/g, '/');
    while (b64.length % 4) b64 += '=';
    const bin = atob(b64);
    const bytes = Uint8Array.from(bin, c => c.charCodeAt(0));
    return new TextDecoder().decode(bytes);
  } catch (e) {
    return href;
  }
}

function decodeDdgLink(href) {
  try {
    if (href.includes('uddg=')) {
      const u = new URL(href, 'https://duckduckgo.com');
      const target = u.searchParams.get('uddg');
      if (target) return target;
    }
    if (href.startsWith('//')) return 'https:' + href;
    return href;
  } catch (e) {
    return href;
  }
}

async function viaJina(target, { html = true, ms = 16000 } = {}) {
  const t = timeout(ms);
  try {
    const headers = html ? { 'x-respond-with': 'html' } : {};
    const r = await fetch(JINA + encodeURIComponent(target), { headers, signal: t.signal });
    if (!r.ok) throw new Error('proxy ' + r.status);
    const body = await r.text();
    if (/Attention Required! \| Cloudflare/.test(body) || /Just a moment\.\.\./.test(body)) {
      throw new Error('proxy blocked');
    }
    return body;
  } finally {
    t.done();
  }
}

function cacheGet(key) {
  try {
    const raw = sessionStorage.getItem(CACHE_PREFIX + key);
    if (!raw) return null;
    const o = JSON.parse(raw);
    if (Date.now() - o.t > TTL) return null;
    return o.v;
  } catch (e) { return null; }
}

function cacheSet(key, v) {
  try { sessionStorage.setItem(CACHE_PREFIX + key, JSON.stringify({ t: Date.now(), v })); } catch (e) {}
}

/* ---------- DuckDuckGo (lite) ---------- */
async function ddgPage(q, start) {
  const target = 'https://lite.duckduckgo.com/lite/?q=' + encodeURIComponent(q) + '&kl=wt-wt'
    + (start ? '&s=' + start : '') + '&' + DDG_OFF;
  const html = await viaJina(target, { html: true });
  const doc = new DOMParser().parseFromString(html, 'text/html');
  const out = [];
  const links = [...doc.querySelectorAll('a.result-link')];
  for (const a of links) {
    const href = decodeDdgLink(a.getAttribute('href') || '');
    if (!/^https?:\/\//i.test(href)) continue;
    // DDG's own ad hop and help pages are not results
    if (/^https?:\/\/([a-z0-9-]+\.)*duckduckgo\.com\/y\.js/i.test(href)) continue;
    let snippet = '';
    let shown = '';
    let row = a.closest('tr');
    let guard = 0;
    while (row && guard++ < 6) {
      row = row.nextElementSibling;
      if (!row) break;
      if (row.querySelector('a.result-link')) break;
      const sn = row.querySelector('.result-snippet');
      if (sn && !snippet) snippet = clean(sn.textContent);
      const st = row.querySelector('.link-text');
      if (st && !shown) shown = clean(st.textContent);
    }
    out.push({ title: clean(a.textContent) || href, url: href, snippet, engine: 'ddg', shown });
    if (out.length >= 30) break;
  }
  return out;
}

/* two pages: DDG shows ten hits at a time, and ten hits alone was the whole
   result page when Bing's market hint was getting in its own way */
async function searchDdg(q) {
  const first = await ddgPage(q, 0);
  if (first.length < 10) return first;
  const second = await ddgPage(q, 10).catch(() => []);
  return first.concat(second);
}

/* ---------- Bing ---------- */
/* Pinning the market (cc=GE&setlang=en) makes Bing answer "There are no results"
   to a Georgian query, so the bare URL — where Bing picks the market itself —
   goes first and the market-hinted forms are only a fallback. */
const BING_TARGETS = [
  (q) => 'https://www.bing.com/search?q=' + encodeURIComponent(q) + '&' + BING_OFF,
  (q) => 'https://www.bing.com/search?q=' + encodeURIComponent(q) + '&' + BING_OFF + '&form=QBRE',
  (q) => 'https://www.bing.com/search?q=' + encodeURIComponent(q) + '&setlang=en&cc=GE&' + BING_OFF,
];

function parseBing(html) {
  const doc = new DOMParser().parseFromString(html, 'text/html');
  const out = [];
  for (const li of doc.querySelectorAll('li.b_algo')) {
    const a = li.querySelector('h2 a');
    if (!a) continue;
    let href = a.getAttribute('href') || '';
    href = href.includes('/ck/a') ? decodeBingLink(href) : href;
    if (!/^https?:\/\//i.test(href)) continue;
    const p = li.querySelector('.b_caption p') || li.querySelector('.b_lineclamp1, p');
    out.push({
      title: clean(a.textContent) || href,
      url: href,
      snippet: p ? clean(p.textContent) : '',
      engine: 'bing',
      shown: (() => { try { return new URL(href).hostname.replace(/^www\./, ''); } catch (e) { return ''; } })(),
    });
    if (out.length >= 25) break;
  }
  return out;
}

async function searchBing(q) {
  let lastErr = null;
  for (const target of BING_TARGETS) {
    try {
      const out = parseBing(await viaJina(target(q), { html: true }));
      if (out.length) return out;
    } catch (e) { lastErr = e; }
  }
  if (lastErr) throw lastErr;
  return [];
}

/* ---------- Yahoo (Bing's index, Yahoo's own safe-search switch) ---------- */
function decodeYahooLink(href) {
  try {
    const m = href.match(/\/RU=([^/]+)\/RK=/);
    if (m) return decodeURIComponent(m[1]);
    if (href.startsWith('//')) return 'https:' + href;
    return href;
  } catch (e) {
    return href;
  }
}

function hostOf(href) {
  try { return new URL(href).hostname.replace(/^www\./, ''); } catch (e) { return ''; }
}

async function searchYahoo(q) {
  const target = 'https://search.yahoo.com/search?p=' + encodeURIComponent(q) +
    '&n=20&ei=UTF-8&fr=yfp-t&' + YAHOO_OFF;
  const html = await viaJina(target, { html: true });
  const doc = new DOMParser().parseFromString(html, 'text/html');
  const out = [];
  for (const a of doc.querySelectorAll('div.compTitle a[href*="/RU="]')) {
    const href = decodeYahooLink(a.getAttribute('href') || '');
    if (!/^https?:\/\//i.test(href)) continue;
    const host = hostOf(href);
    if (!host || /(^|\.)yahoo\.com$/i.test(host)) continue;
    const h3 = a.querySelector('h3');
    const block = a.closest('div.dd') || a.closest('li');
    const p = block && (block.querySelector('.compText p') || block.querySelector('p'));
    out.push({
      title: clean(h3 ? h3.textContent : a.textContent) || href,
      url: href,
      snippet: p ? clean(p.textContent) : '',
      engine: 'yahoo',
      shown: host,
    });
    if (out.length >= 20) break;
  }
  return out;
}

/* ---------- Wikipedia (direct CORS, own API — no filtering to switch off) ---------- */
async function searchWiki(q) {
  const lang = isGeorgian(q) ? 'ka' : 'en';
  const url = `https://${lang}.wikipedia.org/w/api.php?action=query&list=search&srsearch=${encodeURIComponent(q)}&srlimit=4&srprop=snippet&format=json&origin=*`;
  const t = timeout(9000);
  try {
    const r = await fetch(url, { signal: t.signal });
    const j = await r.json();
    return (j.query?.search || []).map(s => ({
      title: s.title,
      url: `https://${lang}.wikipedia.org/wiki/${encodeURIComponent(s.title.replace(/ /g, '_'))}`,
      snippet: stripTags(s.snippet),
      engine: 'wiki',
      shown: lang + '.wikipedia.org',
    }));
  } finally { t.done(); }
}

const SEARCHERS = {
  ddg: searchDdg,
  bing: searchBing,
  yahoo: searchYahoo,
  wiki: searchWiki,
};

function dedupe(results) {
  const seen = new Set();
  const out = [];
  for (const r of results) {
    let key;
    try {
      const u = new URL(r.url);
      key = u.hostname.replace(/^www\./, '') + u.pathname.replace(/\/$/, '');
    } catch (e) { key = r.url; }
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(r);
  }
  return out;
}

/* ---------- public API ---------- */
export async function webSearch(query, { engines = ENGINE_ORDER } = {}) {
  const q = clean(query);
  if (!q) return { query: q, results: [], engines: [], direct: null };

  const order = ENGINE_ORDER.filter(id => engines.includes(id));
  const cached = cacheGet('w:' + q + ':' + order.join(','));
  if (cached) return cached;

  const direct = looksLikeUrl(q);

  // every engine at once — a slow or challenged one loses only its own results
  const settled = await Promise.all(order.map(id =>
    (SEARCHERS[id] || searchBing)(q)
      .then(rs => ({ id, ok: true, rs }))
      .catch(e => ({ id, ok: false, rs: [], error: String(e.message || e) }))
  ));

  let results = [];
  const engineInfo = [];
  for (const s of settled) {
    engineInfo.push({ id: s.id, ok: s.ok, count: s.rs?.length || 0 });
  }

  // interleave, so every engine's best hits are near the top instead of one
  // engine's whole list coming first
  const buckets = settled.filter(s => s.rs?.length).map(s => s.rs.map(r => ({ ...r, source: s.id })));
  for (let i = 0; buckets.some(b => i < b.length); i++) {
    for (const b of buckets) if (i < b.length) results.push(b[i]);
  }

  if (direct) {
    results.unshift({
      title: q.replace(/^https?:\/\//, ''),
      url: direct,
      snippet: 'მისამართი — გაიხსნება დაცულ რეჟიმში',
      engine: 'direct',
      source: 'direct',
      shown: (() => { try { return new URL(direct).hostname; } catch (e) { return ''; } })(),
    });
  }

  results = dedupe(results);

  const mainFailed = !results.some(r => r.source && r.source !== 'direct');

  const value = { query: q, results, engines: engineInfo, direct, mainFailed, at: Date.now() };
  if (results.length) cacheSet('w:' + q + ':' + order.join(','), value);
  return value;
}
