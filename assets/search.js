/* CleanGEO — search backends (no API keys, all keyless) */

const JINA = 'https://r.jina.ai/';
const CACHE_PREFIX = 'cg.q.';
const TTL = 5 * 60 * 1000;

export const ENGINES = {
  ddg: { id: 'ddg', label: 'DuckDuckGo' },
  bing: { id: 'bing', label: 'Bing' },
  wiki: { id: 'wiki', label: 'Wikipedia' },
};

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
async function searchDdg(q) {
  const target = 'https://lite.duckduckgo.com/lite/?q=' + encodeURIComponent(q) + '&kl=wt-wt';
  const html = await viaJina(target, { html: true });
  const doc = new DOMParser().parseFromString(html, 'text/html');
  const out = [];
  const links = [...doc.querySelectorAll('a.result-link')];
  for (const a of links) {
    const href = decodeDdgLink(a.getAttribute('href') || '');
    if (!/^https?:\/\//i.test(href)) continue;
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

/* ---------- Bing ---------- */
async function searchBing(q) {
  const target = 'https://www.bing.com/search?q=' + encodeURIComponent(q) + '&setlang=en&cc=GE';
  const html = await viaJina(target, { html: true });
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

/* ---------- Wikipedia (direct CORS) ---------- */
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
export async function webSearch(query, { engines = ['ddg', 'bing'] } = {}) {
  const q = clean(query);
  if (!q) return { query: q, results: [], engines: [], direct: null };

  const cached = cacheGet('w:' + q + ':' + engines.join(','));
  if (cached) return cached;

  const direct = looksLikeUrl(q);
  const tasks = [];
  const order = engines.includes('ddg') ? ['ddg', 'bing'] : ['bing'];

  for (const id of order) {
    const fn = id === 'ddg' ? searchDdg : searchBing;
    tasks.push(
      fn(q).then(rs => ({ id, ok: true, rs })).catch(e => ({ id, ok: false, error: String(e.message || e) }))
    );
  }
  tasks.push(searchWiki(q).then(rs => ({ id: 'wiki', ok: true, rs })).catch(() => ({ id: 'wiki', ok: false, rs: [] })));

  const settled = await Promise.all(tasks);

  let results = [];
  const engineInfo = [];
  for (const s of settled) {
    engineInfo.push({ id: s.id, ok: s.ok, count: s.rs?.length || 0 });
    if (s.rs?.length) {
      // main engines first, wikipedia only supplements
      results = results.concat(s.rs.map(r => ({ ...r, source: s.id })));
    }
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

  const mainFailed = !results.some(r => r.source === 'ddg' || r.source === 'bing');

  // put wikipedia "about" card right after the direct hit
  const value = { query: q, results, engines: engineInfo, direct, mainFailed, at: Date.now() };
  if (results.length) cacheSet('w:' + q + ':' + engines.join(','), value);
  return value;
}
