/* CleanGEO — app shell */
import { webSearch } from './search.js';
import { adguardLookup, ADGUARD_DOH } from './dns.js';
import { fetchReadable } from './proxy.js';
import {
  blockList, bootstrap, checkForUpdates, downloadList, changelog, source,
  autoConfig, setAuto, settings, saveSettings, savedAt, lastCheck, extraRules, setExtraRules, sanitizeExtra,
  onUpdate, scheduleAuto, watchVisibility,
} from './store.js';

const $ = (sel) => document.querySelector(sel);
const el = (tag, attrs = {}, ...kids) => {
  const n = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (v === true) n.setAttribute(k, '');
    else if (v !== false && v != null) n.setAttribute(k, v);
  }
  for (const k of kids.flat()) if (k != null) n.appendChild(typeof k === 'string' ? document.createTextNode(k) : k);
  return n;
};

const state = { query: '', results: [], engineInfo: [], busy: false, list: null };

/* ---------- toast ---------- */
let toastTimer = null;
function toast(msg, ms = 2600) {
  const t = $('#toast');
  t.textContent = msg;
  t.classList.add('on');
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => t.classList.remove('on'), ms);
}

/* ---------- list status ---------- */
function refreshStatus() {
  const list = blockList();
  state.list = list;
  const s = list.stats();
  const dot = $('#shieldDot');
  const txt = $('#shieldText');
  const on = settings().shield;
  dot.className = 'dot ' + (!on ? '' : s.rules ? 'ok' : 'err');
  txt.textContent = !on ? 'ფილტრი გამორთული' : s.rules ? `დაცვა ჩართული` : 'სია ცარიელია';
  txt.title = `${s.rules} AdGuard წესი · ${s.domains} დომენი · ${s.exceptions || 0} @@`;
  $('#listLink').href = source();
  renderStats();
  renderLog();
}

function renderStats() {
  const list = state.list || blockList();
  const s = list.stats();
  const nodes = [
    [s.rules, 'AdGuard წესი'],
    [s.domains, 'დომენი'],
    [s.exceptions || 0, 'გამონაკლისი'],
    [savedAt() ? new Date(savedAt()).toLocaleDateString('ka-GE', { day: '2-digit', month: 'short' }) : '—', 'განახლდა'],
  ];
  $('#stats').replaceChildren(...nodes.map(([v, l]) =>
    el('div', { class: 'stat' }, el('b', {}, String(v)), el('span', {}, l))));
  $('#lastCheckText').textContent = lastCheck()
    ? 'ბოლო შემოწმება: ' + new Date(lastCheck()).toLocaleString('ka-GE', { day: '2-digit', month: '2-digit', hour: '2-digit', minute: '2-digit' })
    : 'ჯერ არ შემოწმებულა';
  $('#sourceText').textContent = source().replace(/^https?:\/\//, '');
}

function renderLog() {
  const items = changelog(6);
  const box = $('#logList');
  if (!items.length) {
    box.replaceChildren(el('li', {}, 'ცვლილებები ჯერ არ არის.'));
    return;
  }
  box.replaceChildren(...items.map(e => {
    const d = new Date(e.at);
    const when = d.toLocaleString('ka-GE', { day: '2-digit', month: '2-digit', hour: '2-digit', minute: '2-digit' });
    const parts = [];
    if (e.added) parts.push(el('span', { class: 'plus' }, ` +${e.added}`));
    if (e.removed) parts.push(el('span', { class: 'minus' }, ` −${e.removed}`));
    return el('li', {},
      el('b', {}, e.message || 'განახლება'),
      parts,
      el('div', {}, when + (e.total ? ` · სულ ${e.total}` : '')));
  }));
}

/* ---------- search ---------- */
function readQuery() {
  const sp = new URLSearchParams(location.search);
  if (sp.get('q')) return sp.get('q');
  const h = new URLSearchParams(location.hash.slice(1));
  return h.get('q') || '';
}

function setQueryUrl(q) {
  const base = location.pathname;
  const next = q ? base + '?' + new URLSearchParams({ q }).toString() : base;
  history.replaceState(null, '', next);
}

async function runSearch(q, { push = true } = {}) {
  q = (q || '').trim();
  if (!q) return;
  state.query = q;
  state.busy = true;
  document.body.classList.remove('home');
  document.title = q + ' — CleanGEO';
  setQueryUrl(q);
  $('#q').value = q;

  const out = $('#output');
  out.replaceChildren(
    el('div', { class: 'result-meta' }, el('strong', {}, 'მიმდინარეობს ძებნა…')),
    el('div', { class: 'skel' }), el('div', { class: 'skel' }), el('div', { class: 'skel' }));
  $('#homeNote').hidden = true;

  let data;
  try {
    data = await webSearch(q);
  } catch (e) {
    out.replaceChildren(el('div', { class: 'empty' }, 'ძებნა ვერ შესრულდა — შეამოწმეთ კავშირი.'));
    state.busy = false;
    return;
  }
  state.results = data.results;
  state.engineInfo = data.engines;
  state.busy = false;
  renderResults();
  if (settings().shield) resolveDns(state.results);
}

/* Every result host is resolved by AdGuard DNS — the only resolver the app
   talks to. AdGuard answers a domain on its list with 0.0.0.0 (or ::), so the
   answer is the verdict even when CleanGEO's own list has no rule for it. */
async function resolveDns(items) {
  if (!items.length) return;
  const hosts = [...new Set(items.map(r => siteKey(r.url)).filter(Boolean))];
  const done = await Promise.all(hosts.map(async h => [h, await adguardLookup(h)]));
  const byHost = new Map(done);
  let changed = false;
  for (const r of items) {
    const dns = byHost.get(siteKey(r.url));
    if (dns) { r.dns = dns; changed = true; }
  }
  if (changed && items === state.results) renderResults();
}

function siteKey(url) {
  try { return new URL(url).hostname.replace(/^www\./, ''); } catch (e) { return ''; }
}

function renderResults() {
  const out = $('#output');
  const list = state.list || blockList();
  const shieldOn = settings().shield;
  const items = state.results;

  if (!items.length) {
    out.replaceChildren(
      el('div', { class: 'empty' },
        'შედეგი ვერ მოიძებნა.',
        el('div', { class: 'chips' },
          el('a', { class: 'chip', href: 'https://duckduckgo.com/?q=' + encodeURIComponent(state.query) + '&kp=-2&kpsb=-1', target: '_blank', rel: 'noopener' }, 'DuckDuckGo-ზე გახსნა'),
          el('a', { class: 'chip', href: 'https://www.google.com/search?q=' + encodeURIComponent(state.query) + '&safe=off&num=20', target: '_blank', rel: 'noopener' }, 'Google-ზე გახსნა'))));
    return;
  }

  const blockedCount = items.filter(r => shieldOn && (list.check(r.url, { pageUrl: location.href }).blocked || (r.dns && r.dns.blocked))).length;
  const metas = el('div', { class: 'result-meta' },
    el('strong', {}, String(items.length)),
    ' შედეგი',
    el('span', { style: 'margin-left:auto' }, '🛡️ ' + (shieldOn ? 'დაცვა ჩართული' : 'დაცვა გამორთული')),
    blockedCount ? el('span', { class: 'badge' }, '⛔ ' + blockedCount) : null);

  const rows = items.map(r => renderResult(r, list, shieldOn));
  out.replaceChildren(metas, el('div', { class: 'result-list' }, ...rows));
}

/* site icon: the site's real favicon, with the host's first letter as a fallback
   while it loads or when the icon service has nothing for that domain */
function favicon(host) {
  const tile = el('span', { class: 'fav', 'aria-hidden': 'true' },
    el('span', { class: 'fav-letter' }, (host[0] || '?').toUpperCase()));
  if (!host) return tile;
  const enc = encodeURIComponent(host);
  // first the site's own icon via DuckDuckGo, then Google's cache for domains it misses
  let step = 0;
  const srcs = [
    'https://icons.duckduckgo.com/ip3/' + enc + '.ico',
    'https://www.google.com/s2/favicons?sz=64&domain=' + enc,
  ];
  const img = el('img', {
    src: srcs[0], alt: '', width: 16, height: 16, decoding: 'async', referrerpolicy: 'no-referrer',
  });
  img.addEventListener('load', () => {
    if (img.naturalWidth > 1) tile.classList.add('has');
    else next();
  });
  img.addEventListener('error', next);
  const timer = setTimeout(() => { if (!tile.classList.contains('has')) next(); }, 4000);
  function next() {
    step += 1;
    if (step >= srcs.length) { clearTimeout(timer); img.remove(); return; }
    tile.classList.remove('has');
    img.src = srcs[step];
  }
  tile.appendChild(img);
  return tile;
}

function renderResult(r, list, shieldOn) {
  const host = siteKey(r.url);
  const verdict = shieldOn && list ? list.check(r.url, { pageUrl: location.href }) : { blocked: false };
  const dns = shieldOn && r.dns && r.dns.blocked ? r.dns : null;
  const blocked = verdict.blocked || !!dns;

  const title = el('a', {
    class: 'res-title', href: r.url, rel: 'noopener noreferrer',
    'data-open': r.url,
  }, r.title || r.url);

  const canBypass = !settings().strict;
  const actions = el('div', { class: 'res-actions' });
  actions.append(el('button', { class: 'mini', type: 'button', 'data-reader': r.url }, '🛡️ დაცული გახსნა'));
  if (canBypass) actions.append(el('button', { class: 'mini', type: 'button', 'data-direct': r.url }, 'პირდაპირ ↗'));

  const body = el('div', {},
    title,
    el('div', { class: 'res-url' }, favicon(host), el('span', { class: 'res-host' }, r.shown || host)),
    r.snippet ? el('p', { class: 'res-snippet' }, r.snippet) : null,
    blocked ? el('div', { style: 'margin-top:8px' },
      el('span', { class: 'badge', title: verdict.blocked ? (verdict.rules || []).join('\n') : 'AdGuard DNS: ' + ((dns && dns.ips) || []).join(', ') + '\n' + ADGUARD_DOH },
        verdict.blocked
          ? '⛔ AdGuard წესი: ' + ((verdict.rules && verdict.rules[0]) || verdict.reason || 'დაბლოკვა')
          : '⛔ AdGuard DNS: დაბლოკილი დომენი')) : null,
    actions);

  const row = el('article', { class: 'res' + (blocked ? ' blocked' : '') }, body);

  title.addEventListener('click', (ev) => {
    ev.preventDefault();
    chooseOpen(r);
  });
  actions.querySelector('[data-reader]').addEventListener('click', () => openSmart(r.url));
  const directBtn = actions.querySelector('[data-direct]');
  if (directBtn) directBtn.addEventListener('click', () => {
    if (blocked && settings().warn) {
      if (!confirm(`⛔ ${host || r.url} ბლოკავს AdGuard წესი:\n${(verdict.rules || []).join('\n') || verdict.reason}\n\nმაინც გავხსნათ ჩვეულებრივ ბრაუზერში?`)) return;
    }
    openDirect(r.url);
  });
  return row;
}

/* the reader is tried first; if it cannot read the page, the link continues in a
   normal browser tab instead of showing the site's bot-protection text */
function openSmart(url) { openReader(url); }

function chooseOpen(r) {
  const host = siteKey(r.url);
  const verdict = (settings().shield && (state.list || blockList()).check(r.url, { pageUrl: location.href })) || { blocked: false };

  if (settings().shieldFirst && readability[host] === false && !verdict.blocked) { openSmart(r.url); return; }

  if (verdict.blocked) {
    if (settings().strict) {
      openReader(r.url);
      return;
    }
    if (settings().warn) {
      const ok = confirm(`⛔ ${host || r.url} ბლოკავს AdGuard წესი:\n${(verdict.rules || []).join('\n') || verdict.reason}\n\nმაინც გავხსნათ?`);
      if (!ok) return;
    }
    openDirect(r.url, { quiet: true });
    return;
  }

  if (!settings().shieldFirst) { openDirect(r.url); return; }
  openSmart(r.url);
}


/* ---------- reader ---------- */

/* The page keeps its own markup, its classes, its inline styles, its <style>
   blocks, its linked stylesheets and its pictures — and renders inside a
   sandboxed frame, so the design is the site's own. The frame has no
   allow-scripts: no script of the page can run. */
function buildReaderFrame(doc, url, report, list) {
  const head = doc.head || doc.createElement('head');
  if (!doc.head) doc.documentElement.insertBefore(head, doc.documentElement.firstChild);

  // relative URLs (pictures, fonts, CSS @import) resolve against the site
  const base = doc.createElement('base');
  base.setAttribute('href', url);
  head.insertBefore(base, head.firstChild);

  const viewport = doc.createElement('meta');
  viewport.setAttribute('name', 'viewport');
  viewport.setAttribute('content', 'width=device-width, initial-scale=1');
  head.appendChild(viewport);

  const css = [];
  if (settings().shield && settings().cosmetic) css.push(...report.css);
  // the frame must grow with the page, not with the screen: a site's
  // `html,body{height:100%;overflow:hidden}` would clip everything below it
  css.push('html,body{height:auto!important;min-height:1px;overflow:visible!important}');
  css.push('html{overflow-x:hidden!important}');
  css.push('[data-cg-blocked]{display:none!important}');
  const style = doc.createElement('style');
  style.id = 'cg-shield';
  style.textContent = css.join('\n');
  head.appendChild(style);

  const frame = document.createElement('iframe');
  frame.className = 'cg-frame';
  frame.setAttribute('sandbox', 'allow-same-origin');
  frame.setAttribute('referrerpolicy', 'no-referrer');
  frame.setAttribute('loading', 'eager');
  frame.srcdoc = '<!doctype html>' + doc.documentElement.outerHTML;

  frame.addEventListener('load', () => {
    const inner = frame.contentDocument;
    if (!inner) return;
    const fit = () => {
      const h = Math.max(inner.documentElement.scrollHeight, inner.body ? inner.body.scrollHeight : 0, inner.body ? inner.body.offsetHeight : 0);
      if (h > 80) frame.style.height = h + 'px';
    };
    fit();
    // pictures and fonts arrive after the markup: keep the frame as tall as the page
    try { new ResizeObserver(fit).observe(inner.documentElement); } catch (e) { /* older engine */ }
    frame.contentWindow.addEventListener('load', fit);
    setTimeout(fit, 600);
    setTimeout(fit, 1800);
    wireFrameLinks(inner, url, list);
  });
  return frame;
}

/* a link inside the page opens in the reader, never as an unfiltered navigation
   of the frame; a form cannot be submitted at all */
function wireFrameLinks(inner, pageUrl, list) {
  inner.addEventListener('click', (ev) => {
    const a = ev.target && ev.target.closest ? ev.target.closest('a[href]') : null;
    if (!a) return;
    ev.preventDefault();
    let href = a.getAttribute('href') || '';
    try { href = new URL(href, pageUrl).href; } catch (e) { return; }
    if (!/^https?:/i.test(href)) return;
    const verdict = settings().shield ? list.check(href, { pageUrl }) : { blocked: false };
    if (verdict.blocked && !verdict.allowedBy) {
      if (!settings().warn || confirm(`⛔ ${siteKey(href)} ბლოკავს AdGuard წესი: ${(verdict.rules || []).join(', ') || verdict.reason}. გავხსნათ?`)) {
        openDirect(href, { quiet: true });
      }
      return;
    }
    openReader(href);
  }, true);
  inner.addEventListener('submit', (ev) => ev.preventDefault(), true);
}

/* Everything the reader shows goes through the block list here: the page's own
   address, its pictures and styles, every link, and every element whose id or
   class the list hides. Nothing of the live site is opened unfiltered. */
const RESOURCE_ATTRS = ['src', 'srcset', 'poster', 'background', 'data-src'];
const RESOURCE_TYPES = {
  img: 'image', picture: 'image', source: 'image', input: 'image',
  iframe: 'subdocument', frame: 'subdocument', video: 'media', audio: 'media',
  body: 'other', table: 'other', td: 'other',
};

/* the page itself is on the list: say so instead of rendering it */
function blockedPageCard(url, verdict) {
  const viaDns = !(verdict.rules || []).length && /AdGuard DNS/i.test(verdict.reason || '');
  const kids = [
    el('div', { style: 'font-size:28px' }, '⛔'),
    el('div', { style: 'margin-top:8px;font-weight:600' },
      siteKey(url) + (viaDns ? ' დაბლოკილია AdGuard DNS-ით' : ' დაბლოკილია CleanGEO სიით')),
    el('div', { style: 'margin-top:6px;opacity:.8' }, (verdict.rules || []).join('\n') || verdict.reason || ''),
  ];
  if (!settings().strict) {
    kids.push(el('div', { style: 'margin-top:12px' },
      el('button', { class: 'mini', type: 'button', onclick: () => openDirect(url) }, 'მაინც გავხსნა ↗')));
  }
  return el('div', { class: 'empty' }, ...kids);
}

/* hide the elements the list targets and take away every resource it blocks,
   then report what was stopped so the reader can show it */
function filterReaderDom(doc, pageUrl, list) {
  const report = { elements: 0, resources: 0, rules: [], css: [] };
  const pending = report.css;
  const shield = settings().shield;
  const addRule = (r) => { if (r && !report.rules.includes(r)) report.rules.push(r); };
  const abs = (raw) => { try { return new URL(raw, pageUrl).href; } catch (e) { return raw; } };

  if (shield && settings().cosmetic) {
    for (const css of list.cosmeticFor(pageUrl)) {
      const parts = splitCssRule(css);
      let hits = [];
      if (parts) {
        for (const sel of parts.selectors) {
          try { hits.push(...doc.querySelectorAll(sel)); } catch (e) { hits = []; break; }
        }
      }
      if (hits.length) {
        // the fragment is still detached, so isConnected is false for every hit:
        // detach from the parent instead
        const unique = [...new Set(hits)];
        let removed = 0;
        for (const node of unique) {
          if (node.parentNode) { node.parentNode.removeChild(node); removed++; }
        }
        report.elements += removed;
        addRule(css);
      } else {
        // selector the DOM query cannot express (:has, :not chains): keep the
        // rule as CSS, so the element is at least hidden
        pending.push(css);
      }
    }
  }
  report.css = pending;

  if (!shield) return report;
  const nodes = doc.body ? [doc.body, ...doc.body.querySelectorAll('*')] : [...doc.querySelectorAll('*')];
  for (const node of nodes) {
    // the request a page makes for its own pictures is a subresource request,
    // so $image / $subdocument rules apply to it exactly as they would live
    const type = RESOURCE_TYPES[node.tagName.toLowerCase()] || 'other';
    for (const attrName of RESOURCE_ATTRS) {
      const raw = node.getAttribute(attrName);
      if (!raw || !raw.trim()) continue;
      const candidates = attrName === 'srcset'
        ? raw.split(',').map(part => part.trim().split(/\s+/)[0]).filter(Boolean)
        : [raw];
      const blocked = candidates.some(candidate => {
        if (/^(data|javascript|about):/i.test(candidate)) return false;
        const v = list.check(abs(candidate), { pageUrl, type });
        if (v.blocked) { addRule((v.rules || [])[0]); return true; }
        return false;
      });
      if (blocked) { node.removeAttribute(attrName); report.resources++; }
    }
  }
  return report;
}

/* remember per host whether the protected reader can actually reach the site,
   so a site it cannot read opens in the normal browser instead of a dead end */
const readability = Object.create(null);
/* Direct open leaves the list behind: it is the explicit opt-out, never
   something the app does on its own — and in strict mode it does not happen at
   all, the list stays in charge. */
function openDirect(url, { quiet = false } = {}) {
  if (settings().strict) {
    toast('მკაცრი რეჟიმი: მხოლოდ დაცული გახსნა');
    openReader(url);
    return;
  }
  if (!quiet && settings().shield && settings().warn) {
    const ok = confirm(`⚠️ ${siteKey(url) || url}\n\nგვერდი გაიხსნება ფილტრის გარეშე — ბლოკ-სია ვერ იმუშავებს.\nგავხსნათ მაინც?`);
    if (!ok) return;
  }
  const w = window.open(url, '_blank', 'noopener');
  // async paths (probe, reader failure) can lose the popup gesture — navigate in place then
  if (!w) location.href = url;
}

/* split "a, b > c{display:none}" into its selector list and declaration */
function splitCssRule(css) {
  const text = String(css);
  const open = text.lastIndexOf('{');
  if (open < 0) return null;
  const selectors = text.slice(0, open).split(',').map(s => s.trim()).filter(Boolean);
  const body = text.slice(open);
  if (!selectors.length) return null;
  return { selectors, body };
}

/* the same rule, limited to what the reader renders */
function scopeToReader(css) {
  const parts = splitCssRule(css);
  if (!parts) return null;
  return parts.selectors.map(sel => '#readerBody ' + sel).join(', ') + parts.body;
}

/* cosmetic rules that cannot be expressed as a DOM query are applied as CSS,
   scoped to the reader so they can never touch the app's own interface */
function applyReaderCss(rules) {
  let style = document.getElementById('cgReaderCss');
  const scoped = (rules || []).map(scopeToReader).filter(Boolean);
  if (!scoped.length) {
    if (style) style.remove();
    return;
  }
  if (!style) {
    style = document.createElement('style');
    style.id = 'cgReaderCss';
    document.head.appendChild(style);
  }
  style.textContent = scoped.join('\n');
}

/* one reader at a time: a second open (a fast second click) must not render
   over the page that is already loading, nor clear its shield count */
let readerToken = 0;

async function openReader(url) {
  const token = ++readerToken;
  const reader = $('#reader');
  const body = $('#readerBody');
  const badge = $('#readerBlocked');
    body.replaceChildren(el('div', { class: 'empty' }, 'იტვირთება…'));
    body.classList.remove('has-frame');
  if (badge) { badge.hidden = true; badge.textContent = ''; badge.title = ''; }
  $('#readerTitle').textContent = siteKey(url);
  $('#readerUrl').textContent = url;
  // the ↗ button leaves the filtered view: same explicit confirmation as any
  // other unfiltered open
  $('#readerOpen').onclick = () => openDirect(url);
  reader.hidden = false;
  document.body.style.overflow = 'hidden';

  const list = state.list || blockList();
  // the page's own address is checked first: a blocked site never renders
  const pageVerdict = settings().shield ? list.check(url, { pageUrl: url }) : { blocked: false };
  if (pageVerdict.blocked && !pageVerdict.allowedBy) {
    body.replaceChildren(blockedPageCard(url, pageVerdict));
    body.classList.remove('has-frame');
    return;
  }
  // and AdGuard DNS has the last word: a sinkholed domain is blocked even when
  // CleanGEO's own list says nothing about it
  if (settings().shield) {
    const dns = await adguardLookup(siteKey(url));
    if (token !== readerToken) return;
    if (dns.blocked) {
      body.replaceChildren(blockedPageCard(url, { blocked: true, rules: [], reason: 'AdGuard DNS: ' + (dns.ips || []).join(', ') }));
      body.classList.remove('has-frame');
      return;
    }
  }

  try {
    const page = await fetchReadable(url);
    if (token !== readerToken) return;
    readability[siteKey(url)] = true;
    $('#readerTitle').textContent = page.title;

    let report;
    if (page.via === 'html') {
      // the page as the site built it, filtered, inside the sandboxed frame
      const pageDoc = new DOMParser().parseFromString(page.html, 'text/html');
      report = filterReaderDom(pageDoc, url, list);
      applyReaderCss([]);
      body.replaceChildren(buildReaderFrame(pageDoc, url, report, list));
      body.classList.add('has-frame');
    } else {
      const doc = el('div', { class: 'doc' });
      doc.innerHTML = page.html;
      report = filterReaderDom(doc, url, list);
      body.replaceChildren();
      applyReaderCss(report.css);
      body.appendChild(doc);
      attachLinkHandlers(doc, url, list);
      if (!page.text || page.text.length < 120) throw new Error('გვერდის ტექსტი ვერ ამოიკითხა');
    }

    if (badge && settings().shield && (report.elements || report.resources)) {
      badge.hidden = false;
      badge.textContent = `🛡️ −${report.elements + report.resources}`;
      badge.title = `${report.elements} ელემენტი, ${report.resources} რესურსი\n` + report.rules.slice(0, 6).join('\n');
    }
    const sel = getSelection();
    if (sel) sel.removeAllRanges();
    body.scrollTop = 0;
  } catch (e) {
    if (token !== readerToken) return;
    const host = siteKey(url);
    readability[host] = false;
    // never hand the raw site over silently: say the page could not be read
    // in the filtered view and let the choice be explicit
    const kids = [
      el('div', {}, 'გვერდი დაცულ რეჟიმში ვერ ჩაიტვირთა.'),
      el('div', { style: 'margin-top:6px;opacity:.75;font-size:13px' }, 'სკრიპტების გარეშე ეს გვერდი არ იხსნება.'),
      el('div', { style: 'margin-top:10px;display:flex;gap:8px;justify-content:center' },
        el('button', { class: 'mini', type: 'button', onclick: () => openReader(url) }, '🔄 კიდევ ცადე')),
    ];
    if (!settings().strict) {
      kids[kids.length - 1].append(
        el('button', { class: 'mini', type: 'button', onclick: () => openDirect(url) }, 'პირდაპირ ↗'));
    } else {
      kids.push(el('div', { style: 'margin-top:10px;opacity:.7;font-size:12px' },
        'მკაცრი რეჟიმი ჩართულია — ფილტრის გარეშე გახსნა გამორთულია (პარამეტრებში).'));
    }
    body.replaceChildren(el('div', { class: 'empty' }, ...kids));
  }
}

function attachLinkHandlers(doc, pageUrl, list) {
  doc.querySelectorAll('a[href]').forEach(a => {
    const href = a.getAttribute('href');
    if (!href || !/^https?:/i.test(href)) { a.removeAttribute('href'); return; }
    a.removeAttribute('target');
    // a link whose target the list blocks is shown as such, not offered
    const verdict = settings().shield ? list.check(href, { pageUrl }) : { blocked: false };
    if (verdict.blocked && !verdict.allowedBy) {
      a.setAttribute('data-cg-blocked', (verdict.rules || []).join(' ') || verdict.reason || 'blocked');
      a.setAttribute('title', '⛔ ბლოკავს AdGuard წესი: ' + ((verdict.rules || [])[0] || verdict.reason || ''));
      a.classList.add('cg-blocked-link');
    }
    a.addEventListener('click', (ev) => {
      ev.preventDefault();
      if (verdict.blocked) {
        if (settings().warn && !confirm(`⛔ ${siteKey(href)} ბლოკავს AdGuard წესი: ${(verdict.rules || []).join(', ') || verdict.reason}. გავხსნათ?`)) return;
        openDirect(href, { quiet: true });
        return;
      }
      openReader(href);
    });
  });
}

function closeReader() {
  $('#reader').hidden = true;
  document.body.style.overflow = '';
  applyReaderCss([]);
}

/* ---------- drawer ---------- */
function openDrawer() {
  $('#scrim').classList.add('on');
  $('#drawer').classList.add('on');
  $('#drawer').setAttribute('aria-hidden', 'false');
  $('#menuBtn').setAttribute('aria-expanded', 'true');
  renderStats();
  renderLog();
}
function closeDrawer() {
  $('#scrim').classList.remove('on');
  $('#drawer').classList.remove('on');
  $('#drawer').setAttribute('aria-hidden', 'true');
  $('#menuBtn').setAttribute('aria-expanded', 'false');
}

function syncControls() {
  const s = settings();
  $('#setShield').checked = s.shield;
  $('#setShieldFirst').checked = s.shieldFirst;
  $('#setCosmetic').checked = s.cosmetic;
  $('#setWarn').checked = s.warn;
  $('#setStrict').checked = s.strict;
  const a = autoConfig();
  $('#autoToggle').checked = a.enabled;
  $('#intervalSelect').value = String(a.interval);
  $('#intervalSelect').value = String(a.interval);
  $('#extraRules').value = extraRules();
}

async function doCheck(manual = true) {
  const btn = $('#checkNow');
  btn.disabled = true;
  const label = btn.textContent;
  btn.textContent = 'მოწმდება…';
  $('#updateHint').textContent = '';
  const r = await checkForUpdates({ manual });
  btn.disabled = false;
  btn.textContent = label;
  refreshStatus();
  syncControls();
  if (!r.ok) {
    $('#updateHint').textContent = 'შემოწმება ვერ მოხერხდა — ინტერნეტი ან წყარო მიუწვდომელია.';
    return;
  }
  if (r.changed) {
    const bits = [];
    if (r.added) bits.push(`+${r.added} ახალი`);
    if (r.removed) bits.push(`−${r.removed} წაშლილი`);
    $('#updateHint').textContent = `სია განახლდა: ${bits.join(', ') || 'შინაარსი შეიცვალა'} · სულ ${r.total}`;
    toast('ბლოკ-ლისტი განახლდა' + (bits.length ? ': ' + bits.join(', ') : ''));
  } else {
    $('#updateHint').textContent = 'სია უკვე განახლებულია.';
  }
  if (state.results.length) renderResults();
}

function aboutNodes() {
  const p = (t) => el('p', {}, t);
  return [
    p('ჩვეულებრივი საძიებო სისტემა შედეგზე დაჭერისთანავე ატვირთავს საიტის სკრიპტებს, ტრეკერებსა და რეკლამებს. CleanGEO ამას არ აკეთებს.'),
    el('h3', {}, '1. ძებნა'),
    p('ძებნა ერთდროულად რამდენიმე საძიებო სისტემაში მიდის და შედეგები ერთ სიად იკრიბება — სახელებს არ ვაჩვენებთ, მხოლოდ შედეგებს. Safe Search გამორთულია ყველგან. ყოველი შედეგი მოწმდება ბლოკ-ლისტით — საშიში დომენი მონიშნულია.'),
    el('h3', {}, '2. დაცული გახსნა'),
    p('საიტი იხსნება ტექსტურ რეჟიმში: მისი JavaScript, iframe-ები, ფორმები, ტრეკერ-პიქსელები და რეკლამები არ მუშაობს. სიის CSS წესები რეკლამის ბლოკებს მალავს.'),
    el('h3', {}, '3. ბლოკ-ლისტი'),
    p('დომენი მოწმდება ორივეგან: CleanGEO-ს სია და AdGuard DNS (dns.adguard-dns.com) — სხვა DNS არ გამოიყენება. AdGuard DNS დაბლოკილ დომენზე პასუხობს 0.0.0.0-ით, ამიტომ დაცვა მოქმედებს მაშინაც, როცა სიაში ეს დომენი ჯერ არ არის.'),
    p('გადაწყვეტილებას იღებს მხოლოდ AdGuard სინტაქსი — ის წესები, რომლებსაც AdGuard Pro იღებს: ||host^, @@ გამონაკლისი, $important, $document, $domain=, ## / #?# / #$# / #%#. ისეთი ოფციები, რომლებიც გვერდს არ ბლოკავს ($media, $popup, $third-party, $removeparam, $app...), გვერდს არ ხურავს; ბრაუზერისთვის დამახასიათებელი დაბლოკვის სხვა მექანიზმი აქ არ არის.'),
    p('სია იტვირთება GitHub-იდან და ავტომატურად შემოწმდება თქვენ მიერ არჩეული სიხშირით. თუ სიაში წესები დაემატა — დაემატება თქვენთანაც; თუ წაიშალა — წაიშლება თქვენთანაც. ცვლილებები ჩანს პარამეტრებში.'),
    el('h3', {}, '4. მოწყობილობები'),
    p('საიტი ადაპტირებულია ტელეფონზე, პლანშეტსა და კომპიუტერზე. iPhone-ზე „გაზიარება → ეკრანზე დამატება“ გახდის მას აპად.'),
  ];
}

/* ---------- quick chips ---------- */
function renderQuickChips() {
  const box = $('#quickChips');
  const samples = ['ბათუმი', 'ქართული ფილმები', 'ახალი ამბები', 'weather tbilisi'];
  box.replaceChildren(...samples.map(s => el('button', { class: 'chip', type: 'button', onclick: () => runSearch(s) }, s)));
  box.hidden = false;
}

/* ---------- boot ---------- */
function goHome() {
  document.body.classList.add('home');
  document.title = 'CleanGEO — უსაფრთხო საძიებო სისტემა';
  $('#output').replaceChildren();
  $('#homeNote').hidden = false;
  setQueryUrl('');
  state.results = [];
  renderQuickChips();
}

function wire() {
  $('#searchForm').addEventListener('submit', (ev) => {
    ev.preventDefault();
    const q = $('#q').value.trim();
    if (q) runSearch(q);
  });

  $('#menuBtn').addEventListener('click', openDrawer);
  $('#shieldChip').addEventListener('click', openDrawer);
  $('.brand').addEventListener('click', (ev) => { ev.preventDefault(); goHome(); closeReader(); });
  $('#drawerClose').addEventListener('click', closeDrawer);
  $('#scrim').addEventListener('click', closeDrawer);
  $('#readerBack').addEventListener('click', closeReader);
  $('#aboutBtn').addEventListener('click', () => {
    document.body.classList.remove('home');
    setQueryUrl('');
    state.results = [];
    $('#output').replaceChildren(
      el('div', { class: 'notice' }, '🛡️ როგორ მუშაობს CleanGEO'),
      el('div', { class: 'doc', style: 'font-size:15.5px' }, ...aboutNodes()));
    window.scrollTo({ top: 0, behavior: 'smooth' });
  });

  $('#autoToggle').addEventListener('change', (e) => {
    setAuto({ enabled: e.target.checked });
    scheduleAuto();
    toast(e.target.checked ? 'ავტომატური შემოწმება ჩართულია' : 'ავტომატური შემოწმება გამორთულია');
  });
  $('#intervalSelect').addEventListener('change', (e) => {
    setAuto({ interval: Number(e.target.value) });
    scheduleAuto();
  });
  $('#checkNow').addEventListener('click', () => doCheck(true));
  $('#extraRules').addEventListener('change', (e) => {
    const clean = setExtraRules(e.target.value);
    e.target.value = clean.text;
    refreshStatus();
    if (state.results.length) renderResults();
    if (clean.dropped.length) {
      toast('მიიღება მხოლოდ დამატებითი ფილტრები — CleanGEO-ს წესების გაუქმება (@@, $badfilter) დაუშვებელია', 4200);
    } else {
      toast('საკუთარი წესები შენახულია');
    }
  });

  for (const [id, key] of [['setShield', 'shield'], ['setShieldFirst', 'shieldFirst'], ['setCosmetic', 'cosmetic'], ['setWarn', 'warn'], ['setStrict', 'strict']]) {
    $('#' + id).addEventListener('change', (e) => {
      saveSettings({ [key]: e.target.checked });
      refreshStatus();
      if (state.results.length) renderResults();
    });
  }

  window.addEventListener('popstate', () => {
    const q = readQuery();
    if (q && q !== state.query) runSearch(q);
    else if (!q) goHome();
  });

  onUpdate((r) => {
    refreshStatus();
    if (r && r.changed) toast('ბლოკ-ლისტი ავტომატურად განახლდა');
  });

  // keyboard shortcut for the drawer
  window.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') { closeDrawer(); closeReader(); }
    if (e.key === '/' && document.activeElement !== $('#q')) { e.preventDefault(); $('#q').focus(); }
  });
}

async function init() {
  try {
    wire();
    const sel = $('#intervalSelect');
    const opts = [[15, 'ყოველ 15 წუთში'], [60, 'ყოველ საათში'], [360, 'ყოველ 6 საათში'], [1440, 'დღეში ერთხელ'], [0, 'მხოლოდ ხელით']];
    sel.replaceChildren(...opts.map(([v, l]) => el('option', { value: String(v) }, l)));

    refreshStatus();
    syncControls();

    const q = readQuery();
    if (q) { $('#q').value = q; runSearch(q); } else { renderQuickChips(); }

    // first run / stale: pull the list
    const r = await bootstrap();
    refreshStatus();
    syncControls();
    if (r && r.ok && !r.skipped) {
      if (r.changed) toast('ბლოკ-ლისტი მზადაა: ' + (r.total || blockList().stats().rules) + ' წესი');
      if (state.results.length) renderResults();
    } else if (!blockList().stats().rules) {
      // fall back to the copy published next to the site
      try { await downloadList({ url: new URL('CleanGEO.txt', location.href).href }); } catch (e) {}
      refreshStatus();
      if (state.results.length) renderResults();
    }
    watchVisibility();
  } catch (e) {
    console.error('init', e);
    document.body.classList.remove('home');
    $('#output').replaceChildren(el('div', { class: 'notice warn' }, 'საიტი ვერ ჩაიტვირთა სრულად — გადატვირთეთ გვერდი.'));
  }
}

init();
