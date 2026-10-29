/* CleanGEO — app shell */
import { webSearch } from './search.js';
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
          el('a', { class: 'chip', href: 'https://www.google.com/search?q=' + encodeURIComponent(state.query), target: '_blank', rel: 'noopener' }, 'Google-ზე გახსნა'))));
    return;
  }

  const blockedCount = items.filter(r => shieldOn && list.check(r.url, { pageUrl: location.href }).blocked).length;
  const metas = el('div', { class: 'result-meta' },
    el('strong', {}, String(items.length)),
    ' შედეგი',
    ...(enginesLabel().length ? [' · ', el('span', {}, enginesLabel().join(' · '))] : []),
    el('span', { style: 'margin-left:auto' }, '🛡️ ' + (shieldOn ? 'დაცვა ჩართული' : 'დაცვა გამორთული')),
    blockedCount ? el('span', { class: 'badge' }, '⛔ ' + blockedCount) : null);

  const rows = items.map(r => renderResult(r, list, shieldOn));
  out.replaceChildren(metas, el('div', { class: 'result-list' }, ...rows));
}

function enginesLabel() {
  const names = { ddg: 'DuckDuckGo', bing: 'Bing', wiki: 'Wikipedia', direct: 'მისამართი' };
  const ok = state.engineInfo.filter(e => e.ok && e.count).map(e => names[e.id] || e.id);
  return ok;
}

function renderResult(r, list, shieldOn) {
  const host = siteKey(r.url);
  const verdict = shieldOn && list ? list.check(r.url, { pageUrl: location.href }) : { blocked: false };
  const blocked = verdict.blocked;

  const title = el('a', {
    class: 'res-title', href: r.url, rel: 'noopener noreferrer',
    'data-open': r.url,
  }, r.title || r.url);

  const actions = el('div', { class: 'res-actions' },
    el('button', { class: 'mini', type: 'button', 'data-reader': r.url }, '🛡️ დაცული გახსნა'),
    el('button', { class: 'mini', type: 'button', 'data-direct': r.url }, 'პირდაპირ ↗'));

  const body = el('div', {},
    title,
    el('div', { class: 'res-url' }, r.shown || host),
    r.snippet ? el('p', { class: 'res-snippet' }, r.snippet) : null,
    blocked ? el('div', { style: 'margin-top:8px' },
      el('span', { class: 'badge', title: (verdict.rules || []).join('\n') },
        '⛔ AdGuard წესი: ' + ((verdict.rules && verdict.rules[0]) || verdict.reason || 'დაბლოკვა'))) : null,
    actions);

  const row = el('article', { class: 'res' + (blocked ? ' blocked' : '') }, body);

  title.addEventListener('click', (ev) => {
    ev.preventDefault();
    chooseOpen(r);
  });
  actions.querySelector('[data-reader]').addEventListener('click', () => openSmart(r.url));
  actions.querySelector('[data-direct]').addEventListener('click', () => {
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

  if (settings().shieldFirst && readability[host] === false) { openDirect(r.url); return; }

  if (verdict.blocked && settings().warn) {
    const ok = confirm(`⛔ ${host || r.url} ბლოკავს AdGuard წესი:\n${(verdict.rules || []).join('\n') || verdict.reason}\n\nმაინც გავხსნათ?`);
    if (!ok) return;
  }

  if (!settings().shieldFirst) { openDirect(r.url); return; }
  openSmart(r.url);
}

/* ---------- reader ---------- */

/* remember per host whether the protected reader can actually reach the site,
   so a site it cannot read opens in the normal browser instead of a dead end */
const readability = Object.create(null);
function openDirect(url) {
  const w = window.open(url, '_blank', 'noopener');
  // async paths (probe, reader failure) can lose the popup gesture — navigate in place then
  if (!w) location.href = url;
}

/* cosmetic rules from the block list, active only while the reader is open */
function applyReaderCss(rules) {
  let style = document.getElementById('cgReaderCss');
  if (!rules || !rules.length) {
    if (style) style.remove();
    return;
  }
  if (!style) {
    style = document.createElement('style');
    style.id = 'cgReaderCss';
    document.head.appendChild(style);
  }
  style.textContent = rules.join('\n');
}

async function openReader(url) {
  const reader = $('#reader');
  const body = $('#readerBody');
  body.replaceChildren(el('div', { class: 'empty' }, 'იტვირთება…'));
  $('#readerTitle').textContent = siteKey(url);
  $('#readerUrl').textContent = url;
  $('#readerOpen').onclick = () => window.open(url, '_blank', 'noopener');
  reader.hidden = false;
  document.body.style.overflow = 'hidden';

  const list = state.list || blockList();

  try {
    const page = await fetchReadable(url);
    readability[siteKey(url)] = true;
    $('#readerTitle').textContent = page.title;
    const doc = el('div', { class: 'doc' });
    doc.innerHTML = page.html;
    // the list's cosmetic rules apply to the rendered page as a stylesheet
    const css = settings().cosmetic ? list.cosmeticFor(url) : [];
    body.replaceChildren();
    applyReaderCss(css);
    body.appendChild(doc);
    const sel = getSelection();
    if (sel) sel.removeAllRanges();
    doc.querySelectorAll('a[href]').forEach(a => {
      const href = a.getAttribute('href');
      if (!href || !/^https?:/i.test(href)) { a.removeAttribute('href'); return; }
      a.removeAttribute('target');
      a.addEventListener('click', (ev) => {
        ev.preventDefault();
        const v = list.check(href, { pageUrl: url });
        if (v.blocked && settings().warn) {
          if (!confirm(`⛔ ${siteKey(href)} ბლოკავს AdGuard წესი: ${(v.rules || []).join(', ') || v.reason}. გავხსნათ?`)) return;
        }
        if (readability[siteKey(href)] === false) { window.open(href, '_blank', 'noopener'); return; }
        openReader(href);
      });
    });
    body.scrollTop = 0;
    if (!page.text || page.text.length < 120) {
      readability[siteKey(url)] = false;
      closeReader();
      const w = window.open(url, '_blank', 'noopener');
      if (!w) location.href = url;
    }
  } catch (e) {
    const host = siteKey(url);
    readability[host] = false;
    // no error wall and no protection text: continue in a normal browser tab,
    // and fall back to navigating this tab if the popup is blocked
    body.replaceChildren(
      el('div', { class: 'empty' }, 'იხსნება ჩვეულებრივ ბრაუზერში…',
        el('div', { style: 'margin-top:10px' },
          el('button', { class: 'mini', type: 'button', onclick: () => { window.open(url, '_blank', 'noopener'); } }, 'გახსნა ↗'))));
    setTimeout(() => {
      closeReader();
      const w = window.open(url, '_blank', 'noopener');
      if (!w) location.href = url;
    }, 350);
  }
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
    p('შედეგები მოდის DuckDuckGo-დან და Bing-იდან. ყოველი შედეგი მოწმდება თქვენივე ბლოკ-ლისტით — საშიში დომენი მონიშნულია.'),
    el('h3', {}, '2. დაცული გახსნა'),
    p('საიტი იხსნება ტექსტურ რეჟიმში: მისი JavaScript, iframe-ები, ფორმები, ტრეკერ-პიქსელები და რეკლამები არ მუშაობს. სიის CSS წესები რეკლამის ბლოკებს მალავს.'),
    el('h3', {}, '3. ბლოკ-ლისტი'),
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

  for (const [id, key] of [['setShield', 'shield'], ['setShieldFirst', 'shieldFirst'], ['setCosmetic', 'cosmetic'], ['setWarn', 'warn']]) {
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
