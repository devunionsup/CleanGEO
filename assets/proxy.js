/* CleanGEO — safe reader.

   The page is fetched as HTML, stripped of everything that can run or phone
   home, and rendered inside a sandboxed frame with its own markup, its own
   <link rel="stylesheet"> tags and its own pictures. The browser loads the
   stylesheets and images itself, so the site keeps the design it was built
   with; the frame has no allow-scripts, so nothing on the page executes. */

const READER = 'https://r.jina.ai/';
/* Ordered by how faithfully each route hands back the page's own markup. A
   proxy that answers with something else (cache pages, error screens) is
   rejected by matchesHost, so a wrong page is never rendered as the site. */
const PROXIES = [
  (u) => READER + u,
  (u) => 'https://api.allorigins.win/raw?url=' + encodeURIComponent(u),
  (u) => 'https://api.codetabs.com/v1/proxy/?quest=' + encodeURIComponent(u),
];

const ttl = 10 * 60 * 1000;
const memory = new Map();

function ctrl(ms) {
  const c = new AbortController();
  const timer = setTimeout(() => c.abort(), ms);
  return { signal: c.signal, done: () => clearTimeout(timer) };
}

const CHALLENGE = /just a moment|attention required|performing security verification|checking your browser|verify you are human|enable javascript and cookies/i;

export function looksLikeChallenge(text, title) {
  const head = String(text || '').slice(0, 1200);
  if (CHALLENGE.test(head)) return true;
  return String(title || '').trim().length < 24 && CHALLENGE.test(title || '');
}

const DROP = ['script', 'noscript', 'iframe', 'frame', 'frameset', 'object', 'embed', 'applet',
  'template', 'portal', 'video', 'audio', 'source', 'track', 'base',
  'link[rel~="preconnect"]', 'link[rel~="preload"]', 'link[rel~="prefetch"]',
  'link[rel~="dns-prefetch"]', 'link[rel~="manifest"]'];

/* The page keeps its structure, its classes, its inline styles, its inline
   <style> blocks and its <link rel="stylesheet"> files. Only what can execute,
   navigate on its own or auto-load media is removed. */
export function sanitize(doc) {
  for (const sel of DROP) doc.querySelectorAll(sel).forEach(n => n.remove());

  doc.querySelectorAll('meta[http-equiv]').forEach(n => {
    if (/refresh|content-security|cookie/i.test(n.getAttribute('http-equiv') || '')) n.remove();
  });
  // a phone-sized viewport, so a desktop-only layout is not shoved into 428px
  doc.querySelectorAll('meta[name="viewport"], meta[name="referrer"]').forEach(n => n.remove());

  doc.querySelectorAll('*').forEach(node => {
    for (const attr of [...node.attributes]) {
      const name = attr.name.toLowerCase();
      const value = String(attr.value || '');
      if (name.startsWith('on') || name === 'srcdoc' || name === 'ping' ||
        name === 'integrity' || name === 'nonce') node.removeAttribute(attr.name);
      else if (name === 'href' && /^\s*javascript:/i.test(value)) node.removeAttribute(attr.name);
    }
  });

  doc.querySelectorAll('form').forEach(f => {
    f.removeAttribute('action');
    f.setAttribute('onsubmit', 'return false');
  });

  // Many sites ship their real content hidden and reveal it from JavaScript.
  // With the scripts gone that content would never appear, so a large hidden
  // block is shown — a small one (a modal, a cookie banner) stays hidden.
  doc.querySelectorAll('[style*="display"], [hidden]').forEach(node => {
    const hiddenNow = node.hasAttribute('hidden') || /display\s*:\s*none/i.test(node.getAttribute('style') || '');
    if (!hiddenNow) return;
    if ((node.textContent || '').trim().length < 400 && node.querySelectorAll('img').length < 3) return;
    node.removeAttribute('hidden');
    const style = (node.getAttribute('style') || '').replace(/display\s*:\s*none\s*;?/gi, '');
    if (style.trim()) node.setAttribute('style', style); else node.removeAttribute('style');
  });

  // lazy-loading is the site's own script swapping data-src for src; with the
  // script gone the picture must be shown from the attribute it was parked in
  const LAZY = ['data-src', 'data-original', 'data-lazy-src', 'data-lazy', 'data-url', 'data-image'];
  doc.querySelectorAll('img, source').forEach(node => {
    if (!node.getAttribute('src')) {
      for (const attr of LAZY) {
        const value = node.getAttribute(attr);
        if (value && value.trim()) { node.setAttribute('src', value.trim()); break; }
      }
    }
    if (!node.getAttribute('srcset')) {
      const set = node.getAttribute('data-srcset') || node.getAttribute('data-lazy-srcset');
      if (set && set.trim()) node.setAttribute('srcset', set.trim());
    }
  });
  return doc;
}

/* the frame's own head: a base for relative URLs, a phone viewport, and the
   reader's shield stylesheet */
export function prepare(doc, url, { shieldCss = '' } = {}) {
  const head = doc.head || doc.createElement('head');
  if (!doc.head) doc.documentElement.insertBefore(head, doc.documentElement.firstChild);

  const base = doc.createElement('base');
  base.setAttribute('href', url);
  head.insertBefore(base, head.firstChild);

  const viewport = doc.createElement('meta');
  viewport.setAttribute('name', 'viewport');
  viewport.setAttribute('content', 'width=device-width, initial-scale=1');
  head.insertBefore(viewport, head.firstChild);

  const style = doc.createElement('style');
  style.id = 'cg-shield';
  style.textContent = shieldCss + '\nimg[data-cg-blocked],iframe[data-cg-blocked]{display:none!important}';
  head.appendChild(style);
  return doc;
}

/* very small markdown -> html, for the text fallback */
export function mdToHtml(md) {
  const esc = s => s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  const inline = s => esc(s)
    .replace(/!\[([^\]]*)\]\((https?:[^)\s]+)\)/g, '<img alt="$1" src="$2" loading="lazy" referrerpolicy="no-referrer">')
    .replace(/\[([^\]]+)\]\((https?:[^)\s]+)\)/g, '<a href="$2" rel="noopener noreferrer">$1</a>')
    .replace(/`([^`]+)`/g, '<code>$1</code>')
    .replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>');

  const out = [];
  let list = null;
  for (const rawLine of md.split(/\r?\n/)) {
    const line = rawLine.trimEnd();
    const li = line.match(/^\s*([-*+]|\d+\.)\s+(.*)$/);
    if (li) {
      if (!list) { list = li[1].match(/\d/) ? 'ol' : 'ul'; out.push('<' + list + '>'); }
      out.push('<li>' + inline(li[2]) + '</li>');
      continue;
    }
    if (list) { out.push('</' + list + '>'); list = null; }
    if (!line.trim()) continue;
    const h = line.match(/^(#{1,4})\s+(.*)$/);
    if (h) { const lvl = Math.min(h[1].length, 3); out.push(`<h${lvl}>${inline(h[2])}</h${lvl}>`); continue; }
    if (/^>\s?/.test(line)) { out.push('<blockquote>' + inline(line.replace(/^>\s?/, '')) + '</blockquote>'); continue; }
    if (/^(-{3,}|\*{3,})$/.test(line.trim())) { out.push('<hr>'); continue; }
    out.push('<p>' + inline(line) + '</p>');
  }
  if (list) out.push('</' + list + '>');
  return out.join('\n');
}

function textOf(raw) {
  const doc = new DOMParser().parseFromString(raw, 'text/html');
  return {
    doc,
    title: (doc.title || '').trim(),
    text: (doc.body ? doc.body.textContent : '').replace(/\s+/g, ' ').trim(),
  };
}

function markdownPage(md, url) {
  const titleM = md.match(/^Title:\s*(.+)$/m);
  const idx = md.indexOf('Markdown Content:');
  const body = idx >= 0 ? md.slice(idx + 'Markdown Content:'.length) : md;
  return {
    title: (titleM ? titleM[1].trim() : url),
    html: '<!doctype html>' + mdToHtml(body),
    text: body.replace(/\s+/g, ' ').trim(),
    url,
    via: 'md',
  };
}

async function fetchRaw(url, { timeoutMs = 12000 } = {}) {
  const host = (() => { try { return new URL(url).host.replace(/^www\./, ''); } catch (e) { return ''; } })();

  const fromProxy = async (make) => {
    const c = ctrl(timeoutMs);
    try {
      const r = await fetch(make(url), { headers: { 'x-respond-with': 'html' }, signal: c.signal });
      const raw = r.ok ? await r.text() : '';
      if (!raw || !/<html|<body|<!doctype/i.test(raw.slice(0, 600))) throw new Error('HTTP ' + r.status);
      return raw;
    } finally { c.done(); }
  };

  const errors = [];
  for (const make of PROXIES) {
    try {
      const raw = await fromProxy(make);
      // a proxy that answers with a cache page or an error page is not the site
      if (matchesHost(raw, host)) return raw;
      errors.push(new Error('სხვა გვერდი'));
    } catch (e) { errors.push(e); }
  }
  return { error: errors[errors.length - 1] || new Error('პროქსი ვერ პასუხობს') };
}

/* does this HTML really belong to the requested host? Only absolute URLs are
   evidence — a relative one would resolve against whatever was requested and
   always "match". */
function matchesHost(raw, host) {
  if (!host) return true;
  const doc = new DOMParser().parseFromString(raw, 'text/html');
  const claims = [];
  const canonical = doc.querySelector('link[rel="canonical"], meta[property="og:url"]');
  if (canonical) claims.push(canonical.getAttribute('href') || canonical.getAttribute('content') || '');
  const base = doc.querySelector('base[href]');
  if (base) claims.push(base.getAttribute('href') || '');
  doc.querySelectorAll('link[href], img[src], script[src]').forEach((node, i) => {
    if (i < 12) claims.push(node.getAttribute('href') || node.getAttribute('src') || '');
  });

  const absolute = claims.filter(c => /^https?:\/\//i.test(c));
  if (!absolute.length) return true;   // nothing to go on: let the content decide
  for (const claim of absolute) {
    try {
      const claimHost = new URL(claim).host.replace(/^www\./, '');
      if (claimHost === host || claimHost.endsWith('.' + host) || host.endsWith('.' + claimHost)) return true;
    } catch (e) { /* ignore a broken claim */ }
  }
  return false;
}

/**
 * @returns {Promise<{title,html,text,url,via}>}  html is a whole document
 */
export async function fetchReadable(url, { isBlocked = null, shieldCss = '' } = {}) {
  const hit = memory.get(url);
  if (hit && Date.now() - hit.at < ttl) return hit.value;

  let lastErr = null;

  const finish = (raw, via) => {
    const { doc, title, text } = textOf(raw);
    if (looksLikeChallenge(text, title)) throw new Error('საიტი იცავს თავს ბოტებისგან');
    sanitize(doc);
    prepare(doc, url, { shieldCss });
    const value = {
      title: title || url,
      html: '<!doctype html>' + doc.documentElement.outerHTML,
      text,
      url,
      via,
    };
    if (!/<body/i.test(value.html)) throw new Error('ცარიელი გვერდი');
    memory.set(url, { at: Date.now(), value });
    return value;
  };

  // 1) the page's own HTML through a proxy: real markup, real design
  const direct = await fetchRaw(url);
  if (typeof direct === 'string') {
    try { return finish(direct, 'html'); } catch (e) { lastErr = e; }
  } else lastErr = direct.error;

  // 2) the same through the reader proxy, which renders the page first
  try {
    const c = ctrl(16000);
    const r = await fetch(READER + encodeURIComponent(url), {
      headers: { 'x-respond-with': 'html' },
      signal: c.signal,
    });
    const raw = r.ok ? await r.text() : '';
    c.done();
    if (raw) { try { return finish(raw, 'html'); } catch (e) { lastErr = e; } }
  } catch (e) { lastErr = e; }

  // 3) Markdown fallback — text and pictures, no design
  try {
    const c = ctrl(16000);
    const r = await fetch(READER + encodeURIComponent(url), { signal: c.signal });
    const md = r.ok ? await r.text() : '';
    c.done();
    if (!md) throw new Error('HTTP ' + r.status);
    const page = markdownPage(md, url);
    if (looksLikeChallenge(page.text, page.title)) throw new Error('საიტი იცავს თავს ბოტებისგან');
    memory.set(url, { at: Date.now(), value: page });
    return page;
  } catch (e) { lastErr = e; }

  throw lastErr || new Error('გვერდი ვერ ჩაიტვირთა');
}
