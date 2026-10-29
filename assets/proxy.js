/* CleanGEO — safe reader: fetch a third-party page through a text proxy, sanitize
   the HTML and render it with no third-party scripts, frames or beacons.
   Nothing of the original site executes, so its trackers and malware cannot. */

const READER = 'https://r.jina.ai/';

const ttl = 10 * 60 * 1000;
const memory = new Map();

function ctrl(ms) {
  const c = new AbortController();
  const timer = setTimeout(() => c.abort(), ms);
  return { signal: c.signal, done: () => clearTimeout(timer) };
}

const CHALLENGE = /just a moment|attention required|performing security verification|checking your browser|d dos protection|verify you are human|enable javascript and cookies/i;

function looksLikeChallenge(text, title) {
  const head = String(text || '').slice(0, 1200);
  if (CHALLENGE.test(head)) return true;
  if (String(title || '').trim().length < 24 && CHALLENGE.test(title || '')) return true;
  return false;
}

export function sanitize(doc) {
  const kill = ['script', 'noscript', 'style', 'iframe', 'frame', 'frameset', 'object', 'embed', 'applet',
    'form', 'input', 'button', 'select', 'textarea', 'video', 'audio', 'source', 'track',
    'svg', 'canvas', 'link', 'meta', 'base', 'template', 'nav', 'aside', 'footer', 'header',
    '.navbox', '.vertical-navbox', '.navbox-styles', '#catlinks', '.mw-editsection', '.reference',
    '.vector-header', '#p-lang', '.sidebar', '.toc', '#toc', '.mw-jump-link', '.noprint'];
  for (const sel of kill) doc.querySelectorAll(sel).forEach(n => n.remove());

  doc.querySelectorAll('*').forEach(el => {
    for (const attr of [...el.attributes]) {
      const n = attr.name.toLowerCase();
      const v = String(attr.value || '');
      if (n.startsWith('on') || n === 'srcdoc' || n === 'ping') el.removeAttribute(attr.name);
      else if (n === 'style' && /url\s*\(|expression|javascript:/i.test(v)) el.removeAttribute(attr.name);
      else if ((n === 'src' || n === 'srcset' || n === 'poster' || n === 'background' ||
        n === 'action' || n === 'data-src' || n === 'formaction') && !/^(https?:|data:image\/)/i.test(v)) {
        el.removeAttribute(attr.name);
      } else if (n === 'href' && /^javascript:/i.test(v.trim())) el.removeAttribute(attr.name);
    }
  });
  pruneLinkBlocks(doc);
  return doc;
}

/* menus, language switchers and nav boxes are link soup: drop the blocks whose
   text is mostly anchor labels, keeping real prose intact */
function pruneLinkBlocks(doc) {
  const blocks = [...doc.body.querySelectorAll('div,ul,ol,section,table,tbody,tr')].reverse();
  for (const node of blocks) {
    if (!node.isConnected) continue;
    const anchors = node.querySelectorAll('a');
    if (anchors.length < 8) continue;
    const text = (node.textContent || '').trim().length;
    if (!text) continue;
    let linkText = 0;
    for (const a of anchors) linkText += (a.textContent || '').trim().length;
    // only drop pure navigation: dense links and almost no prose between them
    if (linkText / text > 0.75 && text / anchors.length < 30) node.remove();
  }
}

/* pick the part of the page that actually holds the article */
function contentRoot(doc) {
  const candidates = ['article', '.mw-parser-output', '#mw-content-text', 'main', '[role="main"]',
    '#content', '.entry-content', '.post-content', '.article-body', 'body'];
  let best = null;
  let bestScore = 0;
  for (const sel of candidates) {
    const node = doc.querySelector(sel);
    if (!node) continue;
    let score = 0;
    for (const p of node.querySelectorAll('p')) {
      const t = (p.textContent || '').trim();
      if (t.length > 50) score += t.length;
    }
    if (!score) score = (node.textContent || '').trim().length;
    if (score > bestScore) { bestScore = score; best = node; }
  }
  return best || doc.body;
}

export function absolutize(doc, baseUrl) {
  doc.querySelectorAll('a[href]').forEach(a => {
    try { a.setAttribute('href', new URL(a.getAttribute('href'), baseUrl).href); }
    catch (e) { a.removeAttribute('href'); }
    a.setAttribute('rel', 'noopener noreferrer');
  });
  doc.querySelectorAll('img[src]').forEach(img => {
    try { img.setAttribute('src', new URL(img.getAttribute('src'), baseUrl).href); } catch (e) { img.removeAttribute('src'); }
    img.removeAttribute('srcset');
    img.setAttribute('referrerpolicy', 'no-referrer');
    img.setAttribute('loading', 'lazy');
    img.setAttribute('decoding', 'async');
  });
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

/**
 * @returns {Promise<{title,html,text,url,via}>}
 */
export async function fetchReadable(url, { timeoutMs = 18000 } = {}) {
  const hit = memory.get(url);
  if (hit && Date.now() - hit.at < ttl) return hit.value;

  let lastErr = null;

  // 1) HTML through the reader proxy — lets us apply cosmetic filter rules
  try {
    const c = ctrl(16000);
    const r = await fetch(READER + encodeURIComponent(url), {
      headers: { 'x-respond-with': 'html' },
      signal: c.signal,
    });
    c.done();
    if (r.ok) {
      const raw = await r.text();
      if (!/Attention Required! \| Cloudflare|Just a moment\.\.\./i.test(raw.slice(0, 800))) {
        const doc = new DOMParser().parseFromString(raw, 'text/html');
        const title = (doc.title || '').trim() || url;
        sanitize(doc);
        absolutize(doc, url);
        const src = contentRoot(doc);
        let html = src ? src.innerHTML : '';
        const text = src ? (src.textContent || '').replace(/\s+/g, ' ').trim() : '';
        if (text.length > 60 && !looksLikeChallenge(text, title)) {
          const value = { title, html, text, url, via: 'html' };
          memory.set(url, { at: Date.now(), value });
          return value;
        }
        if (looksLikeChallenge(text, title)) lastErr = new Error('საიტი იცავს თავს ბოტებისგან');
      }
    }
  } catch (e) { lastErr = e; console.warn('CleanGEO reader html route:', e && e.message); }

  // 2) Markdown fallback — pure text, even safer
  try {
    const c = ctrl(timeoutMs);
    const r = await fetch(READER + encodeURIComponent(url), { signal: c.signal });
    c.done();
    if (!r.ok) throw new Error('HTTP ' + r.status);
    const md = await r.text();
    const titleM = md.match(/^Title:\s*(.+)$/m);
    const bodyIdx = md.indexOf('Markdown Content:');
    const body = bodyIdx >= 0 ? md.slice(bodyIdx + 'Markdown Content:'.length) : md;
    if (looksLikeChallenge(body, titleM ? titleM[1] : '')) throw new Error('საიტი იცავს თავს ბოტებისგან');
    const value = {
      title: (titleM ? titleM[1].trim() : url),
      html: mdToHtml(body),
      text: body.replace(/\s+/g, ' ').trim(),
      url,
      via: 'md',
    };
    memory.set(url, { at: Date.now(), value });
    return value;
  } catch (e) { lastErr = e; console.warn('CleanGEO reader md route:', e && e.message); }

  throw lastErr || new Error('გვერდი ვერ ჩაიტვირთა');
}
