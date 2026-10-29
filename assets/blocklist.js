/* CleanGEO — AdGuard/ABP filter-list engine
   Supports: ||host^$options network rules, wildcards, cosmetic ##/$# rules,
   domain scoping, and rule diffing between list versions. */

export const DEFAULT_SOURCE = 'https://raw.githubusercontent.com/devunionsup/CleanGEO/main/CleanGEO.txt';
export const LOCAL_SOURCE = './CleanGEO.txt';
export const PAGES_SOURCE = 'https://devunionsup.github.io/CleanGEO/CleanGEO.txt';
export const COMMIT_API = 'https://api.github.com/repos/devunionsup/CleanGEO/commits?path=CleanGEO.txt&per_page=1';

const SEP = '[^\\w\\d._%-]';

function esc(chark) {
  return chark.replace(/[.+?^${}()|[\]\\]/g, '\\$&');
}

/* ---------- hashing ---------- */
export function hash(text) {
  let h = 0x811c9dc5;
  for (let i = 0; i < text.length; i++) {
    h ^= text.charCodeAt(i);
    h = (h + ((h << 1) + (h << 4) + (h << 7) + (h << 8) + (h << 24))) >>> 0;
  }
  return h.toString(16).padStart(8, '0');
}

/* ---------- network rule -> regex ---------- */
function patternToRegex(pattern) {
  let host = false;
  let p = pattern;
  if (p.startsWith('||')) { host = true; p = p.slice(2); }
  else if (p.startsWith('|')) { p = p.slice(1); }
  let body = '';
  for (const ch of p) {
    if (ch === '*') body += '.*';
    else if (ch === '^') body += SEP;
    else body += esc(ch);
  }
  const src = host ? '^https?://([^/?#]*\\.)?' + body : body;
  return new RegExp(src, 'i');
}

function ruleBody(rule) {
  const i = rule.indexOf('$');
  if (i > 0) return rule.slice(0, i);
  return rule;
}

function extractDomain(pattern) {
  if (!pattern.startsWith('||')) return null;
  let p = pattern.slice(2);
  if (p.includes('/')) return null;
  p = p.replace(/^[*.\s]+/, '').replace(/[*^.\s]+$/, '');
  if (!p || p.includes('*') || p.includes('^')) return null;
  if (!/^[a-z0-9][a-z0-9.-]*\.[a-z]{2,}$/i.test(p)) return null;
  return p.toLowerCase();
}

const COSMETIC_SEPS = ['#$?#', '#$#', '#%#', '#@#', '#?#', '##'];

function splitCosmetic(line) {
  for (const sep of COSMETIC_SEPS) {
    const i = line.indexOf(sep);
    if (i >= 0 && (i > 0 || sep === '##')) {
      const domains = line.slice(0, i);
      if (i > 0 && !domains) continue;
      return { domains, sep, body: line.slice(i + sep.length) };
    }
  }
  return null;
}

function cssFromRuleBody(sep, body) {
  let sel = body.trim();
  if (!sel) return null;
  if (sep === '#%#') return null; // scriptlets are not executed on the modern web build
  if (sep === '#@#') return null;
  if (sep === '#$#' || sep === '#$?#') {
    const m = sel.match(/^(.+?)\s*\{(.*)\}$/s);
    if (!m) return null;
    sel = m[1].trim();
    const decl = m[2].trim();
    if (/remove\s*:\s*true/i.test(decl)) return sel + '{display:none!important}';
    if (/display\s*:\s*none/i.test(decl)) return sel + '{display:none!important}';
    return null;
  }
  // classic ## rule: hide the matching element
  if (sel.endsWith(':remove()')) return sel.slice(0, -':remove()'.length).trim() + '{display:none!important}';
  const styleM = sel.match(/^(.*):style\((.*)\)$/s);
  if (styleM) return styleM[1].trim() + '{' + styleM[2].trim() + '}';
  return sel + '{display:none!important}';
}

/* ---------- parse ---------- */
export function parseList(text) {
  const net = [];           // {raw, pattern, regex, domain}
  const cosmetic = new Map(); // domain -> [css]
  const globalCosmetic = [];
  const domains = new Set();        // hosts the list blocks outright
  const cosmeticDomains = new Set(); // hosts the list only cleans up
  const scriptlets = [];
  const seenNet = new Set();
  const seenCss = new Set();
  const lines = String(text || '').split(/\r?\n/);
  let rules = 0;

  for (let raw of lines) {
    const line = raw.trim();
    if (!line) continue;
    if (line.startsWith('!') || line.startsWith('#')) {
      // '#' at col 0 that is not "##" is a comment in AdGuard lists
      if (!(line.startsWith('##') || line.startsWith('#@#'))) continue;
    }
    if (line.startsWith('[')) continue;

    const cos = splitCosmetic(line);
    if (cos) {
      const css = cssFromRuleBody(cos.sep, cos.body);
      if (!css) {
        if (cos.sep === '#%#') scriptlets.push(line);
        continue;
      }
      if (seenCss.has(css)) continue;
      seenCss.add(css);
      const targets = cos.domains.replace(/^\|\|?/, '').split(',').map(s => s.trim()).filter(Boolean);
      if (!targets.length) { globalCosmetic.push(css); continue; }
      for (const t of targets) {
        if (t.startsWith('~')) continue;
        const key = t.toLowerCase().replace(/^\*\.?/, '');
        if (!key) { globalCosmetic.push(css); continue; }
        if (!cosmetic.has(key)) cosmetic.set(key, []);
        cosmetic.get(key).push(css);
        cosmeticDomains.add(key);
      }
      rules++;
      continue;
    }

    if (line.startsWith('@@')) continue; // exceptions: the public list has none, allowlist handled separately
    if (!/^[|@*a-z0-9]+\b/i.test(line) && !line.startsWith('||')) continue;

    const pattern = ruleBody(line);
    if (!pattern || seenNet.has(pattern)) continue;
    seenNet.add(pattern);
    let regex = null;
    try { regex = patternToRegex(pattern); } catch (e) { regex = null; }
    if (!regex) continue;
    const domain = extractDomain(pattern);
    net.push({ raw: line, pattern, regex, domain });
    if (domain) domains.add(domain);
    rules++;
  }

  return {
    net, cosmetic, globalCosmetic, domains, cosmeticDomains, scriptlets,
    counts: {
      rules,
      network: net.length,
      cosmetic: [...cosmetic.values()].reduce((a, b) => a + b.length, 0) + globalCosmetic.length,
      domains: domains.size,
      scriptlets: scriptlets.length,
    },
  };
}

/* ---------- rule key set for diffing ---------- */
export function ruleKeys(text) {
  const set = new Set();
  for (const raw of String(text || '').split(/\r?\n/)) {
    const line = raw.trim();
    if (!line || line.startsWith('!') || line.startsWith('[')) continue;
    set.add(line);
  }
  return set;
}

export function diffRules(oldText, newText) {
  const a = ruleKeys(oldText);
  const b = ruleKeys(newText);
  const added = [...b].filter(x => !a.has(x));
  const removed = [...a].filter(x => !b.has(x));
  return { added, removed, unchanged: a.size - removed.length, total: b.size };
}

/* ---------- the matcher ---------- */
export class BlockList {
  constructor(text = '', extra = '') {
    this.text = text;
    this.extra = extra;
    this.build();
  }

  build() {
    const parsed = parseList(this.text + '\n' + (this.extra || ''));
    this.net = parsed.net;
    this.cosmetic = parsed.cosmetic;
    this.globalCosmetic = parsed.globalCosmetic;
    this.domains = parsed.domains;
    this.cosmeticDomains = parsed.cosmeticDomains;
    this.scriptlets = parsed.scriptlets;
    this.counts = parsed.counts;
    this.hash = hash(this.text);
    this.regexes = this.net.map(r => r.regex);
  }

  /* Does this exact URL get blocked by a network rule? */
  matchUrl(url) {
    const hits = [];
    const u = String(url || '');
    for (const rule of this.net) {
      if (rule.regex.test(u)) hits.push(rule.raw);
    }
    return { blocked: hits.length > 0, rules: hits };
  }

  /* Is this site itself on the list (host or parent host)? */
  matchHost(url) {
    let host = '';
    try { host = new URL(url).hostname.toLowerCase(); } catch (e) { return { blocked: false, domain: null }; }
    const parts = host.split('.');
    for (let i = 0; i < parts.length - 1; i++) {
      const candidate = parts.slice(i).join('.');
      if (this.domains.has(candidate)) return { blocked: true, domain: candidate };
    }
    return { blocked: false, domain: null };
  }

  /* Combined decision for a navigation target. */
  check(url) {
    const host = this.matchHost(url);
    if (host.blocked) return { blocked: true, reason: 'domain', domain: host.domain, rules: [host.domain] };
    const m = this.matchUrl(url);
    if (m.blocked) return { blocked: true, reason: 'url', domain: null, rules: m.rules };
    return { blocked: false };
  }

  /* CSS for a site we let through, so its ads/trackers stay hidden. */
  cosmeticFor(url, { global = true } = {}) {
    let host = '';
    try { host = new URL(url).hostname.toLowerCase(); } catch (e) { host = ''; }
    const out = global ? [...this.globalCosmetic] : [];
    const parts = host ? host.split('.') : [];
    for (let i = 0; i < parts.length - 1; i++) {
      const candidate = parts.slice(i).join('.');
      const rules = this.cosmetic.get(candidate);
      if (rules) out.push(...rules);
    }
    return [...new Set(out)];
  }

  stats() {
    return this.counts || { rules: 0, network: 0, cosmetic: 0, domains: 0 };
  }
}
