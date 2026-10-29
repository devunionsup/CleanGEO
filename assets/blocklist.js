/* CleanGEO — AdGuard filter engine (AdGuard / AdGuard Pro syntax only)

   A navigation is judged the way AdGuard judges the request a click on a link
   makes: a document request whose referrer is another site (the CleanGEO page
   the result was clicked on). Everything that decides the outcome is an AdGuard
   rule and nothing else:

     ||host^              block (a link from another site is a third-party document)
     ||host^$document     block the page explicitly
     ||host^$popup        block: AdGuard for iOS/Pro closes the page for $popup rules
     ||host/x*$all        block matching URLs of every type, page included
     $third-party         applies — the click comes from another site
     $~third-party        does not apply to such a click
     @@||host^            allowlist wins over blocking
     $important           beats a plain @@ exception
     $badfilter           cancels an identical rule
     $domain=a|~b         page scope of the rule
     ## $#  #?#  #$#  #%# cosmetic / scriptlet rules, #@# exceptions

   Options that only mean something for a sub-resource ($media, $script,
   $image, $subdocument…), that merely modify a request ($removeparam, $csp,
   $cookie, $redirect…) or that belong to another AdGuard product ($app…)
   never block a page. */

export const DEFAULT_SOURCE = 'https://raw.githubusercontent.com/devunionsup/CleanGEO/main/CleanGEO.txt';
export const LOCAL_SOURCE = './CleanGEO.txt';
export const PAGES_SOURCE = 'https://devunionsup.github.io/CleanGEO/CleanGEO.txt';
export const COMMIT_API = 'https://api.github.com/repos/devunionsup/CleanGEO/commits?path=CleanGEO.txt&per_page=1';

const SEP = '[^\\w\\d._%-]';
/* In AdGuard a '^' separator also matches the end of the address. */
const SEP_OR_END = '(?:[^\\w\\d._%-]|$)';

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

/* ---------- option vocabulary ---------- */

const TYPES = new Set([
  'document', 'doc', 'subdocument', 'frame', 'script', 'image', 'stylesheet', 'css', 'object',
  'object-subrequest', 'xmlhttprequest', 'xhr', 'media', 'video', 'audio', 'font', 'websocket', 'webrtc',
  'ping', 'other', 'popup', 'all',
]);
const TYPE_ALIAS = {
  doc: 'document', css: 'stylesheet', xhr: 'xmlhttprequest',
  'object-subrequest': 'object', frame: 'subdocument', video: 'media', audio: 'media',
};
const CONTENT_ONLY = new Set([
  'elemhide', 'generichide', 'specifichide', 'jsinject', 'content', 'urlblock', 'extension',
]);
/* modifiers that only act on a sub-resource: never block a page */
const SUBRESOURCE_ONLY = new Set([
  'removeparam', 'queryprune', 'removeheader', 'header', 'referrerpolicy', 'csp', 'redirect',
  'redirect-rule', 'replace', 'cookie', 'stealth', 'empty', 'mp4', 'jsondiff', 'hls',
  'urltransform', 'permissions', 'dnsrewrite', 'method',
]);
/* modifiers tied to another AdGuard product: the rule cannot apply on the web */
const OTHER_PLATFORM = new Set(['app', 'ctag', 'client', 'ext', 'to']);

function parseOptions(text) {
  const opts = {
    types: new Set(),
    allTypes: false,
    thirdParty: null,          // true = only third-party, false = only first-party
    includeDomains: [],
    excludeDomains: [],
    denyallow: [],
    important: false,
    badfilter: false,
    matchCase: false,
    contentOnly: false,
    subresourceOnly: false,
    otherPlatform: false,
    unsupported: [],
  };

  if (!text) return opts;

  for (let raw of text.split(',')) {
    let part = raw.trim();
    if (!part) continue;
    let negated = false;
    while (part.startsWith('~')) { negated = true; part = part.slice(1).trim(); }
    const eq = part.indexOf('=');
    const name = (eq < 0 ? part : part.slice(0, eq)).toLowerCase();
    const value = eq < 0 ? '' : part.slice(eq + 1).trim();

    if (name === 'third-party' || name === '3p') { opts.thirdParty = !negated; continue; }
    if (name === 'first-party' || name === '1p') { opts.thirdParty = negated; continue; }
    if (name === 'important') { opts.important = !negated; continue; }
    if (name === 'badfilter' || name === 'bad-filter') { opts.badfilter = true; continue; }
    if (name === 'match-case' || name === 'matchcase') { opts.matchCase = true; continue; }
    if (name === 'domain') {
      for (const d of value.split('|')) {
        const tok = d.trim().toLowerCase().replace(/^\*\.?/, '');
        if (!tok) continue;
        if (tok.startsWith('~')) opts.excludeDomains.push(tok.slice(1));
        else opts.includeDomains.push(tok);
      }
      continue;
    }
    if (name === 'denyallow') {
      for (const d of value.split('|')) {
        const tok = d.trim().toLowerCase().replace(/^\*\.?/, '');
        if (tok) opts.denyallow.push(tok);
      }
      continue;
    }
    if (TYPES.has(name)) {
      const t = TYPE_ALIAS[name] || name;
      if (t === 'all') { opts.allTypes = true; opts.types.add('document'); }
      if (!negated) opts.types.add(t);
      continue;
    }
    if (CONTENT_ONLY.has(name)) { opts.contentOnly = true; continue; }
    if (SUBRESOURCE_ONLY.has(name)) { opts.subresourceOnly = true; continue; }
    if (OTHER_PLATFORM.has(name)) { opts.otherPlatform = true; continue; }
    // an option this engine does not know does not restrict the rule
  }
  return opts;
}

/* ---------- pattern -> regex ---------- */
function patternToRegex(pattern, matchCase) {
  const flags = matchCase ? '' : 'i';

  if (rawRegex(pattern)) {
    const end = pattern.lastIndexOf('/');
    const body = pattern.slice(1, end);
    const flagsIn = pattern.slice(end + 1).replace(/[gy]/g, '');
    try { return new RegExp(body, flagsIn || flags); } catch (e) { return null; }
  }

  let host = false;
  let start = false;
  let end = false;
  let p = pattern;
  if (p.startsWith('||')) { host = true; p = p.slice(2); }
  else if (p.startsWith('|')) { start = true; p = p.slice(1); }
  if (p.endsWith('|')) { end = true; p = p.slice(0, -1); }

  let body = '';
  for (let i = 0; i < p.length; i++) {
    const ch = p[i];
    if (ch === '*') body += '.*';
    else if (ch === '^') body += SEP_OR_END;
    else body += esc(ch);
  }

  let src = body;
  if (host) src = '^https?://([^/?#]*\\.)?' + body;
  else if (start) src = '^' + body;
  if (end) src += '$';

  try { return new RegExp(src, flags); } catch (e) { return null; }
}

function rawRegex(pattern) {
  return pattern.length > 2 && pattern.startsWith('/') && pattern.lastIndexOf('/') > 0;
}

/* The rule text without its option tail — '||host^$document' -> '||host^'. */
function ruleBody(rule) {
  if (rawRegex(rule)) {
    const end = rule.lastIndexOf('/');
    const tail = rule.indexOf('$', end);
    return tail > 0 ? rule.slice(0, tail) : rule;
  }
  const i = rule.indexOf('$');
  return i > 0 ? rule.slice(0, i) : rule;
}

function ruleOptions(rule) {
  const body = ruleBody(rule);
  if (body.length >= rule.length) return '';
  return rule.slice(body.length).replace(/^\$/, '');
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

/* ---------- cosmetic ---------- */
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
  if (sep === '#%#') return null; // scriptlets: recorded, never executed here
  if (sep === '#$#' || sep === '#$?#') {
    const m = sel.match(/^(.+?)\s*\{(.*)\}$/s);
    if (!m) return null;
    sel = m[1].trim();
    const decl = m[2].trim();
    if (/remove\s*:\s*true/i.test(decl)) return { sel, css: sel + '{display:none!important}' };
    return { sel, css: sel + '{' + decl + '}' };
  }
  if (sel.endsWith(':remove()')) {
    const s = sel.slice(0, -':remove()'.length).trim();
    return { sel: s, css: s + '{display:none!important}' };
  }
  const styleM = sel.match(/^(.*):style\((.*)\)$/s);
  if (styleM) {
    const s = styleM[1].trim();
    return { sel: s, css: s + '{' + styleM[2].trim() + '}' };
  }
  return { sel, css: sel + '{display:none!important}' };
}

/* ---------- parse ---------- */
export function parseList(text) {
  const rules = [];          // {raw, regex, exception, opts, domain}
  const cosmetic = new Map(); // domain -> [css]
  const cosmeticExceptions = new Map();
  const globalCosmetic = [];
  const globalCosmeticExceptions = new Set();
  const domains = new Set();
  const cosmeticDomains = new Set();
  const scriptlets = [];
  const unsupported = [];
  const seenNet = new Set();
  const seenCss = new Set();
  const lines = String(text || '').split(/\r?\n/);
  let count = 0;

  for (let raw of lines) {
    const line = raw.trim();
    if (!line) continue;
    if (line.startsWith('!') || line.startsWith('[')) continue;
    if (line.startsWith('#') && !line.startsWith('##') && !line.startsWith('#@#')) continue;

    const cos = splitCosmetic(line);
    if (cos) {
      const targets = cos.domains.replace(/^\|\|?/, '').split(',').map(s => s.trim()).filter(Boolean);
      const positive = targets.filter(t => !t.startsWith('~'))
        .map(t => t.toLowerCase().replace(/^\*\.?/, '')).filter(Boolean);
      const negative = targets.filter(t => t.startsWith('~'))
        .map(t => t.toLowerCase().slice(1).replace(/^\*\.?/, '')).filter(Boolean);

      if (cos.sep === '#%#') { scriptlets.push(line); count++; continue; }
      const parsedCss = cssFromRuleBody(cos.sep, cos.body);
      if (!parsedCss) continue;
      const { sel, css } = parsedCss;

      if (cos.sep === '#@#') {
        if (!positive.length) { globalCosmeticExceptions.add(sel); count++; continue; }
        for (const t of positive) {
          if (!cosmeticExceptions.has(t)) cosmeticExceptions.set(t, []);
          cosmeticExceptions.get(t).push(sel);
          count++;
        }
        continue;
      }

      /* the same selector may be written for several sites — remember each
         (selector, site) pair, not the selector alone, or the second site loses
         its hiding rule */
      const cssKey = (cos.sep + '|' + positive.join(',') + '|' + sel).toLowerCase();
      if (seenCss.has(cssKey)) continue;
      seenCss.add(cssKey);
      if (!positive.length) { globalCosmetic.push({ css, sel, except: negative }); count++; continue; }
      for (const t of positive) {
        if (!cosmetic.has(t)) cosmetic.set(t, []);
        cosmetic.get(t).push({ css, sel, except: negative });
        cosmeticDomains.add(t);
      }
      count++;
      continue;
    }

    const exception = line.startsWith('@@');
    const rule = exception ? line.slice(2) : line;
    if (!rule) continue;
    if (!/^[|\/@*~a-z0-9]/i.test(rule)) continue;

    const pattern = ruleBody(rule);
    const opts = parseOptions(ruleOptions(rule));
    if (!pattern) continue;

    const key = (exception ? '@@' : '') + pattern + ruleOptions(rule);
    if (seenNet.has(key)) continue;
    seenNet.add(key);

    const regex = patternToRegex(pattern, opts.matchCase);
    if (!regex) { unsupported.push(line); continue; }

    const domain = opts.includeDomains.length || opts.excludeDomains.length ? null : extractDomain(pattern);
    rules.push({ raw: line, regex, exception, opts, domain });
    if (!exception && domain) domains.add(domain);
    count++;
  }

  /* $badfilter cancels every rule with the same pattern and options */
  const cancelled = new Set(
    rules.filter(r => r.opts.badfilter)
      .map(r => r.raw.replace('@@', '').replace(/\$?badfilter(-filter)?/i, '').replace(/,{2,}/g, ',').replace(/,$/, ''))
  );
  const kept = cancelled.size
    ? rules.filter(r => {
      const bare = r.raw.replace('@@', '').replace(/\$?badfilter(-filter)?/i, '').replace(/,{2,}/g, ',').replace(/,$/, '');
      return !cancelled.has(bare);
    })
    : rules;

  const active = kept.filter(r => !r.opts.badfilter);

  return {
    rules: active,
    cosmetic, cosmeticExceptions, globalCosmetic, globalCosmeticExceptions,
    domains, cosmeticDomains, scriptlets, unsupported,
    counts: {
      rules: active.length + cosmeticDomains.size + [...cosmetic.values()].reduce((a, b) => a + b.length, 0),
      network: active.filter(r => !r.exception).length,
      exceptions: active.filter(r => r.exception).length,
      cosmetic: [...cosmetic.values()].reduce((a, b) => a + b.length, 0) + globalCosmetic.length,
      domains: domains.size,
      scriptlets: scriptlets.length,
      unsupported: unsupported.length,
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

/* ---------- domain helpers ---------- */
function hostOf(url) {
  try { return new URL(url).hostname.toLowerCase(); } catch (e) { return ''; }
}

function domainMatches(host, domain) {
  const h = host.replace(/\.$/, '');
  const d = domain.replace(/\.$/, '');
  return h === d || h.endsWith('.' + d);
}

function hostChain(host) {
  const parts = host.split('.');
  const out = [];
  for (let i = 0; i < parts.length - 1; i++) out.push(parts.slice(i).join('.'));
  return out;
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
    this.rules = parsed.rules;
    this.cosmetic = parsed.cosmetic;
    this.cosmeticExceptions = parsed.cosmeticExceptions;
    this.globalCosmetic = parsed.globalCosmetic;
    this.globalCosmeticExceptions = parsed.globalCosmeticExceptions;
    this.domains = parsed.domains;
    this.cosmeticDomains = parsed.cosmeticDomains;
    this.scriptlets = parsed.scriptlets;
    this.unsupported = parsed.unsupported;
    this.counts = parsed.counts;
    this.hash = hash(this.text);
  }

  /* Does an AdGuard rule apply to this request? A page navigation is a
     document request made from another site. */
  applies(rule, ctx) {
    const o = rule.opts;
    if (o.otherPlatform) return false;
    if (o.subresourceOnly && ctx.type === 'document') return false;

    if (ctx.type === 'document') {
      if (o.types.size && !o.types.has('document') && !o.types.has('popup')) return false;
      if (o.denyallow.some(d => domainMatches(ctx.host, d))) return false;
    } else if (o.types.size && !o.allTypes && !o.types.has(ctx.type)) {
      return false;
    }

    if (o.thirdParty === true && !ctx.thirdParty) return false;
    if (o.thirdParty === false && ctx.thirdParty) return false;

    const from = ctx.pageHost || ctx.host;
    if (o.includeDomains.length && !o.includeDomains.some(d => domainMatches(from, d))) return false;
    if (o.excludeDomains.some(d => domainMatches(from, d))) return false;

    return rule.regex.test(ctx.url);
  }

  /* AdGuard priority: $important allow > $important block > @@ > block. */
  evaluate(url, { type = 'document', pageUrl = '' } = {}) {
    const host = hostOf(url);
    const pageHost = pageUrl ? hostOf(pageUrl) : '';
    const ctx = {
      url: String(url || ''),
      host,
      pageHost,
      // the request a link click makes comes from another site; without a page
      // we assume the same, because that is how a result is opened here
      thirdParty: pageHost ? !domainMatches(host, pageHost) : true,
      type,
    };

    let block = null, blockImportant = null, allow = null, allowImportant = null;

    for (const rule of this.rules) {
      if (!this.applies(rule, ctx)) continue;
      if (rule.exception) {
        if (rule.opts.important) { if (!allowImportant) allowImportant = rule; }
        else if (!allow) allow = rule;
      } else if (rule.opts.important) {
        if (!blockImportant) blockImportant = rule;
      } else if (!block) {
        block = rule;
      }
    }

    if (allowImportant) return { blocked: false, allowedBy: allowImportant.raw, reason: 'exception' };
    if (blockImportant) {
      return { blocked: true, reason: ruleReason(blockImportant), rules: [blockImportant.raw], domain: blockImportant.domain };
    }
    if (allow) return { blocked: false, allowedBy: allow.raw, reason: 'exception' };
    if (block) {
      return { blocked: true, reason: ruleReason(block), rules: [block.raw], domain: block.domain };
    }
    return { blocked: false };
  }

  matchUrl(url) {
    const v = this.evaluate(url);
    return { blocked: !!v.blocked && !v.allowedBy, rules: v.rules || [] };
  }

  /* Kept for stats and for the drawer: hosts the list blocks outright. */
  matchHost(url) {
    const host = hostOf(url);
    for (const candidate of hostChain(host)) {
      if (this.domains.has(candidate)) return { blocked: true, domain: candidate };
    }
    return { blocked: false, domain: null };
  }

  check(url, opts) {
    return this.evaluate(url, opts);
  }

  /* CSS for a site we let through, so its ads stay hidden — AdGuard cosmetic
     rules, exceptions (#@#) already applied. */
  cosmeticFor(url, { global = true } = {}) {
    const host = hostOf(url);
    const chain = hostChain(host);

    const excepted = new Set(this.globalCosmeticExceptions);
    for (const key of chain) {
      for (const sel of this.cosmeticExceptions.get(key) || []) excepted.add(sel);
    }

    const out = [];
    if (global) {
      for (const entry of this.globalCosmetic) {
        if (excepted.has(entry.sel)) continue;
        if (entry.except.some(d => domainMatches(host, d))) continue;
        out.push(entry.css);
      }
    }
    for (const key of chain) {
      for (const entry of this.cosmetic.get(key) || []) {
        if (excepted.has(entry.sel)) continue;
        if (entry.except.some(d => domainMatches(host, d))) continue;
        out.push(entry.css);
      }
    }
    return [...new Set(out)];
  }

  stats() {
    return this.counts || { rules: 0, network: 0, exceptions: 0, cosmetic: 0, domains: 0, unsupported: 0 };
  }
}

function ruleReason(rule) {
  const o = rule.opts;
  if (o.types.has('document')) return 'document';
  return rule.domain ? 'domain' : 'url';
}
