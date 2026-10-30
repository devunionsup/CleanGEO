/* CleanGEO — AdGuard DNS (DNS-over-HTTPS).

   The app asks one resolver and one only: https://dns.adguard-dns.com/dns-query
   (RFC 8484 wire format, GET with ?dns=<base64url>). AdGuard DNS answers a
   domain it blocks with 0.0.0.0 (A) or :: (AAAA), so the answer itself is the
   verdict — no other DNS provider is contacted, ever.

   The endpoint sends no Access-Control-Allow-Origin, so a page on the web
   cannot read it directly. The direct route is tried first; when the browser
   refuses it, the very same AdGuard request is fetched through a public
   pass-through relay (it only carries bytes, it is not a resolver). */

const DOH = 'https://dns.adguard-dns.com/dns-query';
const RELAY = 'https://api.allorigins.win/raw?url=';

const A = 1;
const AAAA = 28;

const DNS_TTL = 10 * 60 * 1000;
const dnsMemory = new Map();

function ctrl(ms) {
  const c = new AbortController();
  const timer = setTimeout(() => c.abort(), ms);
  return { signal: c.signal, done: () => clearTimeout(timer) };
}

function b64url(bytes) {
  let raw = '';
  for (const b of bytes) raw += String.fromCharCode(b);
  return btoa(raw).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/* a DNS question: one name, one type, recursion desired */
function buildQuery(name, type) {
  const out = [0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
  for (const label of String(name).replace(/\.$/, '').split('.')) {
    const bytes = Array.from(new TextEncoder().encode(label));
    if (!label || bytes.length > 63) throw new Error('bad name');
    out.push(bytes.length, ...bytes);
  }
  out.push(0, (type >> 8) & 255, type & 255, 0, 1);
  return new Uint8Array(out);
}

/* read the answer section out of a DNS message: A and AAAA addresses */
function parseAnswer(bytes) {
  if (bytes.length < 12) return { rcode: -1, ips: [] };
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const rcode = bytes[3] & 15;
  const questions = (bytes[4] << 8) | bytes[5];
  const answers = (bytes[6] << 8) | bytes[7];
  let off = 12;

  const skipName = () => {
    while (off < bytes.length) {
      const len = bytes[off];
      if (len === 0) { off += 1; return; }
      if ((len & 0xc0) === 0xc0) { off += 2; return; }
      off += len + 1;
    }
  };

  for (let i = 0; i < questions && off < bytes.length; i++) { skipName(); off += 4; }

  const ips = [];
  for (let i = 0; i < answers; i++) {
    skipName();
    if (off + 10 > bytes.length) break;
    const type = view.getUint16(off);
    const rdlen = view.getUint16(off + 8);
    const start = off + 10;
    if (start + rdlen > bytes.length) break;
    if (type === A && rdlen === 4) {
      ips.push(`${bytes[start]}.${bytes[start + 1]}.${bytes[start + 2]}.${bytes[start + 3]}`);
    } else if (type === AAAA && rdlen === 16) {
      const parts = [];
      for (let j = 0; j < 16; j += 2) parts.push(((bytes[start + j] << 8) | bytes[start + j + 1]).toString(16));
      const ip = parts.join(':');
      ips.push(/^(0:){7}0$/.test(ip) ? '::' : ip);
    }
    off = start + rdlen;
  }
  return { rcode, ips };
}

async function request(name, type, timeoutMs) {
  const url = DOH + '?dns=' + b64url(buildQuery(name, type));
  const headers = { accept: 'application/dns-message' };

  const direct = ctrl(timeoutMs);
  try {
    const r = await fetch(url, { headers, signal: direct.signal, cache: 'no-store' });
    if (r.ok) return { bytes: new Uint8Array(await r.arrayBuffer()), route: 'direct' };
  } catch (e) { /* the endpoint sends no CORS header: fall through to the relay */ }
  finally { direct.done(); }

  const relay = ctrl(timeoutMs + 4000);
  try {
    const r = await fetch(RELAY + encodeURIComponent(url), { signal: relay.signal, cache: 'no-store' });
    if (!r.ok) throw new Error('HTTP ' + r.status);
    return { bytes: new Uint8Array(await r.arrayBuffer()), route: 'relay' };
  } finally { relay.done(); }
}

/* AdGuard's blocking answer: the sinkhole address, never a real server */
export function isSinkhole(ip) {
  return ip === '0.0.0.0' || ip === '::' || ip === '127.0.0.1' || /^0+\.0+\.0+\.0+$/.test(ip);
}

/* Look a host up in AdGuard DNS. `blocked` is true when the answer is the
   sinkhole address — that is AdGuard DNS saying the domain is on its list. */
export async function adguardLookup(host, { force = false } = {}) {
  const name = String(host || '').trim().toLowerCase().replace(/\.$/, '');
  if (!/^[a-z0-9-]+(\.[a-z0-9-]+)+$/.test(name)) return { blocked: false, skipped: true, source: 'dns.adguard-dns.com' };

  const hit = dnsMemory.get(name);
  if (!force && hit && Date.now() - hit.at < DNS_TTL) return hit.result;

  let ips = [];
  let route = '';
  let answer = null;
  try {
    answer = await request(name, A, 5000);
    route = answer.route;
    ips = parseAnswer(answer.bytes).ips;
    if (!ips.length) {
      const v6 = await request(name, AAAA, 5000);
      route = route || v6.route;
      ips = parseAnswer(v6.bytes).ips;
    }
  } catch (e) {
    const failed = { blocked: false, error: String(e.message || e), source: 'dns.adguard-dns.com' };
    dnsMemory.set(name, { at: Date.now(), result: failed });
    return failed;
  }

  const blocked = ips.some(isSinkhole);
  const result = {
    blocked,
    ips,
    route,
    source: 'dns.adguard-dns.com',
    reason: blocked ? 'AdGuard DNS: ' + (ips.find(isSinkhole) || '0.0.0.0') : '',
  };
  dnsMemory.set(name, { at: Date.now(), result });
  return result;
}

export const ADGUARD_DOH = DOH;
