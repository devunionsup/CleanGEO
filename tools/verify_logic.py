#!/usr/bin/env python3
"""
Logic verification for CleanGEO algorithms (mirrors the Swift implementation).

Tests:
 1. FilterCompiler: AdGuard rule -> Safari JSON rule conversion
 2. BigInt modpow: correctness for RSA verification math
 3. DNS wire: name encode/decode with compression pointers
 4. Schedule.isDue logic
"""
import re, json

# ---------- 1. Filter compiler (mirror of FilterCompiler.swift) ----------

UNSUPPORTED = {"redirect","replace","jsinject","websocket","csp","removeparam",
               "ghide","dnstype","dnsrewrite","popup","network","doc","other","ping"}
KNOWN_HARMLESS = {"important","match-case","background","document","inline-font",
                  "inline-script","other","webrtc","app","strict-third-party",
                  "strict-first-party","css","ping","empty","mp4"}

def regex_escape(s: str) -> str:
    out = []
    for ch in s:
        if ch in ".?+()[]{}|$\\":
            out.append("\\" + ch)
        elif ch == "*":
            out.append(".*")
        elif ch == "^":
            out.append("[/:?&=]")
        else:
            out.append(ch)
    return "".join(out)

def compile_network_rule(raw: str):
    line = raw
    is_exception = line.startswith("@@")
    if is_exception: line = line[2:]
    if "$important" in line: line = line.replace("$important", "")
    modifiers = []
    if "$" in line:
        line, modpart = line.split("$", 1)
        modifiers = [m.strip() for m in modpart.split(",") if m.strip()]
    for m in modifiers:
        if m in UNSUPPORTED: return None
    if not line: return None
    prefix = suffix = ""
    if line.startswith("||"):
        line = line[2:]; prefix = "^[a-z-]+://([a-z0-9-]+\\.)*"
    elif line.startswith("|"):
        line = line[1:]; prefix = "^"
    if line.endswith("^|"):
        line = line[:-2]; suffix = "([/:?#]|$)"
    elif line.endswith("|"):
        line = line[:-1]; suffix = "$"
    elif line.endswith("^"):
        line = line[:-1]; suffix = "([/:?#]|$)"
    pattern = regex_escape(line)
    urlfilter = prefix + pattern + suffix
    resource_types, domains, exceptions, third = None, None, None, None
    for m in modifiers:
        if m == "script": resource_types = ["script"]
        elif m == "image": resource_types = ["image"]
        elif m == "stylesheet": resource_types = ["style-sheet"]
        elif m in ("xmlhttprequest","xhr","fetch"): resource_types = ["raw"]
        elif m in ("subdocument","frame","iframe"): resource_types = ["document"]
        elif m == "third-party": third = True
        elif m in ("~third-party","first-party"): third = False
        elif m.startswith("domain="):
            for d in m[7:].split("|"):
                d = d.strip()
                if d.startswith("~"): exceptions = [d[1:]]
                elif d: domains = [d]
        elif m not in KNOWN_HARMLESS:
            return None
    load_context = ["child"] if third is True else (["top"] if third is False else None)
    return {"trigger": {"url-filter": urlfilter,
                        **({"if-domain": domains} if domains else {}),
                        **({"unless-domain": exceptions} if exceptions else {}),
                        **({"resource-type": resource_types} if resource_types else {}),
                        **({"load-context": load_context} if load_context else {})},
            "action": {"type": "ignore-previous-rules" if is_exception else "block"}}

def compile_line(line: str):
    line = line.strip()
    if not line or line.startswith("!") or line.startswith("[") or line.startswith("# "):
        return None
    if "#%#" in line or "#$#" in line or "#$?" in line:
        return None
    for marker in ("#@#", "##", "#?#"):
        idx = line.find(marker)
        if idx != -1:
            dompart, sel = line[:idx], line[idx+len(marker):]
            if not sel: return None
            ifdom = [d.strip() for d in dompart.split(",") if d.strip() and not d.startswith("~")]
            unles = [d[1:].strip() for d in dompart.split(",") if d.startswith("~") and len(d) > 1]
            return {"trigger": {**({"if-domain": ifdom} if ifdom else {}),
                                **({"unless-domain": unles} if unles else {})},
                    "action": {"type": "css-display-none", "selector": sel}}
    return compile_network_rule(line)

def test_compiler():
    r = compile_line("||ads.example.com^")
    assert r["action"]["type"] == "block", r
    assert r["trigger"]["url-filter"] == r"^[a-z-]+://([a-z0-9-]+\.)*ads\.example\.com([/:?#]|$)", r
    assert re.search(r["trigger"]["url-filter"], "https://ads.example.com/x.js")
    assert re.search(r["trigger"]["url-filter"], "https://sub.ads.example.com/")
    assert not re.search(r["trigger"]["url-filter"], "https://ads.example.com.evil.io/")
    assert not re.search(r["trigger"]["url-filter"], "https://example.com/ads.example.com")

    r = compile_line("@@||good.com^")
    assert r["action"]["type"] == "ignore-previous-rules"

    r = compile_line("example.com##.ad-banner")
    assert r["action"] == {"type": "css-display-none", "selector": ".ad-banner"}
    assert r["trigger"]["if-domain"] == ["example.com"]

    r = compile_line("||t.com^$script,third-party")
    assert r["trigger"]["resource-type"] == ["script"]
    assert r["trigger"]["load-context"] == ["child"]

    assert compile_line("||x.com^$redirect=noop") is None
    assert compile_line("! comment") is None
    assert compile_line("[Adblock Plus 2.0]") is None
    assert compile_line("") is None
    r = compile_line("||doubleclick.net^$important")
    assert r and "$important" not in r["trigger"]["url-filter"]

    # End-to-end on a realistic AdGuard-style list fragment.
    sample = """[AdGuard]
! Title: test
||ads.example.com^$third-party
||tracker.net^$script,image
@@||whitelisted.org^
example.com##.banner
example.com,~sub.example.com###top-ad
||paywall.com^$important
||edge.stripe.com^
"""
    rules = [compile_line(l) for l in sample.splitlines()]
    rules = [r for r in rules if r]
    assert len(rules) == 7, rules
    json.dumps(rules)  # must be serializable
    print("1. FilterCompiler: OK")

# ---------- 2. modpow (mirror of BigInt.power, bit-at-a-time) ----------

def modpow(base: int, exp: int, m: int) -> int:
    result, base = 1, base % m
    while exp > 0:
        if exp & 1: result = (result * base) % m
        base = (base * base) % m
        exp >>= 1
    return result

def test_modpow():
    assert modpow(10, 3, 31) == 8
    # Textbook RSA 61*53=3233, e=17, d=2753
    n, e, d = 3233, 17, 2753
    for msg in [2, 66, 123, 3232]:
        c = modpow(msg, e, n)
        assert modpow(c, d, n) == msg, msg
    # 2048-bit style sanity with big numbers
    p = 32416190071; q = 32416187567
    n2 = p * q
    e2 = 65537
    d2 = pow(e2, -1, (p-1)*(q-1))
    m2 = 123456789
    c2 = modpow(m2, e2, n2)
    assert modpow(c2, d2, n2) == m2
    print("2. BigInt modpow (RSA math): OK")

# ---------- 3. DNS wire decode (mirror of DNSWire.swift) ----------

def decode_name(data, offset, seen=None):
    if seen is None: seen = set()
    labels = []
    while True:
        ln = data[offset]; offset += 1
        if ln == 0: break
        if ln & 0xC0 == 0xC0:
            ptr = ((ln & 0x3F) << 8) | data[offset]; offset += 1
            if ptr in seen: raise ValueError("loop")
            seen.add(ptr)
            sub, _ = decode_name(data, ptr, seen)
            labels.append(sub)
            break
        if ln > 63: raise ValueError("bad len")
        labels.append(data[offset:offset+ln].decode()); offset += ln
    return ".".join(labels), offset

def test_dns_wire():
    # Query encode: name + type + class + OPT
    name = "example.com"
    q = b""
    for lbl in name.split("."):
        q += bytes([len(lbl)]) + lbl.encode()
    q += b"\x00"
    assert q == b"\x07example\x03com\x00"

    # Compressed answer: pointer 0xC00C
    msg = bytes([0,1, 0,0, 0,1, 0,1, 0,0, 0,0])
    msg += b"\x07example\x03com\x00" + b"\x00\x01\x00\x01"
    msg += b"\xc0\x0c" + b"\x00\x01\x00\x01\x00\x00\x00<" + b"\x00\x04\x01\x02\x03\x04"
    nm, _ = decode_name(msg, 12)
    assert nm == "example.com", nm
    # rdata offset: header(12) + question name + type(2)+class(2) + answer: name(2 ptr)+type(2)+class(2)+ttl(4)+rdlen(2)
    rd_off = 12 + len(b"\x07example\x03com\x00") + 4 + 2 + 10
    assert msg[rd_off:rd_off+4] == bytes([1,2,3,4]), (rd_off, msg)

    # Self-pointer must raise (loop guard)
    bad = bytes([0,1, 0,0, 0,1, 0,0, 0,0, 0,0]) + b"\xc0\x0c" + b"\x00\x01\x00\x01"
    try:
        decode_name(bad, 12); assert False, "loop not caught"
    except (ValueError, IndexError, RecursionError):
        pass
    print("3. DNS wire format: OK")

# ---------- 4. Schedule.isDue (mirror of UpdateSchedule.swift) ----------

def is_due(times_min, now_min, last_min):
    if not times_min: return False
    if last_min is None:
        return True
    for due in times_min:
        delta = (now_min - due) % 1440
        elapsed = now_min - last_min
        if elapsed >= delta - 0.5:
            return True
    return False

def test_schedule():
    assert is_due([180], 240, 120) is True     # slot 3:00 passed 2h after update
    assert is_due([180, 1260], 1230, 1200) is False  # updated 30 min ago, next 21:00
    assert is_due([180], 240, None) is True    # never updated
    assert is_due([], 240, None) is False      # empty schedule
    # Four-time default
    s = [180, 540, 900, 1260]
    assert is_due(s, 545, 300) is True         # just after 9:00, last 5:00
    assert is_due(s, 560, 541) is False
    print("4. Schedule logic: OK")

if __name__ == "__main__":
    test_compiler()
    test_modpow()
    test_dns_wire()
    test_schedule()
    print("\nAll logic tests passed.")
