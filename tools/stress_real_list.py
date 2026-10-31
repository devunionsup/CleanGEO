#!/usr/bin/env python3
"""Stress-test the CleanGEO filter compiler against a REAL AdGuard Safari list."""
import re, json, sys, time
sys.path.insert(0, "tools")
from verify_logic import compile_line

path = "tools/adguard-safari-2.txt"
text = open(path, encoding="utf-8", errors="replace").read()
lines = text.splitlines()
print(f"Source: {path}  ({len(text):,} bytes, {len(lines):,} lines)")

t0 = time.time()
rules, dropped = [], 0
bad_sel = 0
for line in lines:
    r = compile_line(line)
    if r is None:
        if line.strip() and not line.strip().startswith(("!", "[", "# ")):
            dropped += 1
        continue
    # Safari url-filter must be a valid JS regex: sanity-check the pieces we emit.
    uf = r["trigger"].get("url-filter", "")
    if uf:
        try:
            re.compile(uf)
        except re.error:
            dropped += 1
            continue
    sel = r["action"].get("selector")
    if sel is not None:
        # reject empty or absurd selectors
        if not sel.strip() or len(sel) > 8192:
            bad_sel += 1
            continue
    rules.append(r)
dt = time.time() - t0

compiled = len(rules)
print(f"Compiled rules : {compiled:,}")
print(f"Dropped lines  : {dropped:,} (comments/unsupported/invalid)")
print(f"Bad selectors  : {bad_sel}")
print(f"Compile time   : {dt:.2f}s")
assert compiled <= 150_000, "exceeds Safari limit!"

# Safari JSON schema conformance spot-check
actions = {}
for r in rules:
    actions[r["action"]["type"]] = actions.get(r["action"]["type"], 0) + 1
print("Action types   :", actions)

# Validate JSON round-trip and size
payload = json.dumps(rules, separators=(",", ":")).encode()
print(f"JSON payload   : {len(payload):,} bytes")
dec = json.loads(payload)
assert len(dec) == compiled

# Every rule must have exactly one valid action type and well-formed trigger keys
valid_actions = {"block", "ignore-previous-rules", "css-display-none"}
valid_trigger_keys = {"url-filter", "if-domain", "unless-domain", "resource-type",
                      "load-type", "load-context", "if-top-url", "unless-top-url"}
valid_resource = {"document","image","raw","font","media","popup","script","svg-document","style-sheet"}
for r in dec:
    assert r["action"]["type"] in valid_actions
    t = r["trigger"]
    for k in t:
        assert k in valid_trigger_keys, k
    rt = t.get("resource-type")
    if rt:
        for v in rt:
            assert v in valid_resource, v
    lc = t.get("load-context")
    if lc:
        assert set(lc) <= {"child", "top"}
print("Safari schema conformance: OK")

# Real-world behavior checks on rules that ARE present in this list.
def find(urlfilter_sub):
    for r in rules:
        uf = r["trigger"].get("url-filter", "")
        if urlfilter_sub in uf:
            return r
    return None

def lines_with(sub):
    return [l for l in text.splitlines() if sub in l.lower() and not l.strip().startswith('!')]

def blocks(r, url):
    return re.search(r["trigger"]["url-filter"], url) is not None

# A real block rule must match its own ad URL and NOT benign traffic.
probe_host = None
for l in text.splitlines():
    ls = l.strip()
    if ls.startswith("||") and "$" not in ls and not ls.startswith("@@"):
        m = re.match(r"^\|\|([a-z0-9.-]+)\^$", ls)
        if m:
            probe_host = m.group(1)
            break
assert probe_host, "no plain ||host^ rule"
rp = None
for r2 in rules:
    uf3 = r2["trigger"].get("url-filter", "")
    if probe_host.replace(".", "\\.") in uf3 and "([/:?#]|$)" in uf3 and r2["action"]["type"] == "block":
        rp = r2
        break
assert rp and rp["action"]["type"] == "block", probe_host
assert blocks(rp, f"https://{probe_host}/ad.js"), probe_host
assert blocks(rp, f"https://deep.{probe_host}/"), probe_host
assert not blocks(rp, f"https://{probe_host}.evil.example/"), probe_host
assert not blocks(rp, "https://www.wikipedia.org/"), probe_host
print(f"Block rule '{probe_host}': matches its domain, no over-match, no false positive: OK")

# Every compiled url-filter must be a valid, anchor-clean regex:
#    no literal '^' or unescaped '|' in the middle of the pattern.
bad_re = 0
examples = []
for r in rules:
    uf = r["trigger"].get("url-filter", "")
    if not uf:
        continue
    body = uf
    if body.startswith("^[a-z-]+://"):
        body = body[len("^[a-z-]+://([a-z0-9-]+\\.)*"):]
    elif body.startswith("^"):
        body = body[1:]
    # strip the suffix anchor
    if body.endswith("([/:?#]|$)"):
        body = body[:-len("([/:?#]|$)")]
    elif body.endswith("$"):
        body = body[:-1]
    for ch in body:
        if ch == "^":
            bad_re += 1; examples.append(uf); break
        if ch == "|" and (body.index(ch) == 0 or body[body.index(ch)-1] != "\\"):
            bad_re += 1; examples.append(uf); break
assert bad_re == 0, f"{bad_re} bad regexes, e.g. {examples[:3]}"

# The '^|$modifier' family must compile without stray separators.
probe = None
for l in lines_with("^|"):
    if "^|" not in l:
        continue
    rr = compile_line(l)
    if rr:
        uf2 = rr["trigger"]["url-filter"]
        re.compile(uf2)
        assert "\\^" not in uf2, uf2
        assert "\\|" not in uf2, uf2
        probe = rr
        break
assert probe is not None, "no '^|$' rule survived; family must compile"

# Wildcard rules ('*') must become .* and actually match.
star = None
for l in lines_with("*"):
    rr = compile_line(l)
    if rr and ".*" in rr["trigger"].get("url-filter", ""):
        star = rr
        break
assert star is not None, "no wildcard rule compiled to .*"
re.compile(star["trigger"]["url-filter"])

# pick a real blocked host from the list and verify its regex semantics
blocked_hosts = []
for l in lines_with("||")[:4000]:
    m = re.match(r"^\|\|([a-z0-9.-]+)\^", l.strip())
    if m and m.group(1) != probe_host:
        blocked_hosts.append(m.group(1))
assert blocked_hosts, "no plain host rules found"
host = blocked_hosts[0]
rr = compile_line(f"||{host}^")
assert rr and rr["action"]["type"] == "block", host
assert blocks(rr, f"https://{host}/ad.js"), host
assert blocks(rr, f"https://sub.{host}/"), host
assert not blocks(rr, f"https://{host}.evil.example/"), host
assert not blocks(rr, "https://www.wikipedia.org/"), host
print(f"Real-rule semantics on '{host}': OK")

print("REAL-LIST STRESS TEST PASSED")
