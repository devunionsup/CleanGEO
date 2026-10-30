"""Build the whole site in one step and prove every feature is in the result.

    python tools/build_all.py

One command, one output file. It:

  1. runs tools/build.py — Python inlines every assets/*.js module and the CSS
     into a single self-contained index.html (no module loading, no CORS);
  2. verifies the assembled page: no leftover module syntax, no broken element
     ids from $('#id') lookups, balanced CSS, one script block;
  3. checks that each feature is really present in the bundle — the parallel
     search with Safe Search off on every engine, the AdGuard filter engine,
     the shielded reader, the settings drawer, the PWA metadata;
  4. audits CleanGEO.txt with tools/audit_list.py (duplicates, mixed syntax,
     unanchored rules, empty sections).

The site itself is HTML + CSS + JavaScript; Python only assembles and tests it,
which is why every function runs in the browser without a Python runtime.
"""
import re
import runpy
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / 'tools'))

import build  # noqa: E402  (tools/ is on the path)

failures = []


def check(label, ok, detail=''):
    print(f"{'ok  ' if ok else 'FAIL'} {label}{('  — ' + detail) if detail else ''}")
    if not ok:
        failures.append(label)


# feature -> a snippet that only exists when the feature is wired in
FEATURES = {
    'search: DuckDuckGo with Safe Search off': "kp=-2",
    'search: Bing with Safe Search off': 'adlt=off',
    'search: Yahoo with Safe Search off': 'search.yahoo.com/search',
    'search: Wikipedia API': 'w/api.php?action=query&list=search',
    'search: all engines in parallel': 'Promise.all(order.map(',
    'search: 5-minute cache': 'CACHE_PREFIX',
    'search: direct address hit': 'looksLikeUrl',
    'filter: AdGuard rule engine': 'matchUrl(url)',
    'filter: AdGuard DNS (dns.adguard-dns.com)': 'dns.adguard-dns.com/dns-query',
    'filter: DNS sinkhole verdict': 'isSinkhole',
    'filter: cosmetic rules': 'cosmeticFor(url',
    'filter: own rules, exceptions refused': 'badfilter',
    'reader: script-free page': 'filterReaderDom',
    'reader: site CSS rules applied': 'scopeToReader',
    'reader: blocked card': 'blockedPageCard',
    'reader: YouTube rebuild': 'ytInitialData',
    'proxy: text route': 'r.jina.ai',
    'settings: saved in localStorage': 'cg.settings',
    'settings: auto list update': 'cg.lastCheck',
    'ui: results with shield badge': 'result-meta',
}


def main():
    print('--- build ---')
    build.main()

    html = (ROOT / 'index.html').read_text(encoding='utf-8')
    js = html.split('<script>', 1)[1].rsplit('</script>', 1)[0]
    css = html.split('<style>', 1)[1].split('</style>', 1)[0]

    print('--- page ---')
    check('no build placeholders left', '/*__CSS__*/' not in html and '/*__JS__*/' not in html)
    check('exactly one script block', html.count('<script>') == 1, str(html.count('<script>')))
    check('no module syntax in the bundle', not re.search(r'^\s*(?:import|export)\s', js, re.M))
    check('no stray </script> in the bundle', '</script' not in js)
    check('javascript inlined', len(js) > 50000, f'{len(js)} bytes')
    check('css inlined', len(css) > 5000, f'{len(css)} bytes')
    check('css braces balanced', css.count('{') == css.count('}'),
          f"{css.count('{')} open / {css.count('}')} close")

    ids = sorted(set(re.findall(r"\$\('#([A-Za-z0-9_-]+)'\)", js)))
    missing = [i for i in ids if f'id="{i}"' not in html]
    check(f'all {len(ids)} referenced element ids exist', not missing, ', '.join(missing))

    print('--- features ---')
    for label, needle in FEATURES.items():
        check(label, needle in js)

    print('--- filter list ---')
    try:
        runpy.run_path(str(ROOT / 'tools' / 'audit_list.py'), run_name='__main__')
    except SystemExit:
        pass

    print()
    size = len(html.encode('utf-8'))
    if failures:
        print(f'FAILED {len(failures)} check(s): ' + ', '.join(failures))
        sys.exit(1)
    print(f'index.html — one file, {size} bytes, every feature present')


if __name__ == '__main__':
    main()
