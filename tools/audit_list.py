"""Audit the CleanGEO filter list that this repository holds.

    python tools/audit_list.py

Reads CleanGEO.txt from the project root and reports the mistakes a filter list
usually picks up: duplicate lines, cosmetic rules with a network anchor, rules
that are not anchored at all, and empty sections.
"""
import re
import sys
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
LOCAL = ROOT / 'CleanGEO.txt'
URL = 'https://raw.githubusercontent.com/devunionsup/CleanGEO/refs/heads/main/CleanGEO.txt'

if LOCAL.exists():
    text = LOCAL.read_text(encoding='utf-8-sig')
    print('source: local', LOCAL.name)
else:
    text = urllib.request.urlopen(URL, timeout=30).read().decode('utf-8-sig')
    print('source: github raw')

lines = text.split('\n')

seen = {}
dups = []
mixed = []
network = []
counts = {'net': 0, 'cos': 0, 'all': 0, 'doc': 0, 'exc': 0}
empty_sections = []
section = None

for i, raw in enumerate(lines, 1):
    if not raw.strip():
        continue
    if raw.lstrip().startswith('!'):
        t = raw.strip()[1:].strip()
        if t.lower().startswith('title') or not t:
            continue
        if t.endswith('~>'):
            section = [t[:-2].strip(), i, False]
        elif t.endswith('~^'):
            if section and not section[2]:
                empty_sections.append(section[0])
            section = None
        continue

    line = raw.strip()
    if line in seen:
        dups.append((i, seen[line], line))
    else:
        seen[line] = i

    if re.match(r'^\|\|[^#]*##', line) or re.match(r'^\|\|[^#]*#\?#', line):
        mixed.append((i, line))

    if '##' in line or '#?#' in line or '#$#' in line or '#%#' in line:
        counts['cos'] += 1
        if section:
            section[2] = True
    else:
        counts['net'] += 1
        network.append((i, line))
        if '$all' in line:
            counts['all'] += 1
        if '$document' in line:
            counts['doc'] += 1
        if line.startswith('@@'):
            counts['exc'] += 1
        if section:
            section[2] = True

print('lines total      ', len(lines))
print('network rules    ', counts['net'], ' ($all:', counts['all'], ', $document:', counts['doc'], ', @@:', counts['exc'], ')')
print('cosmetic rules   ', counts['cos'])
print('duplicate lines  ', len(dups))
for i, first, line in dups:
    print('   line', i, 'repeats line', first, ':', line)
print('mixed syntax     ', len(mixed))
for i, line in mixed:
    print('   line', i, ':', line, '  -> the || prefix has no meaning on a cosmetic rule')
print('empty sections   ', empty_sections)

unanchored = [l for _, l in network if not l.lstrip('@').startswith(('||', '|', '/'))]
print('unanchored rules ', len(unanchored))
for l in unanchored:
    print('   ', l)

CASUAL = ['cs.titech.ac.jp', 'ondevice-agreements.apple.com']
accidental = [(i, l) for i, l in network if any(d in l for d in CASUAL)]
if unanchored or mixed or dups:
    sys.exit(0)
