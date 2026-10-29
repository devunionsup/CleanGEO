import re
from pathlib import Path

html = Path('index.html').read_text(encoding='utf-8')
js = html.split('<script>', 1)[1].rsplit('</script>', 1)[0]

print('size', len(html))
print('placeholders left:', html.count('/*__CSS__*/'), html.count('/*__JS__*/'))
print('js bytes', len(js))
print('stray </script> in js:', js.count('</script'))
print('module keywords:', len(re.findall(r'^\s*(?:import|export)\s', js, re.M)))
for needle in ['DOMParser', 'AbortController', 'localStorage', 'sessionStorage']:
    print(f'{needle:<16}', js.count(needle))

ids = sorted(set(re.findall(r"\$\('#([A-Za-z0-9_-]+)'\)", js)))
missing = [i for i in ids if f'id="{i}"' not in html]
print('ids referenced', len(ids), 'missing', missing)

css = html.split('<style>', 1)[1].split('</style>', 1)[0]
print('css braces', css.count('{') - css.count('}'))
