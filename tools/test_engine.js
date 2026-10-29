import { BlockList, diffRules, parseList } from '../assets/blocklist.js';

const sample = `
! CleanGEO test list
||ads.example.com^
||tracker.example.org^$third-party
||*vnmfvnkd.win*$all
||static.cloudflareinsights.com*$all
||cdn.lbs.pw/prm/adjarabet*
qartulad.in##div.avc-cro
qartulad.in##.jw-banner
liveball.sx##a.catfish_block
geofilms.net#?#div[id^="bannerPlace"]
kinolab.cc#$#div.free.align_center { remove: true; }
mykadri.tv#%#//scriptlet('remove-class', 'is-visible', 'div.mykadri-catfish')
##.global-ad-slot
`;

const list = new BlockList(sample);
console.log('stats', JSON.stringify(list.stats()));

const checks = [
  ['https://ads.example.com/pixel.js', true],
  ['https://sub.ads.example.com/x', true],
  ['https://notads.example.com/x', false],
  ['https://vnmfvnkd.win/v.mp4', true],
  ['https://cdn.lbs.pw/prm/adjarabet/catfish.js', true],
  ['https://cdn.lbs.pw/prm/other.js', false],
  ['https://qartulad.in/film', false],
];
for (const [url, want] of checks) {
  const got = list.check(url).blocked;
  console.log(got === want ? 'ok  ' : 'FAIL', url, '->', got, '| reason', list.check(url).reason || '-');
}

console.log('cosmetic qartulad.in ->', JSON.stringify(list.cosmeticFor('https://qartulad.in/x').slice(0, 3)));
console.log('cosmetic geofilms.net ->', JSON.stringify(list.cosmeticFor('https://geofilms.net/a')));
console.log('cosmetic kinolab.cc ->', JSON.stringify(list.cosmeticFor('https://kinolab.cc/a')));
console.log('cosmetic global count ->', list.cosmeticFor('https://nothing.tld/').length);
console.log('scriptlets found ->', list.scriptlets.length);

const next = sample.replace('||ads.example.com^\n', '') + '||newtracker.example.net^\n';
const diff = diffRules(sample, next);
console.log('diff', JSON.stringify({ added: diff.added, removed: diff.removed, total: diff.total }));

const noEmpty = parseList('! only comments\n\n');
console.log('empty list rules ->', noEmpty.counts.rules);
