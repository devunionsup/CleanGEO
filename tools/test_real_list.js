import { BlockList } from '../assets/blocklist.js';

const url = 'https://raw.githubusercontent.com/devunionsup/CleanGEO/main/CleanGEO.txt';
try {
  const r = await fetch(url);
  const text = await r.text();
  const list = new BlockList(text);
  console.log('bytes', text.length, 'stats', JSON.stringify(list.stats()));
  for (const u of ['https://vnmfvnkd.win/x.mp4', 'https://qartulad.in/film/1', 'https://myvideo.ge/', 'https://static.cloudflareinsights.com/beacon.js']) {
    const v = list.check(u);
    console.log(u, '->', v.blocked, v.reason || '', v.domain || '');
  }
  console.log('css qartulad.in', list.cosmeticFor('https://qartulad.in/f').slice(0, 4));
} catch (e) {
  console.log('fetch failed in engine:', e.message);
}
