import sys
from pathlib import Path

try:
    from PIL import Image, ImageDraw
except ImportError:
    print('no pillow')
    sys.exit(0)


def make(size):
    s = size / 64.0
    img = Image.new('RGBA', (size, size), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    for y in range(size):
        t = y / max(1, size - 1)
        r = int(0x2f + (0x12 - 0x2f) * t)
        g = int(0x6b + (0xb8 - 0x6b) * t)
        b = int(0xff + (0x86 - 0xff) * t)
        d.line([(0, y), (size, y)], fill=(r, g, b, 255))
    mask = Image.new('L', (size, size), 0)
    ImageDraw.Draw(mask).rounded_rectangle([0, 0, size - 1, size - 1], radius=int(16 * s), fill=255)
    img.putalpha(mask)
    d = ImageDraw.Draw(img)
    ink = (4, 18, 31, 255)
    pts = [(32*s, 12*s), (46*s, 17*s), (46*s, 28*s), (32*s, 48*s), (18*s, 28*s), (18*s, 17*s)]
    d.polygon(pts, outline=ink, width=max(2, int(3.4 * s)))
    d.line([(25*s, 32*s), (30*s, 37*s), (40*s, 26*s)], fill=ink, width=max(2, int(3.8 * s)), joint='curve')
    out = f'assets/icon-{size}.png'
    img.save(out)
    print('wrote', out, Path(out).stat().st_size, 'bytes')


make(192)
make(512)
