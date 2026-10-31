import base64, sys

src = "cert_unpacked/P12cert/my.p12"
out = "tools/P12_CERT_B64.txt"
raw = open(src, "rb").read()
b64 = base64.b64encode(raw).decode()
open(out, "w").write(b64)
print(f"my.p12: {len(raw)} bytes -> base64 {len(b64)} chars -> {out}")
