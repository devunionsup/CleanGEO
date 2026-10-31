import re, sys, json

path = sys.argv[1] if len(sys.argv) > 1 else "cert_unpacked/P12cert/MY.mobileprovision"
raw = open(path, "rb").read()
xml = re.search(rb"<\?xml[\s\S]*?</plist>", raw).group(0).decode()
print(xml)
