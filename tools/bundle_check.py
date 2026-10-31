import re, sys

path = sys.argv[1] if len(sys.argv) > 1 else "cert_unpacked/P12cert/MY.mobileprovision"
raw = open(path, "rb").read()
xml = re.search(rb"<\?xml[\s\S]*?</plist>", raw).group(0).decode()

m = re.search(r"<key>application-identifier</key>\s*<string>([^<]+)</string>", xml)
print("app id:", m.group(1) if m else "NOT FOUND")

m2 = re.search(r"<key>provisioned-devices</key>\s*<array>([\s\S]*?)</array>", xml)
print("devices:", re.findall(r"<string>([\w-]{40})</string>", m2.group(1)) if m2 else "none")
