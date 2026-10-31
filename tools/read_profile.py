import re, json, sys, base64

path = sys.argv[1] if len(sys.argv) > 1 else "cert_unpacked/P12cert/MY.mobileprovision"
raw = open(path, "rb").read()
m = re.search(rb"<\?xml[\s\S]*?</plist>", raw)
xml = m.group(0).decode("utf-8", "replace")

def grab(tag):
    mm = re.search(rf"<key>{tag}</key>\s*<([\w]+)>([\s\S]*?)</\1>", xml)
    return mm.group(2).strip() if mm else None

print("== keys ==")
for k in ["Name", "TeamName", "TeamIdentifier", "ApplicationIdentifierPrefix", "CreationDate", "ExpirationDate", "UUID"]:
    print(f"{k}: {grab(k)}")

mm = re.search(r"<key>ProvisionedDevices</key>\s*<array>([\s\S]*?)</array>", xml)
devs = re.findall(r"<string>([\w-]+)</string>", mm.group(1)) if mm else []
print(f"ProvisionedDevices: {len(devs)}")

ent = re.search(r"<key>Entitlements</key>\s*<dict>([\s\S]*?)</dict>\s*</dict>\s*</plist>", xml)
if ent:
    e = ent.group(1)
    appid = re.search(r"<key>application-identifier</key>\s*<string>([^<]+)</string>", e)
    aps = re.search(r"<key>aps-environment</key>\s*<string>([^<]+)</string>", e)
    ni = re.search(r"<key>get-task-allow</key>\s*<(true|false)/>", e)
    print("application-identifier:", appid.group(1) if appid else None)
    print("aps-environment:", aps.group(1) if aps else None)
    print("get-task-allow:", ni.group(1) if ni else None)

certs = re.findall(rb"-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----", raw)
print(f"embedded certs: {len(certs)}")
