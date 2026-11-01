#!/usr/bin/env python3
"""pbxproj ვალიდაცია: სტრუქტურა, ბალანსი, დამოკიდებულებები."""
import re, sys

src = open("CleanGEO.xcodeproj/project.pbxproj").read()
errs = []

# 1. ფიგურნების ბალანსი
bal = src.count("{") - src.count("}")
if bal != 0:
    errs.append(f"figuranta balance: {bal}")

# 2. multi-line isa ბლოკები + single-line ჩანაწერები
ids = set()

for m in re.finditer(r"^[ \t]*([0-9A-F]{6,24})\s*/\*.*?\*/\s*=\s*\{", src, re.M):
    ids.add(m.group(1))
for m in re.finditer(r"^[ \t]*([0-9A-F]{6,24})\s*=\s*\{", src, re.M):
    ids.add(m.group(1))
for m in re.finditer(r"([0-9A-F]{24})\s*/\*.*?\*/\s*=\s*\{[^}]*\};", src):
    ids.add(m.group(1))

# 3. ყველა ლინკი არსებობს?
for m in re.finditer(r"fileRef = ([0-9A-F]{6,24})", src):
    if m.group(1) not in ids:
        errs.append(f"fileRef ვერ მოიძებნა: {m.group(1)}")
for m in re.finditer(r"(?:target|productRef|proxy|remoteGlobalIDString) = ([0-9A-F]{6,24})", src):
    if m.group(1) not in ids:
        errs.append(f"ref ვერ მოიძებნა: {m.group(1)}")
# group children და phase files
for m in re.finditer(r"^[ \t]+([0-9A-F]{6,24})\s*/\*", src, re.M):
    if m.group(1) not in ids:
        errs.append(f"children/files წევრი ვერ მოიძებნა: {m.group(1)}")

# 4. სავალდებულო ჩანაწერები
must = ["TunnelStatsStore.swift", "PacketTunnelProvider.swift",
        "AB0111", "110113", "AB0401", "AB0202", "AB0404"]
for k in must:
    if k not in src:
        errs.append(f"აკლია: {k}")

# 5. TunnelStatsStore: buildfile(2)+fileref(2)+group(1)+sources(1) = 6 თანადგომა
cnt = len(re.findall(r"TunnelStatsStore\.swift", src))
if cnt != 6:
    errs.append(f"TunnelStatsStore.swift ნაპოვნია {cnt}-ჯერ (უნდა 6)")

# 6. duplicate ID
lines = [l for l in src.splitlines() if re.match(r"^\t\t[0-9A-F]", l)]
seen, dup = set(), []
for l in lines:
    k = re.match(r"^\t\t([0-9A-F]+)", l).group(1)
    if k in seen:
        dup.append(k)
    seen.add(k)
if dup:
    errs.append(f"დუბლიკატი ID: {set(dup)}")

# 7. pbxproj header
if not src.startswith("// !$*UTF8*$!"):
    errs.append("ჰედერი დაზიანებულია")

if errs:
    print("შეცდომები:")
    for e in errs:
        print(" -", e)
    sys.exit(1)
print(f"OK: {len(ids)} ობიექტი, ყველა ლინკი სწორია")
