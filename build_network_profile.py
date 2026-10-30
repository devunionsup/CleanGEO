#!/usr/bin/env python3
"""Turn the unified network profile into one installable configuration profile.

One source of truth (netprofile.json) -> one .mobileconfig carrying:

  * DNS settings payload (DoH)          — the system resolver, IPv4 and IPv6
  * VPN payload (IKEv2)                 — a real tunnel, not a simulation
  * proxy attached to the VPN payload   — this is what sets the routing order:
        no VPN             browser -> proxy -> internet
        VPN + nested true  browser -> VPN -> proxy -> internet
        VPN + nested false browser -> proxy -> VPN -> internet

Apple exposes proxy keys only inside a VPN payload (a proxy payload of its own
always sits outside the tunnel), so those two placements are the only orders
the platform can honour. Anything else is refused rather than written into a
file that would quietly do something else.

Usage:
  python build_network_profile.py                  # writes cleangeo-network.mobileconfig
  python build_network_profile.py --check          # validate and print the plan, write nothing
  python build_network_profile.py --out x.mobileconfig
"""
from __future__ import annotations

import argparse
import plistlib
import sys
from pathlib import Path

import netcontroller as nc

ROOT = Path(__file__).resolve().parent
OUT = ROOT / "cleangeo-network.mobileconfig"

# Stable UUIDs: reinstalling the profile updates it instead of stacking copies.
UUID_ROOT = "6f1c2a84-57d3-4b19-9c8c-2a0d3e41b7f0"
UUID_DNS = "0b9a7c31-2d54-4c8e-91f6-5a7e8c21d304"
UUID_VPN = "c3d67f18-9e42-4a70-b5b1-84f0e29a6d52"


class Unsupported(Exception):
    """The profile asks for something the platform cannot do."""


def build(profile: dict) -> dict:
    """Return the plist document for `profile`. Raises ConfigError/Unsupported."""
    errors = validate_profile(profile)
    if errors:
        raise ConfigError("; ".join(errors))
    if not profile.get("enabled"):
        raise Unsupported("the profile is disabled: nothing to install")

    vpn = profile.get("vpn") or {}
    proxy = profile.get("proxy") or {}
    dns = profile.get("dns") or {}
    ipv6 = profile.get("ipv6") or {}

    payloads = []
    if dns.get("enabled"):
        payloads.append(dns_payload(dns, ipv6))
    if vpn.get("enabled") or proxy.get("enabled"):
        payloads.append(vpn_payload(profile, vpn, proxy, dns, ipv6))
    if not payloads:
        raise Unsupported("no component is enabled: nothing to install")

    return {
        "PayloadType": "Configuration",
        "PayloadIdentifier": "tv.cleangeo.network",
        "PayloadUUID": UUID_ROOT,
        "PayloadVersion": 1,
        "PayloadDisplayName": profile.get("name") or "CleanGEO Secure Network",
        "PayloadOrganization": profile.get("organization") or "CleanGEO",
        "PayloadDescription": describe(profile),
        "PayloadRemovalDisallowed": False,
        "PayloadContent": payloads,
    }


def validate_profile(profile: dict) -> list[str]:
    """Module-level alias so callers can `from build_network_profile import ...`."""
    return nc.validate_profile(profile)


ConfigError = nc.ConfigError


def describe(profile: dict) -> str:
    parts = []
    vpn = profile.get("vpn") or {}
    proxy = profile.get("proxy") or {}
    dns = profile.get("dns") or {}
    if vpn.get("enabled"):
        parts.append("VPN (IKEv2) to %s" % vpn.get("remoteAddress"))
    if proxy.get("enabled"):
        if str(proxy.get("type")).upper() == "PAC":
            parts.append("PAC proxy %s" % proxy.get("pacUrl"))
        else:
            parts.append("%s proxy %s:%s"
                         % (proxy.get("type"), proxy.get("host"), proxy.get("port")))
    if dns.get("enabled"):
        parts.append("DNS over HTTPS via %s (fallback %s)"
                     % ((dns.get("primary") or {}).get("name"),
                        (dns.get("fallback") or {}).get("name")))
    return "%s. Routing: %s" % ("; ".join(parts), nc.routing_path(profile))


def dns_payload(dns: dict, ipv6: dict) -> dict:
    primary = dns.get("primary") or {}
    settings = {"DNSProtocol": "HTTPS", "ServerURL": primary.get("url")}
    if (ipv6.get("mode") or "prefer") == "disable":
        # No supplemental domains: the payload answers for every name, and the
        # absence of AAAA answers is what keeps IPv6 out of the picture.
        settings["SupplementalMatchDomains"] = []
    return {
        "PayloadType": "com.apple.dnsSettings.managed",
        "PayloadIdentifier": "tv.cleangeo.network.dns",
        "PayloadUUID": UUID_DNS,
        "PayloadVersion": 1,
        "PayloadDisplayName": "CleanGEO DNS — %s" % (primary.get("name") or "DoH"),
        "PayloadDescription": (
            "Every DNS query, IPv4 and IPv6, goes to %s over HTTPS. %s is used only when "
            "this provider fails a health check or exceeds the latency budget."
            % (primary.get("url"), (dns.get("fallback") or {}).get("name"))),
        "DNSSettings": settings,
    }


def vpn_payload(profile: dict, vpn: dict, proxy: dict, dns: dict, ipv6: dict) -> dict:
    payload = {
        "PayloadType": "com.apple.vpn.managed",
        "PayloadIdentifier": "tv.cleangeo.network.vpn",
        "PayloadUUID": UUID_VPN,
        "PayloadVersion": 1,
        "PayloadDisplayName": "CleanGEO tunnel and proxy layer",
        "UserDefinedName": "CleanGEO Secure Network",
        "VPNType": "IKEv2",
        "IKEv2": {},
    }

    if vpn.get("enabled"):
        remote = str(vpn.get("remoteAddress") or "")
        ike = {
            "RemoteAddress": remote,
            "RemoteIdentifier": vpn.get("remoteIdentifier") or remote,
            "LocalIdentifier": vpn.get("localIdentifier") or "cleangeo",
            "AuthenticationMethod": vpn.get("authMethod") or "UserNamePassword",
        }
        if vpn.get("serverCertificateCommonName"):
            ike["ServerCertificateCommonName"] = vpn["serverCertificateCommonName"]
        if vpn.get("username"):
            ike["Username"] = vpn["username"]
        if vpn.get("onDemand"):
            ike["OnDemandEnabled"] = 1
            ike["OnDemandRules"] = [{"Action": "Connect"}]
        payload["IKEv2"] = ike
        if vpn.get("overridePrimary"):
            payload["OverridePrimary"] = 1
        if dns.get("enabled"):
            payload["DNS"] = {"ServerURL": (dns.get("primary") or {}).get("url"),
                              "SupplementalMatchDomains": [""]}
    else:
        # No tunnel configured: this payload exists only to carry the proxy and
        # is labelled as such. It is never reported as a VPN connection.
        payload["PayloadDescription"] = ("Proxy container only — no VPN tunnel is "
                                         "configured in this profile.")
        payload["IKEv2"] = {"RemoteAddress": "", "DeadPeerDetectionRate": "None"}

    if proxy.get("enabled"):
        payload["Proxies"] = proxies(proxy)
    if (ipv6.get("mode") or "prefer") == "strict":
        payload["IPv4"] = {"OverridePrimary": 1}
    return payload


def proxies(proxy: dict) -> dict:
    ptype = str(proxy.get("type") or "").upper()
    out: dict = {"ProxyAutoDiscoveryEnable": 0, "HTTPEnable": 0, "HTTPSEnable": 0,
                 "SOCKSEnable": 0, "ProxyAutoConfigEnable": 0}
    if ptype == "PAC":
        out["ProxyAutoConfigEnable"] = 1
        out["ProxyAutoConfigURLString"] = proxy.get("pacUrl")
        # Fallback off means: an unreachable PAC does not become DIRECT traffic.
        out["ProxyAutoConfigFallbackAllowed"] = 1 if proxy.get("pacFallbackAllowed") else 0
        return out

    host = str(proxy.get("host") or "")
    port = int(proxy.get("port") or 0)
    if ptype == "SOCKS5":
        out["SOCKSEnable"] = 1
        out["SOCKSProxy"] = host
        out["SOCKSPort"] = port
        if proxy.get("username"):
            out["SOCKSUser"] = proxy["username"]
    else:
        out["HTTPEnable"] = 1
        out["HTTPProxy"] = host
        out["HTTPPort"] = port
        if ptype == "HTTPS":
            out["HTTPSEnable"] = 1
            out["HTTPSProxy"] = host
            out["HTTPSPort"] = port
        if proxy.get("username"):
            out["HTTPUser"] = proxy["username"]
    return out


def nested_order(profile: dict) -> str:
    """The order the generated profile actually expresses."""
    vpn = (profile.get("vpn") or {}).get("enabled")
    proxy = (profile.get("proxy") or {}).get("enabled")
    placement = (profile.get("proxy") or {}).get("placement")
    if not proxy:
        return "browser → vpn → internet" if vpn else "browser → internet"
    if not vpn:
        return "browser → proxy → internet"
    if placement == "vpn":
        return "browser → vpn → proxy → internet"
    return "browser → proxy → vpn → internet"


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Build the CleanGEO unified network profile")
    ap.add_argument("--out", default=str(OUT))
    ap.add_argument("--check", action="store_true", help="validate and print, write nothing")
    ns = ap.parse_args(argv)

    try:
        profile = nc.load_profile()
        doc = build(profile)
    except (nc.ConfigError, Unsupported) as exc:
        print("error: %s" % exc)
        return 1

    print("profile:  %s" % profile.get("name"))
    print("routing:  %s" % nc.routing_path(profile))
    print("payloads: %s" % ", ".join(p["PayloadType"] for p in doc["PayloadContent"]))
    for warning in nc.conflicts(profile):
        print("warning: %s" % warning)

    if ns.check:
        print("check only: nothing written")
        return 0

    out = Path(ns.out)
    with out.open("wb") as f:
        plistlib.dump(doc, f)
    print("wrote %s (%d bytes)" % (out.name, out.stat().st_size))
    return 0


if __name__ == "__main__":
    sys.exit(main())
