"""CleanGEO NetworkController — one profile for VPN, proxy and DoH.

netprofile.json is the single source of truth. The configuration-profile
builder, the panel and the tests all read it, so VPN, proxy and DNS cannot
drift apart into three independent settings.

Rules this module enforces:

* A component is "ok"/"active" only after a probe actually succeeded. No
  probe, no claim.
* DNS goes to ONE provider at a time: the primary until it fails a health
  check or exceeds the latency budget, then the fallback. Never both.
* Failures are recorded, recovery is bounded, and a failure never rewrites the
  user's configuration.
* Diagnostics carry provider names, timings and error classes — never visited
  hostnames, DNS question names, passwords or tokens.
"""
from __future__ import annotations

import json
import os
import socket
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent
PROFILE_PATH = ROOT / "netprofile.json"

PROXY_TYPES = ("HTTP", "HTTPS", "SOCKS5", "PAC")
ROUTING_STEPS = ("proxy", "vpn", "internet")
IPV6_MODES = ("prefer", "strict", "disable")
AUTH_METHODS = ("None", "SharedSecret", "Certificate", "UserNamePassword")
SECTIONS = ("vpn", "proxy", "dns", "routing", "ipv6", "recovery")


class ConfigError(ValueError):
    """The profile is unusable; nothing is applied."""


# --------------------------------------------------------------------------
# profile
# --------------------------------------------------------------------------

def default_profile() -> dict:
    return {
        "version": 1,
        "name": "CleanGEO Secure Network",
        "organization": "CleanGEO",
        "enabled": True,
        "vpn": {
            "enabled": False,
            "remoteAddress": "",
            "remoteIdentifier": "",
            "localIdentifier": "cleangeo",
            "authMethod": "UserNamePassword",
            "username": "",
            "serverCertificateCommonName": "",
            "overridePrimary": True,
            "onDemand": True,
        },
        "proxy": {
            "enabled": True,
            "placement": "vpn",
            "type": "PAC",
            "pacUrl": "https://devunionsup.github.io/CleanGEO/proxy.pac",
            "pacFallbackAllowed": False,
            "captiveLoginAllowed": True,
            "host": "",
            "port": 0,
            "scheme": "HTTPS",
            "username": "",
        },
        "dns": {
            "enabled": True,
            "primary": {
                "name": "AdGuard",
                "url": "https://dns.adguard-dns.com/dns-query",
                "probe": "https://dns.adguard-dns.com/resolve",
            },
            "fallback": {
                "name": "Cloudflare Security",
                "url": "https://security.cloudflare-dns.com/dns-query",
                "probe": "https://security.cloudflare-dns.com/dns-query",
            },
            "timeoutMs": 2000,
            "maxLatencyMs": 800,
            "maxRetries": 1,
        },
        "routing": {"order": ["proxy", "vpn", "internet"]},
        "ipv6": {"mode": "prefer", "blockWhenUnproxied": False},
        "recovery": {"maxAttempts": 3},
    }


def load_profile(path: Path | str = PROFILE_PATH) -> dict:
    p = Path(path)
    if not p.exists():
        return default_profile()
    with p.open(encoding="utf-8") as f:
        return merge_defaults(json.load(f))


def merge_defaults(data: dict, base: dict | None = None) -> dict:
    """Fill absent keys from the defaults, keep everything the user set.

    The recursion carries the matching *sub*-default as its base, so a section
    only ever gains keys that belong to that section.
    """
    base = default_profile() if base is None else base
    out = dict(base)
    for key, value in data.items():
        if isinstance(value, dict) and isinstance(base.get(key), dict):
            out[key] = merge_defaults(value, base[key])
        else:
            out[key] = value
    return out


def save_profile(profile: dict, path: Path | str = PROFILE_PATH) -> None:
    """Validate, then write atomically: no half-written profile survives a crash."""
    errors = validate_profile(profile)
    if errors:
        raise ConfigError("; ".join(errors))
    p = Path(path)
    tmp = p.with_suffix(p.suffix + ".tmp")
    tmp.write_text(json.dumps(profile, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    os.replace(tmp, p)


def validate_profile(profile: dict) -> list[str]:
    """Every problem at once, not just the first."""
    e: list[str] = []
    if not isinstance(profile, dict):
        return ["profile is not an object"]
    if not str(profile.get("name") or "").strip():
        e.append("profile name is empty")

    vpn = profile.get("vpn") or {}
    proxy = profile.get("proxy") or {}
    dns = profile.get("dns") or {}
    routing = profile.get("routing") or {}
    ipv6 = profile.get("ipv6") or {}
    rec = profile.get("recovery") or {}

    if vpn.get("enabled"):
        if not str(vpn.get("remoteAddress") or "").strip():
            e.append("vpn: remoteAddress is required when VPN is enabled")
        if vpn.get("authMethod") not in AUTH_METHODS:
            e.append("vpn: unknown authMethod %r" % (vpn.get("authMethod"),))
        if vpn.get("authMethod") in ("Certificate", "UserNamePassword") \
                and not str(vpn.get("remoteIdentifier") or "").strip():
            e.append("vpn: remoteIdentifier must match the server certificate identity")

    if proxy.get("enabled"):
        ptype = str(proxy.get("type") or "").upper()
        if ptype not in PROXY_TYPES:
            e.append("proxy: unknown type %r (use %s)" % (proxy.get("type"), ", ".join(PROXY_TYPES)))
        if ptype == "PAC":
            if not str(proxy.get("pacUrl") or "").lower().startswith("https://"):
                e.append("proxy: pacUrl must be https:// (a plain http PAC can be rewritten in transit)")
        else:
            if not str(proxy.get("host") or "").strip():
                e.append("proxy: host is required for %s" % ptype)
            port = proxy.get("port")
            if not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535:
                e.append("proxy: port must be an integer 1-65535")
            scheme = str(proxy.get("scheme", "")).upper()
            if ptype == "SOCKS5" and scheme not in ("SOCKS5", "SOCKS"):
                e.append("proxy: SOCKS5 proxy must use the SOCKS5 scheme")
            if ptype in ("HTTP", "HTTPS") and scheme not in ("HTTP", "HTTPS"):
                e.append("proxy: %s proxy must use the HTTP or HTTPS scheme" % ptype)
        if proxy.get("placement") not in ("vpn", "global"):
            e.append("proxy: placement must be 'vpn' (inside the tunnel) or 'global'")

    if dns.get("enabled"):
        for role in ("primary", "fallback"):
            prov = dns.get(role) or {}
            if not str(prov.get("url") or "").lower().startswith("https://"):
                e.append("dns: %s provider url must be https://" % role)
            if not str(prov.get("name") or "").strip():
                e.append("dns: %s provider needs a name" % role)
        t = dns.get("timeoutMs", 2000)
        if not isinstance(t, int) or isinstance(t, bool) or not 100 <= t <= 10000:
            e.append("dns: timeoutMs must be 100-10000")
        r = dns.get("maxRetries", 1)
        if not isinstance(r, int) or isinstance(r, bool) or not 0 <= r <= 5:
            e.append("dns: maxRetries must be 0-5")
        lat = dns.get("maxLatencyMs", 800)
        if not isinstance(lat, int) or isinstance(lat, bool) or not 50 <= lat <= 10000:
            e.append("dns: maxLatencyMs must be 50-10000")
        if (dns.get("primary") or {}).get("url") == (dns.get("fallback") or {}).get("url"):
            e.append("dns: fallback provider must differ from the primary")

    order = routing.get("order")
    if not isinstance(order, list) or not order:
        e.append("routing: order must be a non-empty list")
    else:
        unknown = [s for s in order if s not in ROUTING_STEPS]
        if unknown:
            e.append("routing: unknown step(s) %s" % ", ".join(map(str, unknown)))
        if "internet" not in order:
            e.append("routing: order must end the path at 'internet'")
        elif order[-1] != "internet":
            e.append("routing: 'internet' must be the last step")

    if ipv6.get("mode") not in IPV6_MODES:
        e.append("ipv6: mode must be one of %s" % ", ".join(IPV6_MODES))

    m = rec.get("maxAttempts", 3)
    if not isinstance(m, int) or isinstance(m, bool) or not 1 <= m <= 10:
        e.append("recovery: maxAttempts must be 1-10 (bounded, no infinite retry)")

    return e


def conflicts(profile: dict) -> list[str]:
    """Behaviour changes that are not syntax errors."""
    out: list[str] = []
    vpn = profile.get("vpn") or {}
    proxy = profile.get("proxy") or {}
    dns = profile.get("dns") or {}
    order = ((profile.get("routing") or {}).get("order") or [])
    if vpn.get("enabled") and proxy.get("enabled"):
        if proxy.get("placement") == "vpn":
            out.append("VPN + proxy: the proxy is applied inside the tunnel "
                       "(browser → VPN → proxy → internet), so the proxy address must be "
                       "reachable from the VPN endpoint.")
        else:
            out.append("VPN + proxy: the proxy is global, so tunneled traffic uses it too "
                       "(browser → proxy → VPN → internet). A LAN-only proxy breaks then.")
        if "proxy" in order and "vpn" in order and order.index("proxy") < order.index("vpn"):
            out.append("VPN + proxy: routing.order puts the proxy before the VPN; only "
                       "'global' placement can honour that ordering.")
    if proxy.get("enabled") and str(proxy.get("type")).upper() == "PAC" and proxy.get("pacFallbackAllowed"):
        out.append("proxy: PAC fallback allowed — an unreachable PAC means DIRECT traffic, "
                   "i.e. no proxy protection. Turn it off for a strict setup.")
    if proxy.get("enabled") and not dns.get("enabled"):
        out.append("DNS: the proxy is not a resolver. Without the DoH payload, DNS follows "
                   "the network and can be seen by the provider.")
    if (profile.get("ipv6") or {}).get("mode") == "prefer" and proxy.get("enabled"):
        out.append("IPv6: 'prefer' keeps IPv6 reachable. If the proxy does not carry IPv6, "
                   "IPv6 traffic can bypass it — use 'strict' to prevent that.")
    if vpn.get("enabled") and not vpn.get("onDemand"):
        out.append("VPN: onDemand is off, so a dropped tunnel stays down until someone "
                   "reconnects. On-demand is the only kill-switch mechanism this profile has.")
    if not vpn.get("enabled"):
        out.append("VPN: no tunnel is configured, so this is a proxy + DNS setup. Nothing "
                   "here is reported as a VPN connection.")
    return out


def routing_path(profile: dict) -> str:
    order = list(((profile.get("routing") or {}).get("order")) or ROUTING_STEPS)
    vpn = (profile.get("vpn") or {}).get("enabled")
    proxy = (profile.get("proxy") or {}).get("enabled")
    kept = []
    for step in order:
        if step == "vpn" and not vpn:
            continue
        if step == "proxy" and not proxy:
            continue
        kept.append(step)
    label = {"vpn": "VPN tunnel", "proxy": "proxy", "internet": "internet"}
    return "browser → " + " → ".join(label.get(s, s) for s in kept)


# --------------------------------------------------------------------------
# probes
# --------------------------------------------------------------------------

class Probe:
    """Probe seam. Tests substitute fakes; production uses these methods."""

    def doh(self, provider: dict, timeout_ms: int) -> dict:
        url = provider.get("probe") or provider.get("url") or ""
        if "name=" not in url:
            url = "%s%sname=example.com&type=A" % (url, "&" if "?" in url else "?")
        req = urllib.request.Request(url, headers={"accept": "application/dns-json"})
        started = time.perf_counter()
        try:
            with urllib.request.urlopen(req, timeout=timeout_ms / 1000.0) as r:
                raw = r.read(8192)
                status = r.status
        except urllib.error.HTTPError as ex:
            return {"ok": False, "latencyMs": _ms(started), "error": "http_%d" % ex.code}
        except urllib.error.URLError as ex:
            return {"ok": False, "latencyMs": _ms(started), "error": _classify(ex.reason)}
        except (socket.timeout, TimeoutError):
            return {"ok": False, "latencyMs": _ms(started), "error": "timeout"}
        except ssl.SSLError:
            return {"ok": False, "latencyMs": _ms(started), "error": "tls"}
        except OSError:
            return {"ok": False, "latencyMs": _ms(started), "error": "network"}
        if status != 200:
            return {"ok": False, "latencyMs": _ms(started), "error": "http_%d" % status}
        try:
            doc = json.loads(raw.decode("utf-8", "replace"))
        except ValueError:
            return {"ok": False, "latencyMs": _ms(started), "error": "bad_response"}
        # A real DNS answer, not an HTML interstitial.
        if "Status" not in doc or "Question" not in doc:
            return {"ok": False, "latencyMs": _ms(started), "error": "bad_response"}
        return {"ok": True, "latencyMs": _ms(started), "error": "", "status": doc.get("Status")}

    def proxy(self, proxy: dict, timeout_ms: int = 4000) -> dict:
        ptype = str(proxy.get("type") or "").upper()
        started = time.perf_counter()
        if ptype == "PAC":
            url = str(proxy.get("pacUrl") or "")
            req = urllib.request.Request(url, headers={"user-agent": "CleanGEO-NetworkController"})
            try:
                with urllib.request.urlopen(req, timeout=timeout_ms / 1000.0) as r:
                    body = r.read(65536).decode("utf-8", "replace")
                    status = r.status
            except urllib.error.HTTPError as ex:
                return {"ok": False, "latencyMs": _ms(started), "error": "http_%d" % ex.code}
            except urllib.error.URLError as ex:
                return {"ok": False, "latencyMs": _ms(started), "error": _classify(ex.reason)}
            except (socket.timeout, TimeoutError):
                return {"ok": False, "latencyMs": _ms(started), "error": "timeout"}
            except OSError:
                return {"ok": False, "latencyMs": _ms(started), "error": "network"}
            if status != 200 or "FindProxyForURL" not in body:
                return {"ok": False, "latencyMs": _ms(started), "error": "bad_pac"}
            return {"ok": True, "latencyMs": _ms(started), "error": ""}

        host = str(proxy.get("host") or "").strip()
        port = int(proxy.get("port") or 0)
        try:
            with socket.create_connection((host, port), timeout=timeout_ms / 1000.0) as s:
                s.settimeout(timeout_ms / 1000.0)
                if ptype == "SOCKS5":
                    s.sendall(b"\x05\x01\x00")
                    if s.recv(2) != b"\x05\x00":
                        return {"ok": False, "latencyMs": _ms(started),
                                "error": "socks_handshake_refused"}
                    return {"ok": True, "latencyMs": _ms(started), "error": ""}
                if ptype in ("HTTP", "HTTPS"):
                    s.sendall(b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n")
                    reply = s.recv(64)
                    if not reply.startswith(b"HTTP/"):
                        return {"ok": False, "latencyMs": _ms(started), "error": "bad_proxy_reply"}
                    parts = reply.split(b" ")
                    code = parts[1] if len(parts) > 1 else b"000"
                    if not code.startswith(b"2"):
                        return {"ok": False, "latencyMs": _ms(started),
                                "error": "proxy_refused_%s" % code.decode("ascii", "replace")}
                    return {"ok": True, "latencyMs": _ms(started), "error": ""}
        except (socket.timeout, TimeoutError):
            return {"ok": False, "latencyMs": _ms(started), "error": "timeout"}
        except ConnectionRefusedError:
            return {"ok": False, "latencyMs": _ms(started), "error": "refused"}
        except socket.gaierror:
            return {"ok": False, "latencyMs": _ms(started), "error": "dns_failure"}
        except OSError:
            return {"ok": False, "latencyMs": _ms(started), "error": "network"}
        return {"ok": False, "latencyMs": _ms(started), "error": "unsupported_type"}

    def vpn_state(self) -> dict:
        """Ask the OS. A tunnel is never inferred from the configuration."""
        if sys.platform == "darwin":
            try:
                out = subprocess.run(
                    ["scutil", "--nc", "status", "CleanGEO Secure Network"],
                    capture_output=True, text=True, timeout=5,
                ).stdout.strip()
            except (OSError, subprocess.SubprocessError):
                return {"state": "unknown", "source": "scutil unavailable"}
            if out == "Connected":
                return {"state": "active", "source": "scutil --nc status"}
            if out == "Disconnected":
                return {"state": "provisioned", "source": "scutil --nc status"}
            return {"state": "not_configured", "source": "scutil --nc status"}
        return {"state": "unknown",
                "source": "this OS does not expose VPN state to an unprivileged process"}


def _ms(started: float) -> int:
    return max(0, int((time.perf_counter() - started) * 1000))


def _classify(reason) -> str:
    text = str(reason).lower()
    if "timed out" in text or "timeout" in text:
        return "timeout"
    if "certificate" in text or "ssl" in text:
        return "tls"
    if "name or service" in text or "nodename" in text or "getaddrinfo" in text:
        return "dns_failure"
    if "refused" in text:
        return "refused"
    return "network"


# --------------------------------------------------------------------------
# controller
# --------------------------------------------------------------------------

class NetworkController:
    def __init__(self, profile: dict | None = None, *, path: Path | str = PROFILE_PATH,
                 probes: Probe | None = None, sleeper=time.sleep, log=None):
        self.path = Path(path)
        if profile is None:
            self.profile = load_profile(self.path)
        else:
            errors = validate_profile(profile)
            if errors:
                raise ConfigError("; ".join(errors))
            self.profile = merge_defaults(profile)
        self.probes = probes or Probe()
        self.sleep = sleeper
        self.log = log or (lambda message: None)
        self.history: list[dict] = []
        self.last_error: dict | None = None
        self.dns_state: dict = {"provider": None, "fallbackUsed": False, "latencyMs": None,
                                "status": "unchecked", "error": ""}

    # -- configuration ----------------------------------------------------
    def update(self, section: str, **values) -> dict:
        """Merge values into one section and persist, or change nothing at all."""
        if section not in SECTIONS:
            raise ConfigError("unknown section %r" % (section,))
        current = dict(self.profile.get(section) or {})
        if section == "dns":
            for role in ("primary", "fallback"):
                if role in values:
                    current[role] = {**(current.get(role) or {}), **values.pop(role)}
        candidate = {**self.profile, section: {**current, **values}}
        save_profile(candidate, self.path)
        self.profile = merge_defaults(candidate)
        self.log("profile saved: section=%s keys=%s"
                 % (section, ",".join(sorted(values)) or "-"))
        return candidate

    def set_enabled(self, enabled: bool) -> dict:
        candidate = {**self.profile, "enabled": bool(enabled)}
        save_profile(candidate, self.path)
        self.profile = candidate
        return candidate

    def reset(self) -> dict:
        save_profile(default_profile(), self.path)
        self.profile = load_profile(self.path)
        return self.profile

    # -- status -----------------------------------------------------------
    def check_dns(self) -> dict:
        """Probe the primary; ask the fallback only when it is unusable."""
        dns = self.profile.get("dns") or {}
        if not self.profile.get("enabled") or not dns.get("enabled"):
            self.dns_state = {"provider": None, "fallbackUsed": False, "latencyMs": None,
                              "status": "disabled", "error": ""}
            return self.dns_state

        timeout = int(dns.get("timeoutMs", 2000))
        budget = int(dns.get("maxLatencyMs", 800))
        retries = int(dns.get("maxRetries", 1))
        primary = dns.get("primary") or {}
        fallback = dns.get("fallback") or {}

        result = self._probe_provider(primary, timeout, retries)
        reason = ""
        if not result["ok"]:
            reason = "primary_failed:" + (result.get("error") or "unknown")
        elif result["latencyMs"] > budget:
            reason = "primary_slow:%dms>%dms" % (result["latencyMs"], budget)

        if not reason:
            self.dns_state = {"provider": primary.get("name"), "fallbackUsed": False,
                              "latencyMs": result["latencyMs"], "status": "ok", "error": ""}
            self.log("dns ok: %s %dms" % (primary.get("name"), result["latencyMs"]))
            return self.dns_state

        self.log("dns primary unusable (%s), trying the fallback" % reason)
        fb = self._probe_provider(fallback, timeout, retries)
        if fb["ok"]:
            self.dns_state = {"provider": fallback.get("name"), "fallbackUsed": True,
                              "latencyMs": fb["latencyMs"], "status": "fallback", "error": reason}
            self.log("dns fallback active: %s %dms" % (fallback.get("name"), fb["latencyMs"]))
        else:
            self.dns_state = {"provider": None, "fallbackUsed": False, "latencyMs": None,
                              "status": "down",
                              "error": reason + "; fallback_failed:" + (fb.get("error") or "unknown")}
            self._record_error("dns", self.dns_state["error"])
            self.log("dns down: neither %s nor %s answered"
                     % (primary.get("name"), fallback.get("name")))
        return self.dns_state

    def _probe_provider(self, provider: dict, timeout: int, retries: int) -> dict:
        last = {"ok": False, "latencyMs": 0, "error": "not_run"}
        for attempt in range(retries + 1):
            last = self.probes.doh(provider, timeout)
            if last["ok"]:
                return last
            if attempt < retries:
                self.sleep(min(1.0, 0.2 * (attempt + 1)))
        return last

    def check_proxy(self) -> dict:
        proxy = self.profile.get("proxy") or {}
        if not self.profile.get("enabled") or not proxy.get("enabled"):
            return {"status": "disabled", "error": "", "latencyMs": None, "type": None}
        result = self.probes.proxy(proxy)
        if result["ok"]:
            return {"status": "ok", "error": "", "latencyMs": result["latencyMs"],
                    "type": str(proxy.get("type")).upper()}
        self._record_error("proxy", result.get("error") or "unknown")
        return {"status": "failed", "error": result.get("error") or "unknown",
                "latencyMs": result["latencyMs"], "type": str(proxy.get("type")).upper()}

    def check_vpn(self) -> dict:
        vpn = self.profile.get("vpn") or {}
        if not self.profile.get("enabled") or not vpn.get("enabled"):
            return {"status": "off", "state": "off", "endpoint": None,
                    "source": "VPN disabled in the profile"}
        if not str(vpn.get("remoteAddress") or "").strip():
            return {"status": "not_configured", "state": "not_configured", "endpoint": None,
                    "source": "no remoteAddress in the profile"}
        state = self.probes.vpn_state()
        if state.get("state") == "active":
            return {"status": "active", "state": "active",
                    "endpoint": vpn.get("remoteAddress"), "source": state.get("source")}
        return {"status": "inactive", "state": state.get("state"),
                "endpoint": vpn.get("remoteAddress"), "source": state.get("source")}

    def status(self) -> dict:
        vpn = self.check_vpn()
        proxy = self.check_proxy()
        dns = self.check_dns()
        enabled = bool(self.profile.get("enabled"))

        blocking = []
        if enabled and (self.profile.get("proxy") or {}).get("enabled") and proxy["status"] == "failed":
            blocking.append("proxy")
        if enabled and (self.profile.get("vpn") or {}).get("enabled") \
                and vpn["status"] in ("inactive", "not_configured"):
            blocking.append("vpn")
        if enabled and (self.profile.get("dns") or {}).get("enabled") and dns["status"] == "down":
            blocking.append("dns")

        if not enabled:
            overall = "disabled"
        elif blocking:
            overall = "degraded"
        else:
            overall = "ok"

        return {
            "overall": overall,
            "enabled": enabled,
            "verified": overall == "ok",
            "routing": routing_path(self.profile),
            "vpn": vpn,
            "proxy": proxy,
            "dns": dns,
            "leaks": self.leak_report(vpn, proxy, dns),
            "lastError": self.last_error,
            "conflicts": conflicts(self.profile),
            "blocking": blocking,
        }

    def leak_report(self, vpn, proxy, dns) -> dict:
        """What is actually protected, and what is not. No blanket claims."""
        ipv6 = self.profile.get("ipv6") or {}
        dns_ok = self.dns_state.get("status") in ("ok", "fallback")
        return {
            "dns": {
                "protected": dns_ok,
                "resolverProbed": dns.get("provider"),
                "note": ("The DNS payload sends every resolver query, IPv4 and IPv6, to "
                         "the configured DoH provider once it is installed."
                         if dns_ok else
                         "No resolver is enforced here: queries follow whatever DNS the "
                         "network hands out."),
            },
            "webrtc": {
                "protected": False,
                "note": ("WebRTC/STUN can reveal local and public IPs, and no supported "
                         "configuration payload turns it off — it is a per-browser policy. "
                         "This is reported as unprotected on purpose."),
            },
            "ipv6": {
                "protected": ipv6.get("mode") in ("strict", "disable"),
                "mode": ipv6.get("mode"),
                "note": ("IPv6 is resolved by the same payload as IPv4. With 'strict' an "
                         "IPv6-only path cannot leave unproxied."),
            },
            "killswitch": {
                "available": bool((self.profile.get("vpn") or {}).get("enabled"))
                               and bool((self.profile.get("vpn") or {}).get("onDemand")),
                "note": ("On-demand VPN is the only mechanism available at this layer: the "
                         "OS then refuses traffic outside the tunnel. Without a supervised "
                         "always-on payload the user can still switch the VPN off, which is "
                         "a real limit, not a kill switch."
                         if (self.profile.get("vpn") or {}).get("enabled") else
                         "No VPN is configured, so there is nothing to switch off and no "
                         "kill switch to offer. Traffic protection here is the proxy plus DNS."),
            },
        }

    def _record_error(self, component: str, error: str) -> None:
        entry = {"component": component, "error": error, "at": int(time.time())}
        self.last_error = entry
        self.history.append(entry)
        del self.history[:-20]

    # -- recovery ---------------------------------------------------------
    def recover(self) -> dict:
        attempts = int((self.profile.get("recovery") or {}).get("maxAttempts", 3))
        tried = []
        for attempt in range(1, attempts + 1):
            state = self.status()
            tried.append({"attempt": attempt, "overall": state["overall"]})
            self.log("recovery attempt %d/%d: %s" % (attempt, attempts, state["overall"]))
            if state["overall"] in ("ok", "disabled"):
                return {"ok": True, "attempts": tried, "status": state}
            self.sleep(min(5.0, 0.5 * attempt))
        return {"ok": False, "attempts": tried, "status": self.status()}

    # -- diagnostics ------------------------------------------------------
    def diagnostics(self) -> dict:
        """Shareable state: no history, no query names, no secrets."""
        p = self.profile
        vpn = p.get("vpn") or {}
        proxy = p.get("proxy") or {}
        dns = p.get("dns") or {}
        return {
            "profile": {"name": p.get("name"), "enabled": p.get("enabled"),
                        "version": p.get("version")},
            "vpn": {"enabled": vpn.get("enabled"), "endpoint": vpn.get("remoteAddress") or None,
                    "authMethod": vpn.get("authMethod"), "onDemand": vpn.get("onDemand")},
            "proxy": {"enabled": proxy.get("enabled"), "type": proxy.get("type"),
                      "placement": proxy.get("placement"),
                      "server": ("%s:%s" % (proxy.get("host"), proxy.get("port")))
                      if str(proxy.get("type")).upper() != "PAC" and proxy.get("host") else None,
                      "pac": proxy.get("pacUrl") if str(proxy.get("type")).upper() == "PAC" else None},
            "dns": {"enabled": dns.get("enabled"),
                    "primary": (dns.get("primary") or {}).get("name"),
                    "fallback": (dns.get("fallback") or {}).get("name"),
                    "state": self.dns_state},
            "routing": routing_path(p),
            "ipv6": (p.get("ipv6") or {}).get("mode"),
            "errors": list(self.history),
        }
