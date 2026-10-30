#!/usr/bin/env python3
"""Tests for the unified network profile.

  unit         fast, deterministic, fake probes. Always run.
  integration  real sockets: DoH answers, a dead proxy port, the PAC URL.
               Run with --integration; they skip when the network is unusable.

  python test_network.py
  python test_network.py --integration
"""
from __future__ import annotations

import json
import plistlib
import socket
import sys
import tempfile
from pathlib import Path

import netcontroller as nc
import build_network_profile as bp

FAILS: list[str] = []
RUN = 0


class Skip(Exception):
    """Not runnable here; not a failure."""


def test(fn):
    global RUN
    RUN += 1
    name = fn.__name__
    try:
        fn()
    except Skip as exc:
        print("skip %s — %s" % (name, exc))
    except AssertionError as exc:
        FAILS.append("%s: %s" % (name, exc))
        print("FAIL %s — %s" % (name, exc))
    except Exception as exc:  # noqa: BLE001 - a crash is a failure too
        FAILS.append("%s: %s: %s" % (name, type(exc).__name__, exc))
        print("FAIL %s — %s: %s" % (name, type(exc).__name__, exc))
    else:
        print("ok   %s" % name)
    return fn


class FakeProbes(nc.Probe):
    """Deterministic probe seam."""

    def __init__(self, doh_ok=True, doh_latency=120, doh_error="timeout",
                 primary_ok=True, proxy_ok=True, proxy_error="refused",
                 vpn="active", calls=None):
        self.doh_ok = doh_ok
        self.doh_latency = doh_latency
        self.doh_error = doh_error
        self.primary_ok = primary_ok
        self.proxy_ok = proxy_ok
        self.proxy_error = proxy_error
        self.vpn = vpn
        self.calls = calls if calls is not None else []

    def doh(self, provider, timeout_ms):
        self.calls.append(("doh", provider.get("name"), timeout_ms))
        if provider.get("name") == "AdGuard" and not self.primary_ok:
            return {"ok": False, "latencyMs": 0, "error": self.doh_error}
        if self.doh_ok:
            return {"ok": True, "latencyMs": self.doh_latency, "error": ""}
        return {"ok": False, "latencyMs": 0, "error": self.doh_error}

    def proxy(self, proxy, timeout_ms=4000):
        self.calls.append(("proxy", proxy.get("type"), timeout_ms))
        if self.proxy_ok:
            return {"ok": True, "latencyMs": 40, "error": ""}
        return {"ok": False, "latencyMs": 0, "error": self.proxy_error}

    def vpn_state(self):
        self.calls.append(("vpn", None, None))
        return {"state": self.vpn, "source": "fake"}


def make(section: str | None = None, **values):
    def apply(p: dict) -> dict:
        if section is None:
            return {**p, **values}
        return {**p, section: {**(p.get(section) or {}), **values}}
    return apply


def profile_with(*edits) -> dict:
    p = nc.default_profile()
    for edit in edits:
        p = edit(p)
    return p


def base() -> dict:
    """The shipped profile: proxy on, VPN off."""
    return nc.default_profile()


def vpn_on(p: dict) -> dict:
    return {**p, "vpn": {**p["vpn"], "enabled": True,
                         "remoteAddress": "vpn.example.net",
                         "remoteIdentifier": "vpn.example.net"}}


def controller(p: dict, probes=None, path=None) -> nc.NetworkController:
    """A controller backed by a real file, as after a restart."""
    target = Path(path or (Path(tempfile.mkdtemp()) / "netprofile.json"))
    if not target.exists():
        nc.save_profile(p, target)
    return nc.NetworkController(nc.load_profile(target), path=target,
                                probes=probes or FakeProbes(), sleeper=lambda s: None)


# --------------------------------------------------------------------------
# persistence
# --------------------------------------------------------------------------

@test
def profile_round_trips_every_section():
    tmp = Path(tempfile.mkdtemp()) / "netprofile.json"
    p = profile_with(make("proxy", type="SOCKS5", host="10.0.0.5", port=1080, scheme="SOCKS5"),
                     make("vpn", enabled=True, remoteAddress="vpn.example.net",
                          remoteIdentifier="vpn.example.net"))
    nc.save_profile(p, tmp)
    back = nc.load_profile(tmp)
    assert back["proxy"]["host"] == "10.0.0.5"
    assert back["vpn"]["remoteAddress"] == "vpn.example.net"
    assert tmp.read_text(encoding="utf-8").endswith("\n")


@test
def missing_file_yields_defaults_without_writing():
    tmp = Path(tempfile.mkdtemp()) / "absent.json"
    p = nc.load_profile(tmp)
    assert p["name"] == "CleanGEO Secure Network"
    assert not tmp.exists(), "load must not create a file"


@test
def merge_defaults_does_not_leak_keys_into_a_section():
    merged = nc.merge_defaults({"proxy": {"host": "p.example"}})
    assert "version" not in merged["proxy"], sorted(merged["proxy"])
    assert "vpn" not in merged["proxy"], sorted(merged["proxy"])
    assert set(merged["dns"]["primary"]) == {"name", "url", "probe"}, merged["dns"]["primary"]
    assert merged["dns"]["primary"]["url"] == "https://dns.adguard-dns.com/dns-query"


@test
def repeated_save_and_reload_does_not_nest_the_profile():
    tmp = Path(tempfile.mkdtemp()) / "netprofile.json"
    p = profile_with(make("proxy", type="HTTP", host="p.example", port=3128, scheme="HTTP"))
    for _ in range(3):
        nc.save_profile(nc.load_profile(tmp) if tmp.exists() else nc.merge_defaults(p), tmp)
    final = nc.load_profile(tmp)
    assert final["proxy"]["host"] == "p.example"
    assert set(final["proxy"]) <= set(nc.default_profile()["proxy"]), sorted(final["proxy"])


@test
def partial_profile_gets_defaults_for_absent_keys():
    merged = nc.merge_defaults({"proxy": {"host": "p.example"}})
    assert merged["proxy"]["host"] == "p.example"
    assert merged["proxy"]["type"] == "PAC"
    assert merged["dns"]["primary"]["name"] == "AdGuard"


@test
def update_persists_and_survives_restart():
    c = controller(nc.default_profile())
    c.update("proxy", type="HTTP", host="proxy.local", port=3128, scheme="HTTP")
    restarted = nc.NetworkController(nc.load_profile(c.path), path=c.path,
                                     probes=FakeProbes(), sleeper=lambda s: None)
    assert restarted.profile["proxy"]["host"] == "proxy.local"
    assert restarted.profile["proxy"]["type"] == "HTTP"


@test
def update_is_rejected_whole_and_leaves_the_file_alone():
    c = controller(nc.default_profile())
    before = c.path.read_text(encoding="utf-8")
    try:
        c.update("proxy", type="HTTP", host="", port=3128)
    except nc.ConfigError as exc:
        assert "host" in str(exc), exc
    else:
        raise AssertionError("an empty host must be rejected")
    assert c.path.read_text(encoding="utf-8") == before


@test
def disabled_profile_persists_as_disabled():
    c = controller(nc.default_profile())
    c.set_enabled(False)
    assert nc.load_profile(c.path)["enabled"] is False


@test
def unknown_section_is_refused():
    c = controller(nc.default_profile())
    try:
        c.update("firewall", enabled=True)
    except nc.ConfigError:
        return
    raise AssertionError("an unknown section must be refused")


# --------------------------------------------------------------------------
# validation
# --------------------------------------------------------------------------

@test
def validation_reports_every_problem_at_once():
    bad = {
        "name": "",
        "vpn": {"enabled": True, "remoteAddress": "", "authMethod": "Nonsense"},
        "proxy": {"enabled": True, "type": "GOPHER", "host": "", "port": 99999},
        "dns": {"enabled": True, "timeoutMs": 5, "maxRetries": 99, "maxLatencyMs": 1,
                "primary": {"name": "a", "url": "http://x"},
                "fallback": {"name": "", "url": "http://x"}},
        "routing": {"order": ["teleport", "internet"]},
        "ipv6": {"mode": "sometimes"},
        "recovery": {"maxAttempts": 500},
    }
    errors = nc.validate_profile(bad)
    for needle in ("name is empty", "remoteAddress", "authMethod", "unknown type",
                   "port must be", "timeoutMs", "maxRetries", "maxLatencyMs",
                   "https://", "teleport", "ipv6", "maxAttempts"):
        assert any(needle in e for e in errors), "missing %r in %s" % (needle, errors)


@test
def routing_must_end_at_internet():
    good = profile_with(make("routing", order=["vpn", "proxy", "internet"]))
    assert nc.validate_profile(good) == [], nc.validate_profile(good)
    bad = profile_with(make("routing", order=["vpn", "proxy"]))
    errors = nc.validate_profile(bad)
    assert any("internet" in e for e in errors), errors


@test
def socks5_with_an_http_scheme_is_refused():
    p = profile_with(make("proxy", type="SOCKS5", host="h.example", port=1080, scheme="HTTP"))
    assert any("SOCKS5" in e for e in nc.validate_profile(p))


@test
def plaintext_pac_url_is_refused():
    p = profile_with(make("proxy", type="PAC", pacUrl="http://example.com/p.pac"))
    assert any("https://" in e for e in nc.validate_profile(p))


@test
def duplicate_dns_providers_are_refused():
    p = nc.default_profile()
    p["dns"]["fallback"] = dict(p["dns"]["primary"])
    assert any("must differ" in e for e in nc.validate_profile(p))


@test
def boolean_is_not_a_valid_port_or_timeout():
    p = profile_with(make("proxy", type="HTTP", host="h.example", port=True, scheme="HTTP"))
    assert any("port must be" in e for e in nc.validate_profile(p))
    q = profile_with(make("dns", timeoutMs=True))
    assert any("timeoutMs" in e for e in nc.validate_profile(q))


# --------------------------------------------------------------------------
# DNS selection and fallback
# --------------------------------------------------------------------------

@test
def healthy_primary_is_the_only_one_queried():
    probes = FakeProbes(doh_ok=True, doh_latency=100)
    c = controller(nc.default_profile(), probes)
    state = c.check_dns()
    assert state["status"] == "ok", state
    assert state["provider"] == "AdGuard"
    assert state["fallbackUsed"] is False
    names = [call[1] for call in probes.calls if call[0] == "doh"]
    assert names == ["AdGuard"], names


@test
def fallback_is_queried_only_after_the_primary_fails():
    probes = FakeProbes(primary_ok=False, doh_ok=True)
    c = controller(nc.default_profile(), probes)
    state = c.check_dns()
    assert state["status"] == "fallback", state
    assert state["provider"] == "Cloudflare Security"
    assert state["fallbackUsed"] is True
    names = [call[1] for call in probes.calls if call[0] == "doh"]
    assert names[0] == "AdGuard" and names[-1] == "Cloudflare Security", names


@test
def slow_primary_triggers_fallback():
    probes = FakeProbes(doh_latency=5000)
    c = controller(profile_with(make("dns", maxLatencyMs=800)), probes)
    state = c.check_dns()
    assert state["status"] == "fallback", state
    assert "primary_slow" in state["error"], state


@test
def timeout_and_retries_are_bounded():
    probes = FakeProbes(doh_ok=False, doh_error="timeout", primary_ok=False)
    c = controller(profile_with(make("dns", maxRetries=2, timeoutMs=1000)), probes)
    state = c.check_dns()
    assert state["status"] == "down", state
    doh_calls = [x for x in probes.calls if x[0] == "doh"]
    # 1 primary + 2 retries + 1 fallback + 2 retries = 6, never more.
    assert len(doh_calls) == 6, doh_calls
    assert all(x[2] == 1000 for x in doh_calls), doh_calls


@test
def both_providers_down_is_reported_as_down_and_recorded():
    probes = FakeProbes(doh_ok=False, primary_ok=False)
    c = controller(nc.default_profile(), probes)
    state = c.check_dns()
    assert state["status"] == "down"
    assert state["provider"] is None, "a provider must not be claimed when it failed"
    assert c.last_error["component"] == "dns"


@test
def disabled_dns_is_not_probed():
    probes = FakeProbes()
    c = controller(profile_with(make("dns", enabled=False)), probes)
    assert c.check_dns()["status"] == "disabled"
    assert not [x for x in probes.calls if x[0] == "doh"]


@test
def master_switch_off_stops_all_probes():
    probes = FakeProbes()
    c = controller(profile_with(lambda p: {**p, "enabled": False}), probes)
    st = c.status()
    assert st["overall"] == "disabled", st
    assert probes.calls == [], probes.calls


# --------------------------------------------------------------------------
# proxy
# --------------------------------------------------------------------------

@test
def proxy_failure_is_never_reported_as_a_connection():
    c = controller(nc.default_profile(), FakeProbes(proxy_ok=False, proxy_error="refused"))
    st = c.status()
    assert st["proxy"]["status"] == "failed", st
    assert st["overall"] == "degraded", st
    assert st["verified"] is False
    assert "proxy" in st["blocking"]


@test
def dead_proxy_records_the_error():
    c = controller(nc.default_profile(), FakeProbes(proxy_ok=False, proxy_error="refused"))
    c.check_proxy()
    assert c.last_error["component"] == "proxy"
    assert "refused" in c.last_error["error"]


@test
def ok_proxy_needs_a_successful_probe():
    c = controller(nc.default_profile(), FakeProbes(proxy_ok=True))
    assert c.check_proxy()["status"] == "ok"
    assert c.last_error is None


# --------------------------------------------------------------------------
# VPN
# --------------------------------------------------------------------------

@test
def unconfigured_vpn_says_off_not_connected():
    c = controller(nc.default_profile(), FakeProbes(vpn="active"))
    st = c.check_vpn()
    assert st["status"] == "off", st
    assert st["endpoint"] is None


@test
def enabled_vpn_without_a_server_is_not_configured_and_cannot_be_saved():
    broken = profile_with(make("vpn", enabled=True))
    try:
        nc.save_profile(broken, Path(tempfile.mkdtemp()) / "p.json")
    except nc.ConfigError:
        pass
    else:
        raise AssertionError("a VPN without a server must not be storable")
    loose_path = Path(tempfile.mkdtemp()) / "none.json"
    try:
        nc.NetworkController(broken, path=loose_path, probes=FakeProbes(vpn="active"),
                             sleeper=lambda s: None)
    except nc.ConfigError as exc:
        assert "remoteAddress" in str(exc), exc
    else:
        raise AssertionError("the controller must refuse a VPN with no server")
    # A hand-edited file can still reach that state; status must still tell the
    # truth instead of echoing what the OS probe says.
    raw = Path(tempfile.mkdtemp()) / "hand.json"
    raw.write_text(json.dumps({"enabled": True,
                               "vpn": {"enabled": True, "remoteAddress": ""}}),
                   encoding="utf-8")
    loose = nc.NetworkController(path=raw, probes=FakeProbes(vpn="active"),
                                 sleeper=lambda s: None)
    st = loose.check_vpn()
    assert st["status"] == "not_configured", st
    assert st["endpoint"] is None


@test
def vpn_is_active_only_when_the_os_reports_the_tunnel():
    up = controller(profile_with(vpn_on), FakeProbes(vpn="active"))
    assert up.check_vpn()["status"] == "active"
    assert up.check_vpn()["endpoint"] == "vpn.example.net"

    down = controller(profile_with(vpn_on), FakeProbes(vpn="Disconnected"))
    st = down.check_vpn()
    assert st["status"] == "inactive", st
    assert down.status()["overall"] == "degraded"


@test
def configuration_alone_never_yields_a_verified_connection():
    c = controller(profile_with(vpn_on), FakeProbes(vpn="provisioned"))
    st = c.status()
    assert st["verified"] is False
    assert st["vpn"]["status"] == "inactive"


# --------------------------------------------------------------------------
# conflicts and routing order
# --------------------------------------------------------------------------

@test
def vpn_plus_proxy_reports_the_placement_conflict():
    p = profile_with(vpn_on, make("proxy", enabled=True, type="HTTP", host="p.example",
                                  port=3128, scheme="HTTP"))
    text = " ".join(nc.conflicts(p))
    assert "proxy is applied inside the tunnel" in text, text


@test
def global_placement_conflict_is_reported():
    p = profile_with(vpn_on, make("proxy", enabled=True, type="HTTP", host="p.example",
                                  port=3128, scheme="HTTP", placement="global"))
    assert "proxy is global" in " ".join(nc.conflicts(p))


@test
def pac_fallback_is_flagged_as_leaking():
    p = profile_with(make("proxy", pacFallbackAllowed=True))
    assert any("PAC fallback" in c for c in nc.conflicts(p))


@test
def missing_dns_is_flagged_even_with_a_proxy():
    p = profile_with(make("dns", enabled=False))
    assert any("DNS" in c for c in nc.conflicts(p))


@test
def routing_label_tracks_what_is_enabled():
    both = profile_with(vpn_on, make("proxy", enabled=True, placement="vpn"))
    assert nc.routing_path(both) == "browser → proxy → VPN tunnel → internet", nc.routing_path(both)
    assert bp.nested_order(both) == "browser → vpn → proxy → internet"
    assert nc.routing_path(base()) == "browser → proxy → internet"
    assert nc.routing_path(profile_with(make("proxy", enabled=False))) == "browser → internet"


# --------------------------------------------------------------------------
# failure handling
# --------------------------------------------------------------------------

@test
def recovery_is_bounded_and_reports_the_real_state():
    probes = FakeProbes(proxy_ok=False, doh_ok=False, primary_ok=False)
    c = controller(profile_with(make("recovery", maxAttempts=2)), probes)
    result = c.recover()
    assert result["ok"] is False
    assert len(result["attempts"]) == 2, result["attempts"]
    assert result["status"]["overall"] == "degraded"


@test
def recovery_stops_as_soon_as_the_connection_is_real():
    calls = {"n": 0}

    class Flaky(FakeProbes):
        def proxy(self, proxy, timeout_ms=4000):
            calls["n"] += 1
            ok = calls["n"] > 1
            return {"ok": ok, "latencyMs": 10, "error": "" if ok else "refused"}

    c = controller(profile_with(make("recovery", maxAttempts=4)), Flaky())
    result = c.recover()
    assert result["ok"] is True, result
    assert len(result["attempts"]) == 2, result["attempts"]


@test
def a_failure_never_rewrites_the_user_configuration():
    c = controller(profile_with(make("recovery", maxAttempts=2)), FakeProbes(proxy_ok=False))
    before = c.path.read_text(encoding="utf-8")
    c.recover()
    assert c.path.read_text(encoding="utf-8") == before


@test
def error_history_is_capped():
    c = controller(nc.default_profile(), FakeProbes(proxy_ok=False))
    for _ in range(40):
        c.check_proxy()
    assert len(c.history) <= 20, len(c.history)


# --------------------------------------------------------------------------
# diagnostics privacy
# --------------------------------------------------------------------------

@test
def kill_switch_is_not_offered_without_a_tunnel():
    no_vpn = controller(nc.default_profile(), FakeProbes()).status()
    assert no_vpn["leaks"]["killswitch"]["available"] is False, no_vpn["leaks"]["killswitch"]
    with_vpn = controller(profile_with(vpn_on), FakeProbes(vpn="active")).status()
    assert with_vpn["leaks"]["killswitch"]["available"] is True


@test
def webrtc_is_never_claimed_as_protected():
    st = controller(nc.default_profile(), FakeProbes()).status()
    assert st["leaks"]["webrtc"]["protected"] is False


@test
def diagnostics_carry_no_secrets_or_query_names():
    p = profile_with(vpn_on,
                     make("proxy", type="HTTP", host="p.example", port=3128,
                          scheme="HTTP", username="alice"))
    p["vpn"] = {**p["vpn"], "username": "bob"}
    c = controller(p, FakeProbes())
    blob = json.dumps(c.diagnostics())
    for secret in ("alice", "bob", "password", "token", "example.com&type", "Animal"):
        assert secret not in blob, "%r leaked into diagnostics" % secret


# --------------------------------------------------------------------------
# generated configuration profile
# --------------------------------------------------------------------------

@test
def profile_payload_carries_dns_and_vpn_layers():
    doc = bp.build(nc.default_profile())
    types = [p["PayloadType"] for p in doc["PayloadContent"]]
    assert "com.apple.dnsSettings.managed" in types, types
    assert "com.apple.vpn.managed" in types, types
    dns = [p for p in doc["PayloadContent"] if p["PayloadType"] == "com.apple.dnsSettings.managed"][0]
    assert dns["DNSSettings"]["ServerURL"] == "https://dns.adguard-dns.com/dns-query"
    assert dns["DNSSettings"]["DNSProtocol"] == "HTTPS"


@test
def generated_profile_is_valid_plist_and_reparses():
    doc = bp.build(nc.default_profile())
    tmp = Path(tempfile.mkdtemp()) / "p.mobileconfig"
    with tmp.open("wb") as f:
        plistlib.dump(doc, f)
    with tmp.open("rb") as f:
        back = plistlib.load(f)
    assert back["PayloadIdentifier"] == "tv.cleangeo.network"


@test
def proxy_inside_tunnel_payload_when_vpn_is_on():
    p = profile_with(vpn_on, make("proxy", enabled=True, type="HTTP", host="p.example",
                                  port=3128, scheme="HTTP"))
    doc = bp.build(p)
    vpn = [x for x in doc["PayloadContent"] if x["PayloadType"] == "com.apple.vpn.managed"][0]
    assert vpn["Proxies"]["HTTPEnable"] == 1
    assert vpn["Proxies"]["HTTPProxy"] == "p.example"
    assert vpn["IKEv2"]["RemoteAddress"] == "v.example.net" or True
    assert vpn["IKEv2"]["RemoteAddress"] == "vpn.example.net"


@test
def pac_proxy_settings_are_expressed_in_the_payload():
    p = profile_with(make("proxy", type="PAC", pacUrl="https://example.org/x.pac"))
    doc = bp.build(p)
    vpn = [x for x in doc["PayloadContent"] if x["PayloadType"] == "com.apple.vpn.managed"][0]
    assert vpn["Proxies"]["ProxyAutoConfigEnable"] == 1
    assert vpn["Proxies"]["ProxyAutoConfigURLString"] == "https://example.org/x.pac"
    assert vpn["Proxies"]["ProxyAutoConfigFallbackAllowed"] == 0, "fallback must be off"


@test
def socks5_proxy_maps_to_a_socks_payload():
    p = profile_with(make("proxy", type="SOCKS5", host="s.example", port=1080, scheme="SOCKS5"))
    doc = bp.build(p)
    vpn = [x for x in doc["PayloadContent"] if x["PayloadType"] == "com.apple.vpn.managed"][0]
    assert vpn["Proxies"]["SOCKSEnable"] == 1
    assert vpn["Proxies"]["SOCKSPort"] == 1080
    assert vpn["Proxies"]["HTTPEnable"] == 0


@test
def proxy_only_payload_is_labelled_as_not_a_tunnel():
    doc = bp.build(nc.default_profile())
    vpn = [x for x in doc["PayloadContent"] if x["PayloadType"] == "com.apple.vpn.managed"][0]
    assert "no VPN tunnel" in vpn["PayloadDescription"], vpn["PayloadDescription"]


@test
def disabled_profile_is_not_installable():
    try:
        bp.build(profile_with(lambda p: {**p, "enabled": False}))
    except bp.Unsupported:
        return
    raise AssertionError("a disabled profile must not produce an installable file")


@test
def profile_with_nothing_enabled_is_not_installable():
    p = profile_with(make("proxy", enabled=False), make("dns", enabled=False))
    try:
        bp.build(p)
    except bp.Unsupported:
        return
    raise AssertionError("a profile with no layer must not be installable")


@test
def ipv6_disable_mode_changes_the_dns_payload():
    doc = bp.build(profile_with(make("ipv6", mode="disable")))
    dns = [x for x in doc["PayloadContent"] if x["PayloadType"] == "com.apple.dnsSettings.managed"][0]
    assert dns["DNSSettings"]["SupplementalMatchDomains"] == []


# --------------------------------------------------------------------------
# socks5 handshake, without a listening socket
# --------------------------------------------------------------------------

@test
def socks5_handshake_is_verified_not_assumed():
    class FakeSock:
        def __init__(self, reply):
            self.reply = reply
            self.sent = b""

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def settimeout(self, t):
            pass

        def sendall(self, data):
            self.sent += data

        def recv(self, n):
            return self.reply

    import netcontroller
    p = profile_with(make("proxy", enabled=True, type="SOCKS5", host="s.example",
                          port=1080, scheme="SOCKS5"))
    real = netcontroller.socket.create_connection
    try:
        good = FakeSock(b"\x05\x00")
        netcontroller.socket.create_connection = lambda addr, timeout=None: good
        ok = nc.Probe().proxy(p["proxy"])
        assert ok["ok"] is True, ok
        assert good.sent == b"\x05\x01\x00", good.sent

        bad = FakeSock(b"\x05\xff")
        netcontroller.socket.create_connection = lambda addr, timeout=None: bad
        refused = nc.Probe().proxy(p["proxy"])
        assert refused["ok"] is False, refused
        assert refused["error"] == "socks_handshake_refused", refused
    finally:
        netcontroller.socket.create_connection = real


# --------------------------------------------------------------------------
# integration — real network
# --------------------------------------------------------------------------

def needs_network() -> None:
    if "--integration" not in sys.argv:
        raise Skip("needs --integration")


@test
def live_doh_primary_answers():
    needs_network()
    state = controller(nc.default_profile(), nc.Probe()).check_dns()
    assert state["status"] in ("ok", "fallback"), state
    assert state["provider"], state
    print("     live resolver: %s %dms (%s)"
          % (state["provider"], state["latencyMs"], state["error"] or "healthy"))


@test
def live_doh_falls_back_when_the_primary_probe_host_is_dead():
    needs_network()
    p = profile_with(make("dns", timeoutMs=3000, maxRetries=0))
    p["dns"]["primary"] = {"name": "AdGuard",
                           "url": "https://dns.adguard-dns.com/dns-query",
                           "probe": "https://127.0.0.1:9/resolve"}
    state = controller(p, nc.Probe()).check_dns()
    assert state["status"] == "fallback", state
    assert state["provider"] == "Cloudflare Security", state


@test
def live_proxy_probe_detects_a_closed_port():
    needs_network()
    p = profile_with(make("proxy", enabled=True, type="HTTP", host="127.0.0.1",
                          port=9, scheme="HTTP"))
    state = controller(p, nc.Probe()).check_proxy()
    assert state["status"] == "failed", state
    assert state["error"], state


@test
def live_pac_url_in_the_profile_is_fetchable():
    needs_network()
    state = controller(nc.default_profile(), nc.Probe()).check_proxy()
    assert state["status"] == "ok", state


def main() -> int:
    print("\n%d tests, %d failed" % (RUN, len(FAILS)))
    for f in FAILS:
        print("  - %s" % f)
    return 1 if FAILS else 0


if __name__ == "__main__":
    sys.exit(main())
