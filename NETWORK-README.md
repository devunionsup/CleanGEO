# CleanGEO Secure Network — one profile for VPN, proxy and DNS

One file, `netprofile.json`, holds every network setting. The controller, the
installable profile and the panel all read it, so VPN, proxy and DNS cannot
drift into three separate configurations.

## What is in here

| File | What it does |
|---|---|
| `netprofile.json` | The unified profile: VPN, proxy, DoH, routing order, IPv6, recovery |
| `netcontroller.py` | `NetworkController` — config, probes, status, recovery, diagnostics |
| `build_network_profile.py` | Turns the profile into one installable `.mobileconfig` |
| `build_network_panel.py` | Renders the network panel (`network-panel.html`) |
| `cleangeo-network.mobileconfig` | The generated profile (regenerate, don't hand-edit) |
| `test_network.py` | 55 tests: unit + live DNS/proxy probes |

```bash
python test_network.py                 # unit tests, no network
python test_network.py --integration   # + live DoH, dead-proxy, PAC checks
python build_network_profile.py        # -> cleangeo-network.mobileconfig
python build_network_panel.py          # -> network-panel.html with live status
```

## Architecture, and why it is a configuration profile

There is **no Electron app** in this repository. The CleanGEO browser was
removed in the previous commits; what is left is the block list. So there was
no main process, preload script, Chromium session or existing PAC wiring to
integrate with, and requirements written for an Electron main process could
not be met by inspecting code that does not exist.

Rather than mock that layer, the feature is built on the layer that actually
controls traffic on the platforms CleanGEO targets (iOS, iPadOS, macOS): a
**configuration profile**. It carries:

- `com.apple.dnsSettings.managed` — DNS over HTTPS for the whole system
- `com.apple.vpn.managed` with `VPNType: IKEv2` — a real tunnel
- `Proxies` inside that VPN payload — the proxy, and therefore the ordering

That last point is the important one. Apple only exposes proxy keys **inside**
a VPN payload; a standalone proxy payload always sits outside the tunnel. So
these are the orders the platform can honour:

| Setup | Order |
|---|---|
| proxy only | browser → proxy → internet |
| VPN + `placement: vpn` | browser → VPN → proxy → internet |
| VPN + `placement: global` | browser → proxy → VPN → internet |

Anything else is refused by `build_network_profile.py` instead of being
written into a file that would quietly do something different.

If CleanGEO is later shipped as an Electron app, the controller is the part to
reuse: `NetworkController` is plain Python with a probe seam and no UI, so the
same profile can drive `session.setProxy`, PAC generation and status. Electron's
session proxy would still not be a system-wide VPN — that needs a real tunnel
from the OS or a VPN client.

## Reporting rules (the part that matters)

- **Nothing is "connected" without a successful probe.** `status()` probes the
  resolver, the proxy and (via `scutil` on macOS) the tunnel. A profile that
  merely names a VPN server reports `not_configured` or `inactive`.
- **One resolver at a time.** The primary is probed; the fallback is contacted
  only when the primary fails or exceeds `maxLatencyMs`. `test_network.py`
  asserts the fallback is never queried while the primary is healthy.
- **Retries are bounded.** `maxRetries` applies per provider and
  `recovery.maxAttempts` caps the reconnect loop, so no infinite retry.
- **Failures never rewrite your settings.** A dead proxy or resolver records an
  error and leaves `netprofile.json` untouched.
- **Diagnostics carry no secrets.** No visited hostnames, no DNS question names,
  no usernames or tokens. `test_network.py` asserts this.
- **WebRTC is reported as unprotected**, because no configuration payload can
  turn it off. It is a per-browser policy.
- **The kill switch is on-demand VPN, and nothing more.** With `onDemand` on,
  the OS refuses traffic outside the tunnel. Without a supervised always-on
  payload the user can still switch the VPN off. A true always-on kill switch
  needs device supervision and an MDM; a profile alone cannot provide it, and
  the panel says so instead of showing a switch that does nothing.

## Configuration

```json
"dns": {
  "primary":  { "url": "https://dns.adguard-dns.com/dns-query" },
  "fallback": { "url": "https://security.cloudflare-dns.com/dns-query" },
  "timeoutMs": 2000, "maxLatencyMs": 800, "maxRetries": 1
}
```

Proxy types: `PAC`, `HTTP`, `HTTPS`, `SOCKS5`. A PAC URL must be `https://`
(a plain-http PAC can be rewritten in transit). `pacFallbackAllowed: false`
means an unreachable PAC does not silently become DIRECT traffic.

IPv6: `prefer`, `strict` or `disable`. The DNS payload answers for IPv4 and
IPv6 alike; `strict` keeps an IPv6-only path from leaving unproxied.

## Panel

`network-panel.html` shows the live state of each component, lists the leak
status honestly, and edits the profile. The page validates the same rules the
controller does, then writes `netprofile.json` as a download; apply it with:

```bash
python build_network_panel.py --apply netprofile.json
```

## Known limits

- Installing a `.mobileconfig` needs user approval in Settings (or MDM). The
  scripts cannot install it for you.
- The VPN payload needs a real IKEv2 server, credentials or a certificate.
  Without them the profile is proxy + DNS only, and says exactly that.
- `scutil --nc status` is macOS-only. On other systems the VPN state reads
  `unknown` rather than being guessed.
- DoH here protects the system resolver. It does not protect other
  applications that bring their own resolver.
