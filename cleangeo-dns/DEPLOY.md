# Deploying the CleanGEO private DoH server

Target: a small VPS (1 vCPU, 512 MB is enough) with a domain you control.
Commands assume Debian/Ubuntu. Replace `dns.cleangeo.net` with your domain.

## 0. What you need first

- A domain, and the ability to create an `A`/`AAAA` record for `dns.<domain>`.
- A VPS with a public IPv4 address (IPv6 optional).
- Ports 443 open. Port 53 is **not** needed for DoH; the server makes outbound
  queries to authoritative servers on 53.

DNS is not circular here: the endpoint's own hostname must resolve through a
resolver the client already has, because DoH cannot bootstrap itself.
`browser_integration.py` emits the `EXCLUDE` rule that handles this in Chromium.

## 1. Point the hostname at the server

```
dns.cleangeo.net.   300   IN   A      203.0.113.10
```

Wait for propagation, and confirm before requesting a certificate:

```
dig +short dns.cleangeo.net
```

## 2. Install

```
sudo apt update && sudo apt install -y python3 python3-venv python3-pip
sudo useradd --system --home /opt/cleangeo --shell /usr/sbin/nologin cleangeo
sudo -u cleangeo python3 -m venv /opt/cleangeo/venv
sudo -u cleangeo /opt/cleangeo/venv/bin/pip install cryptography h2
sudo install -d -o cleangeo -g cleangeo -m 700 /opt/cleangeo/app
sudo cp -r cleangeo-dns/* /opt/cleangeo/app/
sudo chown -R cleangeo:cleangeo /opt/cleangeo/app
```

The two real dependencies are `cryptography` (DNSSEC signatures, TLS bits) and
`h2` (HTTP/2). Everything else is the standard library.

## 3. Certificate

Production path — Let's Encrypt, with renewal:

```
sudo apt install -y certbot
sudo certbot certonly --standalone -d dns.cleangeo.net
```

That writes `/etc/letsencrypt/live/dns.cleangeo.net/fullchain.pem` and
`privkey.pem`. The server accepts this layout directly via `--cert-dir`.

Permissions: certbot already sets the key to `0600`. The server **refuses to
start** if either file is group- or world-readable, so a wrong `chmod` fails
loudly instead of silently exposing the key.

Renewal is a cron/timer job certbot installs. Verify it:

```
sudo systemctl list-timers | grep certbot
sudo certbot renew --dry-run
```

Reload the server after renewal — the TLS context is built at startup, so a new
certificate needs a restart:

```
sudo systemctl restart cleangeo-dns
```

Check remaining validity at any time:

```
/opt/cleangeo/venv/bin/python /opt/cleangeo/app/keys.py inspect \
  /etc/letsencrypt/live/dns.cleangeo.net/fullchain.pem
```

## 4. Configuration check before starting

```
cd /opt/cleangeo/app
sudo -u cleangeo /opt/cleangeo/venv/bin/python server.py check \
  --domain dns.cleangeo.net \
  --cert-dir /etc/letsencrypt/live/dns.cleangeo.net
```

Expected output includes the certificate subject, days remaining, and
`configuration OK`. If DNSSEC is reported as *required* with 2 trust anchors and
13 root hints, that is correct.

## 5. Run it

```
sudo -u cleangeo /opt/cleangeo/venv/bin/python /opt/cleangeo/app/server.py serve \
  --host 0.0.0.0 --port 443 --domain dns.cleangeo.net \
  --cert-dir /etc/letsencrypt/live/dns.cleangeo.net
```

Port 443 needs privileges; either run as root with `CAP_NET_BIND_SERVICE`, or
put a port-forward in front. The cleanest option is the systemd unit below with
the capability granted.

### systemd unit

`/etc/systemd/system/cleangeo-dns.service`:

```ini
[Unit]
Description=CleanGEO private DoH resolver
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=cleangeo
Group=cleangeo
WorkingDirectory=/opt/cleangeo/app
ExecStart=/opt/cleangeo/venv/bin/python /opt/cleangeo/app/server.py serve \
  --host 0.0.0.0 --port 443 --domain dns.cleangeo.net \
  --cert-dir /etc/letsencrypt/live/dns.cleangeo.net
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadOnlyPaths=/etc/letsencrypt
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
```

```
sudo systemctl daemon-reload
sudo systemctl enable --now cleangeo-dns
sudo journalctl -u cleangeo-dns -f
```

Note: `ProtectSystem=strict` plus `ReadOnlyPaths` is why nothing is written to
disk — the server does not try to, and the sandbox would stop it if it did.

## 6. Verify it is really working

Local, then from another machine:

```
cd /opt/cleangeo/app
/opt/cleangeo/venv/bin/python doh_client.py dns.cleangeo.net example.com --type A

/opt/cleangeo/venv/bin/python dns_probe.py dns.cleangeo.net \
  --name example.com --control dns.adguard-dns.com
```

The probe prints one line per check. What a good run looks like:

```
PASS tls            handshake completed with TLSv1.3, TLS_CHACHA20_POLY1305_SHA256
PASS tls-version    negotiated TLSv1.3 (required TLSv1.3)
PASS http2          ALPN selected h2
PASS certificate    subject=dns.cleangeo.net san=dns.cleangeo.net
PASS doh-query      answered in 34 ms with rcode NOERROR
PASS dnssec         AD bit set
PASS answers        1 answer record(s)
PASS control        answers match the control (dns.adguard-dns.com)

RESULT: encrypted path verified
```

If `tls-version` says TLSv1.2, the endpoint is not what you deployed. If
`control` differs, you are not getting independent resolution — check that
nothing on the host rewrites `/etc/resolv.conf` into the resolution path (it
must not; the resolver talks to authoritative servers directly).

`--control` is a comparison, not a dependency: it uses a second encrypted
channel to see whether the answers agree. It is used **only** in the test tool.
The resolver itself never contacts a public resolver.

## 7. Freshness and health

- `CertificateInfo.days_left` is printed on every start and by `keys.py
  inspect`. Below 21 days, the server prints a renewal warning.
- `/dns-query` refuses anything that is not a single well-formed DNS question,
  so a random HTTP scanner gets 400/415/405, not a query.
- The process prints aggregate counters at shutdown (`Stats.to_dict()`): counts
  only, no names, no addresses.

There is no built-in HTTP health endpoint, deliberately: a health endpoint is
an unauthenticated HTTP surface on a DNS port, and its absence is not needed
for anything here. `doh_client.py` is the health check, because it exercises
the real path.

## 8. Firewall

Only 443 needs to be open inbound. Outbound 53/udp and 53/tcp must be allowed
to the internet — that is how the resolver reaches authoritative servers.

```
sudo ufw allow 443/tcp
sudo ufw allow out 53
sudo ufw enable
```

If the VPS provider blocks outbound 53 (many do, to stop spam), the resolver
will not work at all. Test before relying on it:

```
/opt/cleangeo/venv/bin/python -c "
from resolver import Resolver
print(Resolver().resolve('example.com', 1).to_dict())"
```

A timeout there means the provider is blocking 53 outbound. That is a real
constraint, not something to work around by adding a public forwarder — doing so
would delete the property the project exists for.

## 9. Rollback

Stop the service and point clients back at their previous resolver:

```
sudo systemctl disable --now cleangeo-dns
```

There is no local state to clean up: no database, no cache file, no log file.

## 10. Scaling notes

The server handles one thread per connection with a 30 s idle timeout. For more
than a few hundred concurrent clients, put a TLS-terminating proxy in front —
but be aware that this reintroduces the TLS-terminator problem that `cstp.py`
was designed to address. If you do that, the provider can read queries, and
`THREAT-MODEL.md` §5 applies in full.
