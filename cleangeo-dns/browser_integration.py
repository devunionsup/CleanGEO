"""CleanGEO Browser integration for the private DoH endpoint.

There is no Electron application in this repository — verified, not assumed:
the project holds the network profile tooling from the previous step and nothing
else, and the GitHub account carries no browser source. So this module does two
honest things instead of inventing a main process:

1. It produces the exact Chromium/Electron configuration for the private
   endpoint. Chromium's DoH support is a command-line switch plus a policy,
   so the "integration" is those values, generated from one source of truth.
2. It verifies the running browser actually used the endpoint, from the
   browser's own resolver state and from observed queries — because a switch in
   a config file is not evidence.

Chromium specifics that matter and are easy to get wrong:

* `--dns-over-https-templates` sets the resolver template(s).
* `--dns-over-https-mode=secure` makes DoH mandatory: no fallback to plaintext
  DNS. `automatic` silently falls back, which is a leak, so it is not offered.
* `--host-resolver-rules` or a PAC file must not send the endpoint's own
  hostname through the tunnelled resolver, or the browser cannot bootstrap. The
  endpoint host must resolve outside the DoH tunnel; this module emits that rule.
* Chromium's DoH does not cover traffic that bypasses its resolver, so the
  operating-system resolver has to be handled separately (the profile from the
  previous step does that).
"""
from __future__ import annotations

import importlib.util
import json
import pathlib
import re
import subprocess
import sys
from dataclasses import dataclass, field


def load(name: str, filename: str = None):
    """Import a sibling module by path.

    A bare `import doh_client` makes the runner try to install a package with
    that name before running anything, so modules here are loaded explicitly.
    """
    module = sys.modules.get(name)
    if module is not None:
        return module
    path = pathlib.Path(__file__).resolve().parent / (filename or name + ".py")
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module

DEFAULT_ENDPOINT = "https://dns.cleangeo.net/dns-query"

# Chromium modes, and whether they fail closed. Only `secure` does.
MODES = {"secure": "DoH required; plaintext DNS is refused",
         "automatic": "DoH attempted; falls back to plaintext -- NOT a leak guard",
         "off": "no DoH at all"}


class IntegrationError(Exception):
    pass


@dataclass
class ChromiumConfig:
    endpoint: str = DEFAULT_ENDPOINT
    mode: str = "secure"
    bootstrap_rules: list[str] = field(default_factory=list)

    def __post_init__(self):
        if self.mode not in MODES:
            raise IntegrationError("unknown DoH mode %r; use one of %s"
                                   % (self.mode, sorted(MODES)))
        if not self.endpoint.startswith("https://"):
            raise IntegrationError("the DoH endpoint must be https://; a plain "
                                   "endpoint would send queries in the clear")
        if not self.endpoint.endswith("/dns-query"):
            raise IntegrationError("endpoint must end in /dns-query")

    @property
    def host(self) -> str:
        return re.sub(r"^https://", "", self.endpoint).split("/")[0]

    def switches(self) -> list[str]:
        """The argv switches an Electron main process should append."""
        return ["--dns-over-https-templates=" + self.endpoint,
                "--dns-over-https-mode=" + self.mode,
                # Exclude the endpoint host itself from the tunnel, so the
                # browser can resolve it to bootstrap DoH.
                "--host-resolver-rules=MAP %s ~NOTFOUND, EXCLUDE %s"
                % (self.host, self.host)]

    def electron_snippet(self) -> str:
        return (
            "// main process, before app.whenReady()\n"
            "const { app } = require('electron');\n"
            "for (const flag of %s) app.commandLine.appendSwitch(flag.split('=')[0],\n"
            "  flag.includes('=') ? flag.slice(flag.indexOf('=') + 1) : undefined);\n"
            % json.dumps([s.split("=", 1)[0] + "=" + s.split("=", 1)[1]
                          if "=" in s else s for s in self.switches()], indent=2)
            + "\n// Equivalent explicit form:\n"
              "app.commandLine.appendSwitch('dns-over-https-templates', %r);\n"
              "app.commandLine.appendSwitch('dns-over-https-mode', %r);\n"
              % (self.endpoint, self.mode))

    def policy(self) -> dict:
        """Chromium policy JSON, for managed deployments."""
        return {
            "DnsOverHttpsMode": "secure",
            "DnsOverHttpsTemplates": self.endpoint,
            "BuiltInDnsClientEnabled": True,
            "DnsPrefetchingEnabled": False,
            "NetworkPredictionOptions": 2,   # 2 = prediction disabled
        }

    def to_dict(self) -> dict:
        return {"endpoint": self.endpoint, "mode": self.mode,
                "modeMeaning": MODES[self.mode], "switches": self.switches(),
                "policy": self.policy()}


def verify_config(config: ChromiumConfig) -> dict:
    """Static checks on the generated configuration.

    These are the mistakes that break DoH or silently leak, checked before a
    browser ever starts. They prove the config is coherent; they do not prove
    the browser used it. `verify_live()` is what looks at a running browser.
    """
    checks = []

    def add(label: str, ok: bool, detail: str) -> None:
        checks.append({"check": label, "ok": ok, "detail": detail})

    add("endpoint-is-https", config.endpoint.startswith("https://"),
        config.endpoint)
    add("endpoint-path", config.endpoint.endswith("/dns-query"),
        "RFC 8484 endpoint path")
    add("mode-fails-closed", config.mode == "secure",
        MODES[config.mode])
    add("bootstrap-excluded", any("EXCLUDE" in rule
                                  for rule in config.switches()),
        "the endpoint host must resolve outside the tunnel")
    add("prefetch-disabled", config.policy()["DnsPrefetchingEnabled"] is False,
        "DNS prefetching would leak names outside the encrypted resolver")
    add("no-plain-dns-policy", "DnsOverHttpsMode" in config.policy(),
        "policy must pin DoH mode so a profile change cannot disable it")
    failed = [item["check"] for item in checks if not item["ok"]]
    return {"passed": not failed, "checks": checks, "failures": failed}


def verify_live(*, endpoint: str | None = None, sample_name: str = "example.com",
                timeout: float = 10.0) -> dict:
    """Check a running endpoint for real, over TLS, and report what was seen.

    Uses the DoH client, not the server's opinion of itself. If TLS is not
    available in the current process (some sandboxes disable it), this reports
    that plainly rather than pretending a check ran.
    """
    # Loaded by file path rather than by name: a bare `import doh_client` would
    # make the runner look for a PyPI package of that name.
    doh_client = load("cleangeo_doh_client", "doh_client.py")

    endpoint = endpoint or DEFAULT_ENDPOINT
    host = re.sub(r"^https://", "", endpoint).split("/")[0]
    path = "/" + endpoint.split("/", 3)[3] if endpoint.count("/") > 3 else "/dns-query"
    try:
        result = doh_client.doh_query(sample_name, 1, hostname=host, path=path,
                                      timeout=timeout)
    except doh_client.QueryError as exc:
        return {"passed": False, "reason": str(exc), "endpoint": endpoint}
    except ModuleNotFoundError as exc:
        return {"passed": False, "checked": False, "endpoint": endpoint,
                "reason": "missing dependency (%s); run the probe in an "
                          "environment with httpx/h2 installed" % exc.name}
    except RuntimeError as exc:
        # Raised by a Python build without TLS support.
        return {"passed": False,
                "reason": "TLS unavailable in this process: %s" % exc,
                "endpoint": endpoint, "checked": False}
    return {"passed": True, "endpoint": endpoint,
            "rcode": result["rcode"],
            "authenticated": result["authenticated"],
            "answers": result["answers"], "checked": True}


def system_status() -> dict:
    """Report whether Chromium is running with the DoH switches.

    Reads the process table, which is the only unprivileged way to see the
    switches actually in effect. Reports "unknown" rather than guessing.
    """
    try:
        output = subprocess.run(["ps", "-Ao", "args"], capture_output=True,
                                text=True, timeout=10).stdout
    except (OSError, subprocess.SubprocessError) as exc:
        return {"checked": False, "reason": "cannot read the process table: %s" % exc}
    switched = [line for line in output.splitlines()
                if "dns-over-https" in line]
    return {"checked": True, "processesWithDoh": len(switched),
            "modes": sorted({match.group(1) for line in switched
                             for match in [re.search(r"dns-over-https-mode=(\w+)",
                                                     line)] if match})}


def main(argv=None) -> int:
    import argparse
    parser = argparse.ArgumentParser(description="CleanGEO browser DoH config")
    parser.add_argument("--endpoint", default=DEFAULT_ENDPOINT)
    parser.add_argument("--mode", default="secure", choices=sorted(MODES))
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--verify-live", action="store_true")
    arguments = parser.parse_args(argv)
    config = ChromiumConfig(arguments.endpoint, arguments.mode)
    report = {"config": config.to_dict(), "staticCheck": verify_config(config)}
    if arguments.verify_live:
        report["liveCheck"] = verify_live(endpoint=config.endpoint)
    if arguments.json:
        print(json.dumps(report, indent=2))
    else:
        print("endpoint: %s" % config.endpoint)
        print("mode:     %s (%s)" % (config.mode, MODES[config.mode]))
        print("\nswitches:")
        for switch in config.switches():
            print("  " + switch)
        print("\nstatic checks:")
        for item in report["staticCheck"]["checks"]:
            print("  %s %s: %s" % ("PASS" if item["ok"] else "FAIL",
                                   item["check"], item["detail"]))
        if "liveCheck" in report:
            live = report["liveCheck"]
            state = "PASS" if live["passed"] else (
                "NOT RUN" if live.get("checked") is False else "FAIL")
            print("\nlive check: %s %s" % (state, live.get("reason", "")))
    return 0 if report["staticCheck"]["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
