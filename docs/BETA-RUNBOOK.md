# MirageX BETA runbook

This is the operator-facing runbook for the **`v0.1.0-beta`** drop of
MirageX. It tells you exactly what works, what does not, and how to
verify the install on a fresh box.

> Status: the beta is *runnable* (you can use it as a local SOCKS5 → Direct
> proxy and it carries traffic), but the full feature set of
> `client-reality-vision.toml` / `client-reality-xhttp.toml` is **not yet
> wired end-to-end**. See the *What is and isn't ready* section below.

---

## What is ready in this beta

* **SOCKS5 inbound** on a configurable bind address. No-auth and CONNECT
  command verified.
* **Direct outbound** with mobile-optimised socket options (TCP_NODELAY,
  USER_TIMEOUT, larger SNDBUF/RCVBUF), happy-eyeballs racing of v4/v6
  candidates, BDP-adaptive bidirectional pump (256 KiB initial,
  4 MiB clamp).
* **VLESS outbound, RAW transport, plain TLS path**. Sends correct
  VLESS request headers (including `flow = "xtls-rprx-vision"` in the
  addons block when configured). Interoperates with stock Xray VLESS+TLS
  servers.
* **VLESS outbound, RAW transport, Reality path**: uses a custom rustls
  config that accepts the upstream certificate without chain validation,
  so it talks to a Reality-style edge. **It does NOT yet forge the
  outer ClientHello fingerprint or implement the Reality auth signature
  inside `session_id`** — that's the foundation in
  `crates/mirage-tls-reality/{wire,keys,aead,fingerprint,hello}.rs`
  but not yet plumbed into the connector. Result: this path will be
  rejected by a vanilla xray-core Reality server that enforces auth.
* **Engine boot** validated by the loopback integration test
  (`crates/mirage-engine/tests/loopback_socks5.rs`): SOCKS5 → routing →
  Direct → echo with payload round-trip.

## What is *not* ready in this beta

| Component | Status |
| --- | --- |
| Reality forged-hello wire-up | foundation merged (PR #3); connector still uses plain rustls |
| Reality auth signature inside `session_id` | helpers exist; not embedded in the live ClientHello yet |
| XHTTP H2 stream pump | unimplemented — `protocol="vless"` + `transport.type="xhttp"` returns a clear "not yet" error |
| Vision splice fast-path / record padding | flow marker is sent on the wire; padding + splice are deferred |
| WebSocket / HTTPUpgrade / gRPC transports | unimplemented (clear error message) |
| VMess / Trojan / Shadowsocks outbounds | unimplemented (clear error message) |
| HTTP CONNECT inbound | unimplemented |
| TUN inbound | unimplemented |
| UDP (SOCKS5 ASSOCIATE, VLESS UDP) | unimplemented |
| Platform UIs (Android / iOS / macOS / Windows) | not in scope until the protocol stack lands |

If you point this beta at a config that uses one of those features it
will error out at engine-build time with an explicit message, **not**
silently degrade.

---

## Install

The beta ships as source. Linux & macOS need a Rust 1.75+ toolchain
(`rustup install stable`).

```bash
git clone https://github.com/lpxqwkjd65rjfn-dot/MirageX.git
cd MirageX
cargo build --release -p mirage-cli
sudo install -m 0755 target/release/miragex /usr/local/bin/miragex
miragex version
# miragex 0.1.0
```

The release profile uses LTO + panic=abort, so the binary is ~6 MiB
stripped on x86_64-linux.

---

## Smoke test (3 minutes)

The canonical "is the engine alive" test. Run it after `cargo build` on
a fresh box — if this fails, nothing more elaborate will work either.

```bash
# Terminal 1 — start MirageX with the beta config.
miragex run -c examples/beta.toml
# Expect: "miragex: engine running. Ctrl-C to stop."

# Terminal 2 — make an HTTPS request through the SOCKS5 inbound.
curl --socks5-hostname 127.0.0.1:1080 -sS https://api.ipify.org
# Expect: a single IPv4 address on its own line.
```

If `curl` exits 0 and prints an IP, the engine is sane. Stop the engine
with Ctrl-C.

The same path is exercised in CI:

```bash
cargo test -p mirage-engine --test loopback_socks5
# Expect: "test result: ok. 2 passed; 0 failed; 0 ignored"
```

The integration test runs a TCP echo server in-process, boots the
engine with `examples/beta.toml`-equivalent config, opens a SOCKS5
CONNECT to the echo server, and verifies bytes round-trip.

---

## Trying the proxy configs

Both `examples/client-reality-xhttp.toml` and
`examples/client-reality-vision.toml` are **fully valid TOML** — they
parse, validate, and the engine boots — but the underlying transports
are still partially implemented (see the table above). Pointing them at
a real Xray Reality server will:

* For `client-reality-vision.toml`: fail at the handshake stage,
  because the outer Reality ClientHello is not yet forged.
* For `client-reality-xhttp.toml`: fail at engine build with the error
  `vless: only Raw transport is wired up in this revision (XHTTP coming)`.

This is intentional — the beta won't silently send bad bytes on the
wire. Track [`docs/ROADMAP.md`](ROADMAP.md) for the wire-up timeline.

If you have a stock Xray VLESS+TLS server (no Reality, no Vision), you
can talk to it today with a hand-edited config:

```toml
[[outbounds]]
tag      = "proxy"
protocol = "vless"
server   = "edge.example.com:443"
uuid     = "11111111-2222-3333-4444-555555555555"
flow     = ""        # leave empty — no Vision

[outbounds.tls]
server_name = "edge.example.com"
alpn        = ["h2", "http/1.1"]
insecure    = false

[outbounds.transport]
type = "raw"
```

Add the inbound + routing from `examples/beta.toml` and `miragex run`
will proxy through that server.

---

## Logging and observability

Set `MIRAGEX_LOG=debug` to get per-flow trace lines:

```
MIRAGEX_LOG=debug miragex run -c examples/beta.toml
```

The engine logs:

* `socks inbound started` once per inbound after bind.
* `vless outbound configured` once per VLESS outbound, with
  `transport=`, `tls=`, `fingerprint=`, `flow=` so you can confirm what
  the parsed config actually resolved to.
* `socks: routing` per accepted client with the destination address.
* `vless: header sent (N bytes)` per established proxied flow.

JSON-formatted logs are available via `log.format = "json"` in the
config file (useful for piping into `jq` or a log shipper).

---

## Known limits & gotchas

* **Time skew / TLS dates.** Reality intentionally accepts the upstream
  cert as-is, but the underlying rustls still checks NotBefore /
  NotAfter dates. A box with a wildly wrong clock will fail handshakes
  with a vague "tls error".
* **Backlog under burst.** SOCKS5 inbound listens with a 1024-deep
  backlog; on a t4g.nano with a heavy ramp-up you can saturate it.
  Increase by binding a second listener on a different port.
* **Prewarm pool + restarting servers.** The TCP prewarm pool
  (`mobile.prewarm > 0`) holds open up to N TCP connections to the
  upstream. After the upstream restarts, the pool will need ~30 s to
  drain stale entries before flows recover. Set `prewarm = 0` if your
  upstream is unstable.
* **clippy::pedantic.** The whole workspace is built with
  `-D warnings` on `clippy::pedantic`. PRs should keep that bar.
* **No Windows CI tests beyond compile.** Unit tests do run on Windows
  in CI (`test (windows-latest)`), but the SOCKS5 integration test path
  has only been smoke-tested on Linux.

---

## Filing a bug

When reporting a regression please include:

* `miragex version`
* The exact config file (with secrets / UUIDs redacted).
* The output of `MIRAGEX_LOG=debug miragex run -c <config>` up to the
  first error.
* What you expected to happen vs. what happened.

The repo's issue template will prompt you for these.
