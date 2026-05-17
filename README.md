# MirageX

> A performance-first, Xray-protocol-compatible proxy client engineered for
> the *worst* possible mobile network you have.

MirageX is a Rust workspace that implements the Xray transport stack
(VLESS, VMess, Trojan, Shadowsocks, SOCKS, HTTP) on top of a
modular Rust core. The reference recipe — `VLESS + Reality + XHTTP` and
`VLESS + Reality + Vision + RAW TCP` — is the default deployment target.

## Why another client?

There are plenty of excellent Xray clients (Xray-core itself,
sing-box, hiddify-next, etc.). MirageX takes a different bet:

| Topic | sing-box / Xray-core | MirageX |
| --- | --- | --- |
| Language | Go | Rust |
| Memory model | GC + 1 goroutine/connection | per-task arena, zero-cost futures |
| Mobile profile | one-size-fits-all | first-class adaptive layer (`[mobile]`) |
| Reality | hard-coded transport pairs | composable Reality + any transport |
| Config schema | weakly-typed JSON | strongly-typed TOML *or* JSON |
| Vision flow | implementation lives next to VLESS | own crate, reusable from Trojan / VMess |
| Cross-compile to mobile | external glue libraries | one `cargo build` matrix |

The aim is *not* to throw away the Xray protocol family — every
protocol, fingerprint, and transport stays bit-for-bit on-the-wire
compatible with existing Xray servers — but to rebuild the *client*
side around three core ideas:

1. **Adaptive mobile networking is a first-class concern**, not an
   afterthought. The `[mobile]` config section is the place where you
   *describe the link*, not the proxy.
2. **Every layer is a swappable crate**. Reality, Vision, XHTTP and
   the raw-TCP layer are independent crates; the engine treats them
   as a pipeline of `AsyncRead + AsyncWrite` adapters. Adding a new
   transport never touches the protocol crates and vice versa.
3. **One binary, every platform.** A single Rust workspace targets
   Linux, macOS, Windows, Android (via `cargo-ndk`), and iOS (via
   `cargo-lipo`). The CLI lives here; native GUIs link the same
   `mirage-engine` crate as a library.

## Recommended stacks

### `VLESS + Reality + XHTTP`

Best fit when the edge sits behind a CDN or has to look like a normal
HTTPS site. XHTTP is full-duplex HTTP/2 (or HTTP/3) with an optional
upload/download split (`mode = "packet"`) that keeps the downlink
moving even when the uplink stalls — the dominant failure mode on
weak LTE.

```toml
[outbounds.transport]
type = "xhttp"
path = "/your-secret-path"
mode = "auto"
force_h3 = false
padding  = "100-1000"
```

See [`examples/client-reality-xhttp.toml`](examples/client-reality-xhttp.toml).

### `VLESS + Reality + Vision + RAW TCP`

Best fit when the edge runs on a dedicated port and you want maximum
throughput. After the Reality handshake the Vision flow tag
(`xtls-rprx-vision`) tells both ends to drop into a splice fast-path
that bypasses any further user-space copies for record-level TLS
traffic.

```toml
flow = "xtls-rprx-vision"

[outbounds.transport]
type = "raw"
tcp_fast_open = true
```

See [`examples/client-reality-vision.toml`](examples/client-reality-vision.toml).

## Repository layout

```
MirageX
├── crates/
│   ├── mirage-core/              # shared types, errors, traits
│   ├── mirage-config/            # strongly-typed config (TOML / JSON)
│   ├── mirage-proto-vless/       # VLESS protocol codec (round-trip tested)
│   ├── mirage-tls-reality/       # Reality handshake (uTLS forge in-progress)
│   ├── mirage-transport-raw/     # raw TCP transport (TFO, keep-alive, bind)
│   ├── mirage-transport-xhttp/   # XHTTP transport (HTTP/2 + HTTP/3)
│   ├── mirage-vision/            # XTLS-Vision flow helpers
│   ├── mirage-mobile/            # RTT estimator, pacer, happy-eyeballs, pre-warm pool
│   ├── mirage-engine/            # inbounds, outbounds, dispatcher, router
│   └── mirage-cli/               # `miragex` binary
├── docs/
│   ├── ARCHITECTURE.md           # the long-form architecture write-up
│   ├── PROTOCOLS.md              # protocol-by-protocol feature matrix
│   ├── MOBILE-OPTIMIZATION.md    # how the mobile layer pays for itself
│   ├── COMPARISON-vs-singbox.md  # frank comparison
│   └── ROADMAP.md                # what's next
└── examples/
    ├── client-reality-xhttp.toml
    └── client-reality-vision.toml
```

## Quick start

```bash
# Compile + test the whole workspace.
cargo test --workspace

# Generate a sample config.
cargo run --bin miragex -- gen-config > client.toml

# Validate it.
cargo run --bin miragex -- check -c client.toml

# Run.
cargo run --bin miragex -- run -c client.toml
```

## Status

This is the foundation: the protocol crates compile and are
round-trip tested, the configuration schema is complete, the engine
ships a working SOCKS5 → direct / VLESS dispatch path, and the CLI
is usable for the *direct* outbound today. The Reality forged-hello
path, the XHTTP HTTP/2 stream plumbing, the Vision splice fast-path,
and the mobile GUIs are tracked in
[`docs/ROADMAP.md`](docs/ROADMAP.md).

## License

GPL-3.0-or-later (matches Xray-core).
