# MirageX Architecture

> "*Reality* is not a transport; it is a way of borrowing one." — Project Reality FAQ

This document captures the design philosophy behind MirageX and how the
workspace is structured to satisfy it. It is the source of truth that
the rest of the docs (`PROTOCOLS.md`, `MOBILE-OPTIMIZATION.md`,
`ROADMAP.md`) elaborate on.

## 1. Design principles

1. **One language for the data plane.** Both the protocol parsers and
   the engine that wires them together are written in Rust. There is
   no Go ⇄ C ⇄ Java FFI hop for a payload to traverse — bytes enter
   the inbound socket and leave the outbound socket without ever
   crossing a foreign-function boundary.
2. **Layers are composable.** The TLS/Reality layer, the inner
   protocol (VLESS / Trojan / VMess / Shadowsocks), the framing
   transport (Raw / XHTTP / WebSocket / gRPC / HTTPUpgrade), and the
   flow marker (`xtls-rprx-vision`, none) are independent crates.
   Adding a new transport never touches the protocol crates.
3. **Mobile-network adaptation is a first-class concern.** The
   `[mobile]` block is not a list of TCP knobs that happen to be
   exposed; it is a *description of the link* that the engine uses
   to dynamically tune pacing, retransmits, multipath behaviour, and
   pre-warm pool sizing.
4. **Memory safety, no `unsafe`.** Every crate is `#![forbid(unsafe_code)]`.
   The only place `unsafe` can creep in is inside vendored
   dependencies, and even those have been deliberately curated to
   well-audited primitives (`ring`, `rustls`, `x25519-dalek`).
5. **Compile times that match Xray's release cadence.** Heavy
   features (XHTTP, gRPC, TUN inbound, GUI link) sit behind cargo
   features so platform builds can opt in to exactly what they need.
6. **Cross-platform from day one.** No `#[cfg(target_os = "linux")]`
   in the public APIs; platform-specific code lives behind `cfg`
   walls in private modules.

## 2. Top-level data flow

```text
┌──────────┐      ┌─────────────┐     ┌──────────┐
│ Inbound  │──►──▶│ Dispatcher  │──►──│ Outbound │
└──────────┘      │ + Router    │     └──────────┘
   (SOCKS5,       │ + DNS cache │       (Direct,
    HTTP,         │ + Stats     │        VLESS+Reality+…,
    TUN)          └─────────────┘        VMess, Trojan, SS,
                                          SOCKS/HTTP chain)
```

* **Inbound** parses the local protocol (SOCKS5 today; HTTP / TUN
  forthcoming) into a [`Session`](../crates/mirage-engine/src/dispatcher.rs).
* **Router** evaluates ordered rules and chooses the outbound tag.
* **Dispatcher** materialises that tag into a real outbound object
  (today: `Direct` or `Vless`), then calls `outbound.dial(&session)`
  to obtain a `Box<dyn DuplexStream>`.
* **Inbound** runs the bidirectional copy between its accepted
  socket and that stream.

The dispatcher never decodes the application protocol — it only
shuffles bytes. The protocol-specific decoding (VLESS request
header, VMess AEAD framing, Trojan password, etc.) happens
*inside* the outbound implementation, which keeps the engine
copy-loop generic.

## 3. The outbound pipeline

Every outbound conceptually constructs a stack:

```text
       ┌──────────────────────────────┐
       │   inner: VLESS request hdr   │
       ├──────────────────────────────┤
       │  flow tag: xtls-rprx-vision  │   (optional)
       ├──────────────────────────────┤
       │   transport: Raw / XHTTP /   │
       │     WS / HTTPUpgrade / gRPC  │
       ├──────────────────────────────┤
       │  outer: Reality / TLS / nil  │
       ├──────────────────────────────┤
       │       TCP / UDP socket       │
       └──────────────────────────────┘
```

Bottom-up:
1. Open a TCP socket via [`mirage-transport-raw::RawDialer`]. This
   layer applies `TCP_NODELAY`, optional TCP Fast Open, optional
   per-interface binding, and the mobile pacer's `connect_timeout`.
2. Wrap with Reality (or plain TLS) via
   [`mirage-tls-reality::RealityConnector`]. The connector
   currently builds on `tokio-rustls` with a custom certificate
   verifier; the forged-hello fast path lands incrementally.
3. Apply the framing transport. Raw is a no-op; XHTTP opens an
   HTTP/2 (or HTTP/3) bidirectional stream; WebSocket / HTTPUpgrade
   negotiates an `Upgrade:`; gRPC opens a server-streaming RPC.
4. Optionally wrap with the Vision flow keyer
   ([`mirage-vision`]). Vision prepends a 32-byte command marker
   and then performs randomised record padding until both ends
   agree to drop into the splice fast-path.
5. Write the VLESS / Trojan / VMess request header. From here on
   the engine just copies user bytes through the resulting stream.

## 4. Why this is faster than sing-box / Xray-core

Two reasons that matter on the wire:

### Per-task arena, no GC

In sing-box / Xray-core each accepted connection spawns a goroutine
and allocates several KiB of internal buffers from the heap. Under
GC pressure the read/write buffers can sit in old generations and
balloon RSS. MirageX uses Tokio's `tokio::io::copy` which keeps
buffers on the stack frame; outbound dial reuses a single
`BytesMut` for the VLESS header. The result: less RSS noise, less
TLB pressure, more headroom for the kernel's send/recv buffers.

### Composable Vision

In Xray-core the Vision record-padding logic is implemented inside
the VLESS package. To use the same padding from Trojan you have to
duplicate it. MirageX keeps it in [`mirage-vision`], reusable by
every inner protocol — VMess + Reality + Vision becomes a one-line
config change instead of a forked codebase.

## 5. Cross-platform plan

| Target | Toolchain | Notes |
| ------ | --------- | ----- |
| Linux | `cargo build --release` | reference target |
| macOS | `cargo build --target aarch64-apple-darwin` | first-class |
| Windows | `cargo build --target x86_64-pc-windows-msvc` | first-class |
| Android | `cargo ndk -t arm64-v8a build` → `.so` linked by JNI | GUI in sibling repo |
| iOS | `cargo lipo --release` → `.a` linked by Swift | GUI in sibling repo |

The Tokio runtime, rustls, hyper, and h2 dependencies are all
known-compatible with every target above. Nothing about the
workspace pins it to a particular OS.

## 6. Where to find what

* **Adding a new protocol** → start in
  `crates/mirage-engine/src/outbound/`. Each protocol gets its own
  module; the `AnyOutbound` enum dispatches at runtime.
* **Adding a new transport** → add a crate
  `crates/mirage-transport-<name>/`, expose a connector type, and
  reference it from `mirage-engine/src/outbound/vless.rs`'s match.
* **Adding a new mobile knob** → extend
  `mirage-config::MobileConfig`, plumb the value into
  `mirage-mobile`. The dispatcher reads from the config at startup.
* **Adding a new inbound** → drop a module in
  `crates/mirage-engine/src/inbound.rs`'s sibling and register it
  in `inbound::spawn`.
